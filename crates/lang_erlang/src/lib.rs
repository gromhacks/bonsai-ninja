//! Erlang language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, DeclIndex, FlowEvent, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("erlang");
const PACK_NAME: &str = "erlang";

// Erlang's tree-sitter grammar (WhatsApp) uses language-specific kind
// names for control flow that the generic handler doesn't cover. Layer
// them on top so flow events surface for case / if / try / receive.
const HANDLER: GrammarHandler = GrammarHandler {
    // Erlang functions: `fun_decl` is the umbrella; clauses are
    // `function_clause`. We index both so single- and multi-clause
    // functions both produce decls.
    fn_kinds: &["fun_decl", "function_clause"],
    class_kinds: &[],
    method_kinds: &[],
    method_context_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    if_kinds: &["if_expr", "case_expr"],
    for_kinds: &[],
    // Comprehensions (`[E || X <- L]`, `<< ... >>`) go through the shared
    // walker's comprehension branch (list_comprehension /
    // binary_comprehension with nested `generator` binding clauses);
    // tree-sitter-erlang has no foreach-shaped node kind.
    foreach_kinds: &[],
    while_kinds: &[],
    do_kinds: &[],
    loop_kinds: &[],
    call_kinds: &["call", "remote"],
    assignment_kinds: &["match_expr"],
    return_kinds: &[],
    throw_kinds: &[],
    lambda_kinds: &["fun_expr", "anonymous_fun"],
    try_kinds: &["try_expr"],
    catch_kinds: &["catch_clause"],
    // tree-sitter-erlang names the `after` region `try_after` (not the
    // Elixir `after_block`); with the wrong name the always-run cleanup
    // was misfiled into the try body instead of `finally_events`.
    finally_kinds: &["try_after"],
    break_kinds: &[],
    continue_kinds: &[],
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &["receive_expr"],
    method_receiver_param_index: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
    void_return_type_names: &[],
};

#[derive(Debug, Default, Copy, Clone)]
pub struct ErlangAdapter;

impl ErlangAdapter {
    /// Construct a stateless Erlang adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ErlangAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Erlang"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["erl", "hrl"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        // Erlang exports are explicit: `-export([fn/arity, ...]).`
        // Functions not in any -export attribute are module-private.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let exported_names = collect_erlang_exported_names(&tree, snapshot.text.as_bytes());
            for decl in &mut decl_index.defs {
                if !exported_names.contains(&decl.name) {
                    decl.visibility = Visibility::Module;
                }
            }
        }
        // Second pass: rewrite flow events using full source text.
        // Record-pattern destructuring, `maps:get` accesses, and tail
        // returns aren't reachable from the tree-walker alone — they
        // need textual analysis of byte ranges.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let map_field_assigns =
                collect_erlang_map_literal_field_assigns(&tree, snapshot.text.as_bytes(), file);
            for decl in &mut decl_index.defs {
                if let Some(params) = erlang_clause_param_slots(snapshot.text.as_ref(), decl.span, &decl.name)
                {
                    decl.params = params;
                }
                augment_erlang_param_pattern_bindings(decl, snapshot.text.as_ref());
                normalize_erlang_access_events(&mut decl.flow_events, snapshot.text.as_ref());
                bonsai_lang_api::kit::annotate_tuple_call_result_bindings(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                );
                augment_erlang_record_flow_events(&mut decl.flow_events, snapshot.text.as_ref());
                insert_erlang_map_field_assigns_in_events(&mut decl.flow_events, &map_field_assigns);
                inject_erlang_fun_ref_aliases(&mut decl.flow_events, snapshot.text.as_ref());
                rewrite_erlang_throw_calls(&mut decl.flow_events);
                augment_erlang_tail_return_event(
                    &mut decl.flow_events,
                    decl.span,
                    &tree,
                    snapshot.text.as_ref(),
                );
                inject_erlang_comprehension_generator_bindings(
                    &mut decl.flow_events,
                    &tree,
                    snapshot.text.as_bytes(),
                    file,
                );
                decl.has_implicit_returns = true;
            }
        } else {
            // Parser unavailable — degrade gracefully by normalizing
            // events with empty source (no record / map rewrites).
            for decl in &mut decl_index.defs {
                normalize_erlang_access_events(&mut decl.flow_events, "");
                decl.has_implicit_returns = true;
            }
        }
        // Recognised Erlang lifecycle transitions. Remote-call form
        // (`gen_server:stop`, `ets:delete`) matches what the kit
        // emits for `module:function` calls; bare `close` covers
        // local-call shapes (`close(F)`).
        const ERLANG_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "gen_server:stop",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "ets:delete",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
        ];
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            augment_erlang_collection_transform_flow_events(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, ERLANG_LIFECYCLE_TRANSITIONS);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`new Foo()` / `Foo()` / `Foo::new()` -> typed receiver) so `recv.method(...)` resolves
        // `receiver_type_in` / `[Type, method]` rules; the constructor heuristic only
        // types PascalCase callees, so language exported-function calls are unaffected.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

#[derive(Clone, Debug)]
struct ErlangMapFieldAssigns {
    assign_span: bonsai_common::Span,
    target: String,
    fields: Vec<FlowEvent>,
}

fn collect_erlang_map_literal_field_assigns(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<ErlangMapFieldAssigns> {
    let mut out = Vec::new();
    for assignment in collect_kinds(tree, &["match_expr"]) {
        let Some(left) = assignment.child_by_field_name("lhs") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("rhs") else {
            continue;
        };
        if right.kind() != "map_expr" {
            continue;
        }
        let target = node_text(&left, src).trim().to_string();
        if target.is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        let mut cursor = right.walk();
        for field in right.named_children(&mut cursor) {
            if field.kind() != "map_field" {
                continue;
            }
            let Some(key_node) = field.child_by_field_name("key") else {
                continue;
            };
            let Some(value_node) = field.child_by_field_name("value") else {
                continue;
            };
            let Some(key) = erlang_map_key(key_node, src) else {
                continue;
            };
            let sources = erlang_value_source_names(node_text(&value_node, src));
            fields.push(FlowEvent::Assign {
                span: span_of(file, &value_node),
                target: format!("{target}.{key}"),
                source_name: (sources.len() == 1).then(|| sources[0].clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: sources,
                declares_new_binding: false,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
            });
        }
        if !fields.is_empty() {
            out.push(ErlangMapFieldAssigns {
                assign_span: span_of(file, &assignment),
                target,
                fields,
            });
        }
    }
    out
}

fn erlang_map_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let key = raw.trim_matches(['"', '\'']);
    if !erlang_atom_name(key) {
        return None;
    }
    Some(key.to_string())
}

fn insert_erlang_map_field_assigns_in_events(
    events: &mut Vec<FlowEvent>,
    field_assigns: &[ErlangMapFieldAssigns],
) {
    let mut index = 0usize;
    while index < events.len() {
        match &mut events[index] {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_erlang_map_field_assigns_in_events(then_events, field_assigns);
                insert_erlang_map_field_assigns_in_events(else_events, field_assigns);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_erlang_map_field_assigns_in_events(body, field_assigns);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_erlang_map_field_assigns_in_events(body, field_assigns);
                insert_erlang_map_field_assigns_in_events(catch_events, field_assigns);
                insert_erlang_map_field_assigns_in_events(finally_events, field_assigns);
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

/// Extract Erlang `-import` attributes and `-include` / `-include_lib`
/// preprocessor directives into the canonical `ImportSpec` shape.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // tree-sitter-erlang exposes three import-flavored attributes:
    //   `import_attribute` for `-import(Mod, [F/A, ...]).`
    //   `pp_include` for `-include("X.hrl").`
    //   `pp_include_lib` for `-include_lib("app/include/X.hrl").`
    for import_node in collect_kinds(tree, &["import_attribute"]) {
        if let Some(module_node) = import_node.child_by_field_name("module") {
            let module = node_text(&module_node, src).to_string();
            imports.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module.clone(),
                alias: None,
                is_wildcard: false,
                original_name: None,
                scope: ImportScope::Module,
            });
            for imported in erlang_imported_function_names(&import_node, src) {
                imports.push(ImportSpec {
                    span: span_of(file, &import_node),
                    module: module.clone(),
                    alias: None,
                    is_wildcard: false,
                    original_name: Some(imported),
                    scope: ImportScope::Local,
                });
            }
        }
    }
    for include_node in collect_kinds(tree, &["pp_include", "pp_include_lib"]) {
        if let Some(file_node) = include_node.child_by_field_name("file") {
            // The file path is wrapped in quotes — strip them so the
            // matcher index sees a clean module name.
            let module = node_text(&file_node, src)
                .trim_matches(|ch: char| matches!(ch, '"' | '\''))
                .to_string();
            if !module.is_empty() {
                imports.push(ImportSpec {
                    span: span_of(file, &include_node),
                    module,
                    alias: None,
                    is_wildcard: false,
                    original_name: None,
                    scope: ImportScope::Module,
                });
            }
        }
    }
    imports
}

fn erlang_imported_function_names(import_node: &tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![*import_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "fa" {
            if let Some(fun_node) = node.child_by_field_name("fun") {
                let name = node_text(&fun_node, src).trim().to_string();
                if !name.is_empty() && !out.iter().any(|existing| existing == &name) {
                    out.push(name);
                }
            }
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Rewrite flow events so that `maps:get/2` calls and `Record#tag.field`
/// accesses surface as place-paths the matcher can reason about. The
/// walker emits raw textual fragments — this stage canonicalizes them.
fn normalize_erlang_access_events(events: &mut [FlowEvent], src: &str) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                normalize_erlang_split_dot_args(args);
                for arg in args {
                    if let Some(source) = erlang_fun_ref_source(&arg.value_text) {
                        arg.value_text.clone_from(&source);
                        push_unique_string(&mut arg.source_names, source);
                        continue;
                    }
                    // Prefer `maps:get` rewrites (they consume a pair of
                    // args), fall back to single record access.
                    if let Some(access) = erlang_maps_get_access(&arg.value_text) {
                        arg.value_text.clone_from(&access);
                        arg.place = Some(access.clone());
                        push_unique_string(&mut arg.source_names, access);
                    } else if let Some(access) = single_erlang_record_access(&arg.value_text) {
                        arg.value_text.clone_from(&access);
                        arg.place = Some(access);
                    }
                }
            }
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                // The walker may not have populated source_call when the
                // RHS is a plain function-call expression; reconstruct it
                // textually from the assignment span.
                if source_call.is_none() && source_call_args.is_empty() {
                    if let Some((callee, args)) = erlang_assignment_call_rhs(src, *span) {
                        *source_call = Some(callee);
                        *source_call_args = args;
                    }
                }
                for arg in source_call_args.iter_mut() {
                    if let Some(source) = erlang_fun_ref_source(arg) {
                        *arg = source;
                    } else if let Some(access) = single_erlang_record_access(arg) {
                        *arg = access;
                    }
                }
                // For `X = maps:get(key, M)`, the access path `M.key`
                // becomes a virtual source name.
                if source_call.as_deref().is_some_and(erlang_maps_get_callee_name) {
                    if let Some(access) = erlang_maps_get_access_from_args(source_call_args) {
                        push_unique_string(source_names, access);
                    }
                }
                add_erlang_collection_transform_sources(
                    source_call.as_deref(),
                    source_call_args,
                    source_names,
                );
                if let Some(rhs_text) = erlang_assignment_rhs_text(src, *span) {
                    for source in erlang_comprehension_generator_sources(rhs_text) {
                        push_unique_string(source_names, source);
                    }
                    let dot_accesses = erlang_pseudo_dot_accesses(rhs_text);
                    if !dot_accesses.is_empty() {
                        let structural_bases = dot_accesses
                            .iter()
                            .filter_map(|access| access.split_once('.').map(|(base, _)| base))
                            .collect::<std::collections::HashSet<_>>();
                        if source_name
                            .as_deref()
                            .is_some_and(|name| structural_bases.contains(name.trim()))
                        {
                            *source_name = None;
                        }
                        source_names.retain(|name| !structural_bases.contains(name.trim()));
                        for access in dot_accesses {
                            push_unique_string(source_names, access);
                        }
                    }
                }
                // Any record access mentioned anywhere in the assignment
                // span counts as a source — covers patterns like
                // `Y = case Rec#tag.f of ... end`.
                for access in erlang_record_accesses_in_span(src, *span) {
                    push_unique_string(source_names, access);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_erlang_access_events(then_events, src);
                normalize_erlang_access_events(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_erlang_access_events(body, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_erlang_access_events(body, src);
                normalize_erlang_access_events(catch_events, src);
                normalize_erlang_access_events(finally_events, src);
            }
            _ => {}
        }
    }
}

/// The Erlang grammar treats the compatibility fixture spelling
/// `C.capacity` as two adjacent call arguments (`C.` and `capacity`).
/// Rejoin that losslessly into the same projected storage path used by
/// records and maps. This also prevents the structural base `C` from
/// becoming an independent value source.
fn normalize_erlang_split_dot_args(args: &mut Vec<bonsai_lang_api::CallArg>) {
    let mut index = 0usize;
    while index + 1 < args.len() {
        let base = args[index].value_text.trim().trim_end_matches('.').trim();
        let field = args[index + 1].value_text.trim();
        let is_base = !base.is_empty()
            && base
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
            && base.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        let is_field = !field.is_empty()
            && field
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
            && field.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        if !args[index].value_text.trim().ends_with('.') || !is_base || !is_field {
            index += 1;
            continue;
        }
        let access = format!("{base}.{field}");
        args[index].value_text.clone_from(&access);
        args[index].place = Some(access.clone());
        args[index].source_names.clear();
        args[index].source_names.push(access);
        args.remove(index + 1);
        index += 1;
    }
}

fn erlang_pseudo_dot_accesses(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in text.split(|ch: char| !(ch == '_' || ch == '.' || ch.is_ascii_alphanumeric())) {
        let Some((base, field)) = token.split_once('.') else {
            continue;
        };
        if field.contains('.')
            || base.is_empty()
            || field.is_empty()
            || !base
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
            || !field
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
            || !base.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            || !field.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            continue;
        }
        push_unique_string(&mut out, format!("{base}.{field}"));
    }
    out
}

/// Add exact callback-alias facts for Erlang's function-reference
/// syntax: `Cb = fun helper/1`.
fn inject_erlang_fun_ref_aliases(events: &mut Vec<FlowEvent>, src: &str) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_erlang_fun_ref_aliases(then_events, src);
                inject_erlang_fun_ref_aliases(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_erlang_fun_ref_aliases(body, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_erlang_fun_ref_aliases(body, src);
                inject_erlang_fun_ref_aliases(catch_events, src);
                inject_erlang_fun_ref_aliases(finally_events, src);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let alias = erlang_fun_ref_alias_assignment(&event, src);
        rewritten.push(event);
        if let Some(alias) = alias {
            rewritten.push(alias);
        }
    }
    *events = rewritten;
}

/// Rewrite Erlang exception BIF calls (`throw/1`, `error/1`, `exit/1`,
/// and their `erlang:`-qualified forms) into `FlowEvent::Throw`. These
/// raise via plain `call` nodes, so the walker emits them as `Call`
/// events; without this pass `throw(X)` is never a Throw and try/catch
/// taint seeding (G8) can't link the thrown value to the catch binding.
fn rewrite_erlang_throw_calls(events: &mut [FlowEvent]) {
    // Recurse into nested bodies first so throws inside branch / loop /
    // try regions are rewritten too.
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_erlang_throw_calls(then_events);
                rewrite_erlang_throw_calls(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_erlang_throw_calls(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_erlang_throw_calls(body);
                rewrite_erlang_throw_calls(catch_events);
                rewrite_erlang_throw_calls(finally_events);
            }
            _ => {}
        }
    }
    for event in events.iter_mut() {
        if let Some(throw) = erlang_throw_from_call(event) {
            *event = throw;
        }
    }
}

/// Build a `Throw` from a `Call` to `throw`/`error`/`exit`, taking the
/// thrown value name from the first argument when it is a bare Erlang
/// variable (so G8 can pre-taint the catch binding).
fn erlang_throw_from_call(event: &FlowEvent) -> Option<FlowEvent> {
    let FlowEvent::Call { span, name, args, .. } = event else {
        return None;
    };
    // Match bare exception BIFs (`throw`, `error`, `exit`) and their
    // explicit `erlang:` / `erlang.` forms only. Other modules expose
    // ordinary functions with the same tail (`logger:error`) and must
    // remain call events for security rules and call inventory output.
    let trimmed = name.trim();
    let (module, short) = trimmed
        .rsplit_once([':', '.'])
        .map_or((None, trimmed), |(module, short)| {
            (Some(module.trim()), short.trim())
        });
    if !matches!(short, "throw" | "error" | "exit") {
        return None;
    }
    if module.is_some_and(|module| module != "erlang") {
        return None;
    }
    let value_name = args.first().and_then(|arg| {
        let text = arg.value_text.trim();
        if erlang_variable_name(text) {
            Some(text.to_string())
        } else {
            arg.source_names
                .iter()
                .find(|name| erlang_variable_name(name))
                .cloned()
        }
    });
    Some(FlowEvent::Throw {
        span: *span,
        value_name,
        thrown_type: None,
    })
}

fn erlang_fun_ref_alias_assignment(event: &FlowEvent, src: &str) -> Option<FlowEvent> {
    let FlowEvent::Assign { span, .. } = event else {
        return None;
    };
    let span_text = erlang_span_text(src, *span)?;
    let (lhs, rhs) = split_top_level_match_expr(span_text)?;
    let target = lhs.trim();
    if !erlang_variable_name(target) {
        return None;
    }
    let source_name = erlang_fun_ref_source(rhs.trim().trim_end_matches('.').trim())?;
    Some(FlowEvent::Assign {
        span: *span,
        target: target.to_string(),
        source_name: Some(source_name),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    })
}

fn erlang_fun_ref_source(rhs: &str) -> Option<String> {
    let rest = rhs.strip_prefix("fun ")?.trim_start();
    let (name, arity) = rest.rsplit_once('/')?;
    let name = name.trim();
    let arity = arity.trim();
    if !erlang_atom_name(name) || !arity.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(name.to_string())
}

/// Synthesize parameter destructuring assignments for Erlang record
/// patterns in function heads. `f(R = #user{name = N}) -> ...` turns
/// into a synthetic `N = R.name` Assign event prepended to the body so
/// the taint engine can flow `R.name -> N`.
fn augment_erlang_param_pattern_bindings(decl: &mut bonsai_lang_api::Decl, src: &str) {
    let Some(decl_text) = erlang_span_text(src, decl.span) else {
        return;
    };
    let Some(params_text) = erlang_function_params_text(decl_text) else {
        return;
    };
    let raw_args = split_top_level_args(params_text);
    let mut synthetic_events = Vec::new();
    for (param_index, raw_arg) in raw_args.iter().enumerate() {
        let slot_param_name = decl
            .params
            .get(param_index)
            .filter(|name| !name.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| format!("_Arg{param_index}"));
        let bindings = erlang_record_pattern_bindings(raw_arg);
        if !bindings.is_empty() {
            // Pick the variable bound to the whole record (or fall back to
            // the existing param name, or a generated `Arg<i>`).
            let param_name = erlang_pattern_param_name(raw_arg)
                .or_else(|| {
                    decl.params
                        .get(param_index)
                        .filter(|name| erlang_variable_name(name))
                        .cloned()
                })
                .unwrap_or_else(|| format!("Arg{param_index}"));
            // Replace the param at this index so callers see the canonical
            // record-bound name rather than the raw pattern text.
            if param_index < decl.params.len() {
                decl.params[param_index].clone_from(&param_name);
            } else {
                decl.params.push(param_name.clone());
            }
            for (field_name, bound_variable) in bindings {
                synthetic_events.push(FlowEvent::Assign {
                    span: decl.span,
                    target: bound_variable,
                    source_name: Some(format!("{param_name}.{field_name}")),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: vec![format!("{param_name}.{field_name}")],
                    declares_new_binding: false,
                    value_kind: None,
                });
            }
            continue;
        }

        for bound_variable in erlang_pattern_bound_variables(raw_arg) {
            if bound_variable == "_" || bound_variable == slot_param_name {
                continue;
            }
            synthetic_events.push(FlowEvent::Assign {
                span: decl.span,
                target: bound_variable,
                source_name: Some(slot_param_name.clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: vec![slot_param_name.clone()],
                declares_new_binding: false,
                value_kind: None,
            });
        }
    }
    // Prepend so destructuring lands before any body events that may
    // reference the bound variables.
    if !synthetic_events.is_empty() {
        synthetic_events.append(&mut decl.flow_events);
        decl.flow_events = synthetic_events;
    }
}

/// Expand record-construction assignments into per-field assignments.
/// `R = #user{name = N, email = E}` produces synthetic
/// `R.name = N` and `R.email = E` events alongside the original, which
/// lets the taint engine track field-level flow.
fn augment_erlang_record_flow_events(events: &mut Vec<FlowEvent>, src: &str) {
    // Recurse into nested events first so child branches/bodies are
    // augmented before we walk the top-level list.
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_erlang_record_flow_events(then_events, src);
                augment_erlang_record_flow_events(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_erlang_record_flow_events(body, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_erlang_record_flow_events(body, src);
                augment_erlang_record_flow_events(catch_events, src);
                augment_erlang_record_flow_events(finally_events, src);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let mut synthetic_field_assigns = Vec::new();
        // Only assignments to a record value need expansion — peek at
        // the textual RHS for `#tag{field = value, ...}` initializers.
        if let FlowEvent::Assign { span, target, .. } = &event {
            if let Some(rhs_text) = erlang_assignment_rhs_text(src, *span) {
                for (field_name, field_value) in erlang_record_field_initializers(rhs_text) {
                    synthetic_field_assigns.push(FlowEvent::Assign {
                        span: *span,
                        target: format!("{target}.{field_name}"),
                        source_name: None,
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: erlang_value_source_names(&field_value),
                        declares_new_binding: false,
                        value_kind: None,
                    });
                }
            }
        }
        // Keep the original event ahead of the synthetic ones — tools
        // expect the assignment to appear before its field expansions.
        rewritten.push(event);
        rewritten.extend(synthetic_field_assigns);
    }
    *events = rewritten;
}

/// Synthesize a tail-return event for Erlang functions whose final
/// expression is implicitly returned. Erlang has no `return` keyword —
/// the last expression of a clause is its value — so the walker can't
/// emit a Return naturally; we add one textually.
fn augment_erlang_tail_return_event(
    events: &mut Vec<FlowEvent>,
    span: bonsai_common::Span,
    tree: &Tree,
    src: &str,
) {
    // Don't double up if any Return already exists (e.g. via early `case`
    // arm rewrites).
    if events
        .iter()
        .any(|event| matches!(event, FlowEvent::Return { .. }))
    {
        return;
    }
    let Some((value_text, value_name, value_span)) = erlang_tail_return_value(src, span) else {
        return;
    };
    let value_flow = usize::try_from(value_span.start)
        .ok()
        .zip(usize::try_from(value_span.end).ok())
        // Use the smallest named syntax node for the exact tail span. The
        // generic descendant query may return an enclosing clause when the
        // range begins or ends on trivia, which would incorrectly pull calls
        // from earlier expressions into a literal tail return.
        .and_then(|(start, end)| tree.root_node().named_descendant_for_byte_range(start, end))
        .map(|value| bonsai_lang_api::kit::expression_flow_from_node(value, value_span.file, src.as_bytes()))
        .unwrap_or_default();
    events.push(FlowEvent::Return {
        span: value_span,
        value_text: Some(value_text),
        value_name,
        value_flow,
    });
}

/// Parse `Lhs = callee(args, ...)` out of an assignment span and return
/// `(callee, args)` if the RHS is a clean call expression.
fn erlang_assignment_call_rhs(src: &str, span: bonsai_common::Span) -> Option<(String, Vec<String>)> {
    let span_text = erlang_span_text(src, span)?;
    let (_lhs, rhs_with_dot) = split_top_level_match_expr(span_text)?;
    erlang_call_expr(rhs_with_dot.trim().trim_end_matches('.').trim())
}

/// Slice the right-hand side text out of `Lhs = Rhs` for a given span,
/// stripping trailing `.` and surrounding whitespace.
fn erlang_assignment_rhs_text(src: &str, span: bonsai_common::Span) -> Option<&str> {
    let span_text = erlang_span_text(src, span)?;
    let (_lhs, rhs_with_dot) = split_top_level_match_expr(span_text)?;
    Some(rhs_with_dot.trim().trim_end_matches('.').trim())
}

/// Add source operands for Erlang stdlib collection transforms whose
/// result is semantically derived from one collection input.
fn add_erlang_collection_transform_sources(
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &mut Vec<String>,
) {
    let Some(callee) = source_call else {
        return;
    };
    let source_arg_index = match normalise_erlang_callee_separator(callee).as_str() {
        // string:tokens(String, Separators) returns parts of String.
        "string.tokens" => Some(0),
        // lists:map(Fun, List) and lists:filter(Pred, List) preserve
        // element taint from List into the result collection.
        "lists.map" | "lists.filter" => Some(1),
        // lists:foldl(Fun, Acc0, List) / foldr derive the result from
        // the list elements under the callback.
        "lists.foldl" | "lists.foldr" => Some(2),
        _ => None,
    };
    let Some(source_arg) = source_arg_index.and_then(|idx| source_call_args.get(idx)) else {
        return;
    };
    for source in erlang_value_source_names(source_arg) {
        push_unique_string(source_names, source);
    }
}

fn augment_erlang_collection_transform_flow_events(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                let source_call = source_call.clone();
                let source_call_args = source_call_args.clone();
                add_erlang_collection_transform_sources(
                    source_call.as_deref(),
                    &source_call_args,
                    source_names,
                );
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_erlang_collection_transform_flow_events(then_events);
                augment_erlang_collection_transform_flow_events(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_erlang_collection_transform_flow_events(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_erlang_collection_transform_flow_events(body);
                augment_erlang_collection_transform_flow_events(catch_events);
                augment_erlang_collection_transform_flow_events(finally_events);
            }
            _ => {}
        }
    }
}

fn normalise_erlang_callee_separator(callee: &str) -> String {
    callee.trim().replace(':', ".")
}

/// Extract source operands from Erlang list/binary comprehension
/// generators, e.g. `[Part || Part <- string:tokens(Cmd, " ")]`.
fn erlang_comprehension_generator_sources(rhs_text: &str) -> Vec<String> {
    let Some((_, qualifiers)) = split_top_level_erlang_comprehension(rhs_text) else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    for qualifier in split_top_level_args(qualifiers) {
        let Some((_, generator_source)) = split_top_level_erlang_generator(&qualifier) else {
            continue;
        };
        for source in erlang_value_source_names(generator_source) {
            push_unique_string(&mut sources, source);
        }
    }
    sources
}

/// Erlang comprehensions in tail/return position — `handler() -> [os:cmd(X)
/// || X <- [Cmd]]` — bind the loop variable (`X`) to the iterable, but the
/// shared walker records only the body call (`os:cmd(X)`) and a Return
/// whose text is the whole comprehension; no binding event links `X` to
/// `Cmd`, so the iterable's taint never reaches the body. Synthesize an
/// `Assign { target: X, source_names: [Cmd] }` for each generator so the
/// loop variable inherits the iterable's taint. Inserted just before the
/// comprehension-bearing event so it follows any assignment that taints the
/// iterable (`Cmd = os:getenv(...)` earlier in the body).
type ErlangComprehensionBindings = Vec<(String, Vec<String>)>;

fn inject_erlang_comprehension_generator_bindings(
    events: &mut Vec<FlowEvent>,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let comprehensions = collect_kinds(tree, &["list_comprehension", "binary_comprehension"]);
    let mut plans: Vec<(bonsai_common::Span, ErlangComprehensionBindings)> = Vec::new();
    for event in events.iter() {
        let FlowEvent::Return { span, .. } = event else {
            continue;
        };
        let Some(comprehension) = comprehensions
            .iter()
            .copied()
            .find(|node| span_of(file, node) == *span)
        else {
            continue;
        };
        let bindings = erlang_comprehension_generator_bindings_from_node(comprehension, src);
        if !bindings.is_empty() {
            plans.push((*span, bindings));
        }
    }
    if plans.is_empty() {
        return;
    }
    let mut inserts: Vec<(usize, FlowEvent)> = Vec::new();
    for (comp_span, bindings) in plans {
        // The comprehension BODY (`os:cmd(X)`) is emitted as its own
        // event nested inside `comp_span`, and it appears in the list
        // BEFORE the Return that carries the whole-comprehension text.
        // Insert the loop-variable binding before the earliest event
        // whose span falls inside the comprehension, so the body's read
        // of `X` sees the binding's write. Fall back to the first event
        // at/after the comprehension start when no nested body exists.
        let insert_idx = events
            .iter()
            .position(|e| {
                let s = e.span();
                s.start >= comp_span.start && s.end <= comp_span.end
            })
            .or_else(|| events.iter().position(|e| e.span().start >= comp_span.start))
            .unwrap_or(events.len());
        for (var, sources) in bindings {
            if var.is_empty() {
                continue;
            }
            inserts.push((
                insert_idx,
                FlowEvent::Assign {
                    span: comp_span,
                    target: var,
                    source_name: None,
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: sources,
                    declares_new_binding: true,
                    value_kind: None,
                },
            ));
        }
    }
    // Insert from the back so earlier indices stay valid.
    inserts.sort_by_key(|(idx, _)| *idx);
    for (idx, event) in inserts.into_iter().rev() {
        let idx = idx.min(events.len());
        events.insert(idx, event);
    }
}

fn erlang_comprehension_generator_bindings_from_node(
    comprehension: Node<'_>,
    src: &[u8],
) -> ErlangComprehensionBindings {
    fn collect_generators<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
        if matches!(node.kind(), "generator" | "b_generator" | "map_generator") {
            out.push(node);
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_generators(child, out);
        }
    }

    fn collect_variables(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        if node.kind() == "var" {
            push_unique_string(out, node_text(&node, src).trim().to_string());
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_variables(child, src, out);
        }
    }

    let mut generators = Vec::new();
    collect_generators(comprehension, &mut generators);
    let mut bindings = Vec::new();
    for generator in generators {
        let Some(lhs) = generator.child_by_field_name("lhs") else {
            continue;
        };
        let Some(rhs) = generator.child_by_field_name("rhs") else {
            continue;
        };
        let mut targets = Vec::new();
        collect_variables(lhs, src, &mut targets);
        let Some(target) = targets.into_iter().next() else {
            continue;
        };
        let mut sources = Vec::new();
        collect_variables(rhs, src, &mut sources);
        if !sources.is_empty() {
            bindings.push((target, sources));
        }
    }
    bindings
}

fn split_top_level_erlang_comprehension(text: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
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
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '|' if matches!(iter.peek(), Some((_, '|'))) && depth == 1 => {
                let _ = iter.next();
                let qualifiers = text[idx + 2..].trim();
                let qualifiers = qualifiers
                    .strip_suffix(']')
                    .or_else(|| qualifiers.strip_suffix(">>"))
                    .unwrap_or(qualifiers)
                    .trim();
                return Some((text[..idx].trim(), qualifiers));
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_erlang_generator(text: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
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
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '<' if matches!(iter.peek(), Some((_, '-'))) && depth == 0 => {
                let _ = iter.next();
                return Some((text[..idx].trim(), text[idx + 2..].trim()));
            }
            _ => {}
        }
    }
    None
}

/// Identify the implicit return expression of an Erlang function clause.
/// Returns `(normalized text, optional value name, byte span)` so the
/// caller can emit a synthetic Return event.
fn erlang_tail_return_value(
    src: &str,
    span: bonsai_common::Span,
) -> Option<(String, Option<String>, bonsai_common::Span)> {
    let span_text = erlang_span_text(src, span)?;
    // Skip past the `->` arrow into the body.
    let arrow_offset = find_erlang_arrow(span_text)?;
    let body_start = arrow_offset + 2;
    let body = span_text[body_start..].trim_end();
    // Drop the trailing `.` that terminates every clause.
    let body = body.strip_suffix('.').unwrap_or(body).trim_end();
    // The last `,`- or `;`-separated expression is the implicit return.
    let (relative_expr_start, last_expr) = last_erlang_sequence_expr(body)?;
    let trimmed_expr = last_expr.trim();
    let normalized_expr = normalize_erlang_return_expr(trimmed_expr)?;
    let value_name = erlang_return_value_name(&normalized_expr);
    // Translate the exact, whitespace-adjusted relative offset back to the
    // source file's byte coordinates.
    let absolute_start = usize::try_from(span.start).ok()? + body_start + relative_expr_start;
    let absolute_end = absolute_start + trimmed_expr.len();
    Some((
        normalized_expr,
        value_name,
        bonsai_common::Span::new(
            span.file,
            u64::try_from(absolute_start).unwrap_or(u64::MAX),
            u64::try_from(absolute_end).unwrap_or(u64::MAX),
        ),
    ))
}

/// Slice the source text for a span, returning `None` if the bytes
/// fall outside the buffer or land inside a multi-byte char.
fn erlang_span_text(src: &str, span: bonsai_common::Span) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?.min(src.len());
    let end = usize::try_from(span.end).ok()?.min(src.len());
    if start >= end || !src.is_char_boundary(start) || !src.is_char_boundary(end) {
        return None;
    }
    Some(&src[start..end])
}

/// Slice the parameter list out of a function-clause header. The header
/// is everything before `->`; we extract the contents of its outermost
/// parentheses.
fn erlang_function_params_text(text: &str) -> Option<&str> {
    let arrow_offset = find_erlang_arrow(text)?;
    let header = &text[..arrow_offset];
    let open_paren = header.find('(')?;
    let close_paren = header.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    Some(&header[open_paren + 1..close_paren])
}

fn erlang_clause_param_slots(src: &str, span: bonsai_common::Span, name: &str) -> Option<Vec<String>> {
    let text = erlang_span_text(src, span)?;
    let arrow_offset = find_erlang_arrow(text)?;
    let header = &text[..arrow_offset];
    let name_start = header.find(name)?;
    let after_name = header[name_start + name.len()..].trim_start();
    if !after_name.starts_with('(') {
        return Some(Vec::new());
    }
    let close = find_matching_erlang_delim(after_name, 0, b'(', b')')?;
    let params_text = &after_name[1..close];
    if params_text.trim().is_empty() {
        return Some(Vec::new());
    }
    let args = split_top_level_args(params_text);
    Some(
        args.iter()
            .enumerate()
            .map(|(idx, arg)| erlang_pattern_param_name(arg).unwrap_or_else(|| format!("_Arg{idx}")))
            .collect(),
    )
}

/// Pick the variable name out of a pattern fragment. Handles the
/// `R = #user{...}` shape by treating `=` as a separator and returning
/// the first variable-shaped token.
fn erlang_pattern_param_name(arg: &str) -> Option<String> {
    for part in split_top_level_args(&arg.replace('=', ",")) {
        let candidate = part.trim();
        if erlang_variable_name(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn erlang_pattern_bound_variables(arg: &str) -> Vec<String> {
    erlang_value_source_names(arg)
        .into_iter()
        .filter(|name| erlang_variable_name(name))
        .collect()
}

/// Extract `(field, variable)` pairs from a record pattern. Only entries
/// whose RHS is a bare variable count — literals/expressions don't bind.
fn erlang_record_pattern_bindings(text: &str) -> Vec<(String, String)> {
    erlang_record_field_initializers(text)
        .into_iter()
        .filter(|(_, value)| erlang_variable_name(value))
        .collect()
}

/// Walk `#tag{f1 = v1, f2 = v2, ...}` shapes inside `text` and return
/// each `(field, normalized value)` pair. Multiple records inside the
/// same input are flattened into a single list.
fn erlang_record_field_initializers(text: &str) -> Vec<(String, String)> {
    let mut field_value_pairs = Vec::new();
    for record_body in erlang_record_bodies(text) {
        for part in split_top_level_args(&record_body) {
            let Some((field, value)) = split_top_level_match_expr(&part) else {
                continue;
            };
            let field = field.trim();
            // Field labels must be lowercase atoms; skip anything else
            // (defends against malformed parses).
            if !erlang_atom_name(field) {
                continue;
            }
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            field_value_pairs.push((field.to_string(), normalize_erlang_value_expr(value)));
        }
    }
    field_value_pairs
}

/// Pull the body of every `#tag{...}` record literal out of `text`,
/// returning the contents (excluding braces) of each. Quoted regions
/// and escape sequences are skipped so `#` inside a string doesn't
/// trigger a false match.
fn erlang_record_bodies(text: &str) -> Vec<String> {
    let mut record_bodies = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        // String/char-literal pass-through: ignore everything until the
        // matching close quote so `#` inside a literal isn't seen as a
        // record marker.
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
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        if ch != '#' {
            continue;
        }
        // Walk past the record tag (an atom-like identifier).
        let mut tag_end = idx + ch.len_utf8();
        while tag_end < text.len() && erlang_ident_byte(text.as_bytes()[tag_end]) {
            tag_end += 1;
        }
        // Reject `#` not followed by an atom + `{` — could be a map
        // pattern or a comment.
        if tag_end == idx + ch.len_utf8() || text.as_bytes().get(tag_end) != Some(&b'{') {
            continue;
        }
        if let Some(brace_end) = find_matching_erlang_delim(text, tag_end, b'{', b'}') {
            record_bodies.push(text[tag_end + 1..brace_end].to_string());
        }
        // Advance the outer iterator past the consumed tag bytes so we
        // don't re-scan inside the record.
        while iter.peek().is_some_and(|(next, _)| *next <= tag_end) {
            let _ = iter.next();
        }
    }
    record_bodies
}

/// Find the byte index of the `close` byte that pairs with the `open`
/// byte at `open_idx`, respecting nesting and string literals.
fn find_matching_erlang_delim(text: &str, open_idx: usize, open: u8, close: u8) -> Option<usize> {
    if text.as_bytes().get(open_idx) != Some(&open) {
        return None;
    }
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text
        .char_indices()
        .skip_while(|(byte_idx, _)| *byte_idx < open_idx)
    {
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
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        // Guard `is_ascii()` before narrowing: `ch as u8` truncates to the
        // low byte, so a non-ASCII char whose codepoint & 0xFF equals an
        // ASCII delimiter (e.g. 'Ż' U+017B & 0xFF == b'{') would otherwise
        // be miscounted as a brace/paren and drift the depth.
        if ch.is_ascii() && ch as u8 == open {
            depth = depth.saturating_add(1);
        } else if ch.is_ascii() && ch as u8 == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

/// Canonicalize a value expression so taint tracking sees a stable place
/// path. `maps:get(key, M)` and single record accesses collapse to a
/// dotted path; everything else passes through unchanged.
fn normalize_erlang_value_expr(value: &str) -> String {
    let value = value.trim().trim_end_matches('.').trim();
    if let Some(access) = erlang_maps_get_access(value) {
        return access;
    }
    if let Some(access) = single_erlang_record_access(value) {
        return access;
    }
    value.to_string()
}

/// Collect every variable / record-access / `maps:get` source named
/// inside `value`. Used to populate `source_names` so the taint engine
/// can connect field-level reads back to their roots.
fn erlang_value_source_names(value: &str) -> Vec<String> {
    let mut sources = Vec::new();
    for access in erlang_record_accesses_in_text(value) {
        push_unique_string(&mut sources, access);
    }
    if let Some(access) = erlang_maps_get_access(value) {
        push_unique_string(&mut sources, access);
    }
    // Tokenize variable names by walking char-by-char outside string
    // literals. Append a sentinel space so the trailing token gets
    // flushed.
    let mut token = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in value.chars().chain(std::iter::once(' ')) {
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
        if matches!(ch, '"' | '\'') {
            // Flush whatever's accumulated before entering the literal.
            if erlang_variable_name(&token) {
                push_unique_string(&mut sources, token.clone());
            }
            token.clear();
            quote = Some(ch);
            continue;
        }
        if ch == '_' || ch == '@' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }
        // Hit a non-ident byte: flush the accumulated token if it looks
        // like an Erlang variable.
        if erlang_variable_name(&token) {
            push_unique_string(&mut sources, token.clone());
        }
        token.clear();
    }
    sources
}

/// Locate the `->` separating an Erlang clause head from its body,
/// returning the byte index of the `-`. Skips arrows inside string
/// literals.
fn find_erlang_arrow(text: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
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
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        if ch == '-' && matches!(iter.peek(), Some((_, '>'))) {
            return Some(idx);
        }
    }
    None
}

/// Split `text` on the first top-level `=` into `(lhs, rhs)`. Skips
/// `==`, `=<`, `=>` operators and any `=` inside parens / brackets /
/// strings.
fn split_top_level_match_expr(text: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
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
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => {
                // Skip compound operators: `==`, `=<`, `=>`.
                let next_char = iter.peek().map(|(_, next)| *next);
                if matches!(next_char, Some('=' | '<' | '>')) {
                    continue;
                }
                return Some((&text[..idx], &text[idx + 1..]));
            }
            _ => {}
        }
    }
    None
}

/// Find the start byte and slice of the last expression in a comma /
/// semicolon-separated sequence. Erlang's body is a sequence and the
/// final expression is the implicit return value.
fn last_erlang_sequence_expr(body: &str) -> Option<(usize, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut last_expr_start = 0usize;
    for (idx, ch) in body.char_indices() {
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
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            // Top-level `,` or `;` — the next expression starts here.
            ',' | ';' if depth == 0 => last_expr_start = idx + ch.len_utf8(),
            _ => {}
        }
    }
    let raw_last_expr = &body[last_expr_start..];
    let leading = raw_last_expr
        .len()
        .saturating_sub(raw_last_expr.trim_start().len());
    let last_expr = raw_last_expr.trim();
    (!last_expr.is_empty()).then_some((last_expr_start + leading, last_expr))
}

/// Canonicalize a return expression. Every non-empty Erlang tail expression
/// is a returned value; structured `ExpressionFlow` is subsequently lowered
/// from its exact tree-sitter node, so calls and compound expressions must not
/// be discarded merely because they are not storage-place spellings.
fn normalize_erlang_return_expr(expr: &str) -> Option<String> {
    let expr = expr.trim().trim_end_matches('.').trim();
    if expr.is_empty() {
        return None;
    }
    if erlang_return_container_expr(expr) {
        return Some(expr.to_string());
    }
    if let Some(access) = erlang_maps_get_access(expr) {
        return Some(access);
    }
    if let Some(access) = single_erlang_record_access(expr) {
        return Some(access);
    }
    if erlang_variable_name(expr) || erlang_atom_name(expr) || erlang_quoted_literal(expr) {
        return Some(expr.to_string());
    }
    Some(expr.to_string())
}

fn erlang_return_container_expr(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        || (trimmed.starts_with("<<") && trimmed.ends_with(">>"))
}

/// `Some(value)` when `value` is taintable as a return — variables or
/// dotted place paths qualify; literals don't.
fn erlang_return_value_name(value: &str) -> Option<String> {
    (erlang_variable_name(value) || value.contains('.')).then(|| value.to_string())
}

/// `true` if `text` is a `"..."` string or `'...'` quoted-atom literal.
fn erlang_quoted_literal(text: &str) -> bool {
    let text = text.trim();
    (text.starts_with('"') && text.ends_with('"') && text.len() >= 2)
        || (text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2)
}

/// Parse `callee(arg1, arg2, ...)` into `(callee, args)`. The callee
/// must be a clean module-or-local name (`mod:fun` collapses to
/// `mod.fun`); trailing characters after the close paren reject the
/// match.
fn erlang_call_expr(text: &str) -> Option<(String, Vec<String>)> {
    let open_paren = text.find('(')?;
    let close_paren = text.rfind(')')?;
    if close_paren <= open_paren || !text[close_paren + 1..].trim().is_empty() {
        return None;
    }
    let callee = text[..open_paren].trim();
    if !erlang_callee_name(callee) {
        return None;
    }
    let args = split_top_level_args(&text[open_paren + 1..close_paren]);
    // Normalize remote-call syntax to dotted form so downstream matchers
    // see a consistent name shape.
    Some((callee.replace(':', "."), args))
}

/// `true` when `text` is a syntactically-valid Erlang callee (module-
/// qualified or local).
fn erlang_callee_name(text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return false;
    }
    text.chars()
        .all(|ch| ch == '_' || ch == ':' || ch == '@' || ch.is_ascii_alphanumeric())
}

/// Find every `Var#tag.field` access inside the bytes covered by
/// `span`. Used to populate `source_names` on assignment events.
fn erlang_record_accesses_in_span(src: &str, span: bonsai_common::Span) -> Vec<String> {
    let start = usize::try_from(span.start).ok().unwrap_or(0).min(src.len());
    let end = usize::try_from(span.end).ok().unwrap_or(src.len()).min(src.len());
    if start >= end || !src.is_char_boundary(start) || !src.is_char_boundary(end) {
        return Vec::new();
    }
    erlang_record_accesses_in_text(&src[start..end])
}

/// `Some(access)` only when `text` is exactly one record access
/// (whitespace permitted around it). Anything else — multiple accesses,
/// or trailing tokens — returns `None`.
fn single_erlang_record_access(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let accesses = erlang_record_accesses_in_text(trimmed);
    if accesses.len() == 1 && record_access_consumes_text(trimmed) {
        accesses.into_iter().next()
    } else {
        None
    }
}

/// `true` when the only meaningful content of `text` is a single record
/// access — used to decide whether to substitute the canonical place
/// path in for the original expression.
fn record_access_consumes_text(text: &str) -> bool {
    let Some(hash_idx) = text.find('#') else {
        return false;
    };
    let Some((start, end)) = erlang_record_access_bounds(text, hash_idx) else {
        return false;
    };
    // No leading or trailing tokens around the access.
    text[..start].trim().is_empty() && text[end..].trim().is_empty()
}

/// Walk `text` collecting every `Var#tag.field` access as a normalized
/// `Var.field` place path.
fn erlang_record_accesses_in_text(text: &str) -> Vec<String> {
    let mut accesses = Vec::new();
    for (idx, ch) in text.char_indices() {
        if ch != '#' {
            continue;
        }
        if let Some((access, _start, _end)) = erlang_record_access_at(text, idx) {
            push_unique_string(&mut accesses, access);
        }
    }
    accesses
}

/// Try to parse a `Var#tag.field` access centered on the `#` at
/// `hash_idx`, returning `(canonical "Var.field", start, end)`. Returns
/// `None` when any required token is malformed.
fn erlang_record_access_at(text: &str, hash_idx: usize) -> Option<(String, usize, usize)> {
    let (start, end) = erlang_record_access_bounds(text, hash_idx)?;
    let before_hash = &text[start..hash_idx];
    let after_hash = &text[hash_idx + 1..end];
    let (record_name, field_name) = after_hash.split_once('.')?;
    // All three pieces must be syntactically valid; otherwise we'd
    // surface garbage place paths.
    if !erlang_variable_name(before_hash) || !erlang_atom_name(record_name) || !erlang_atom_name(field_name) {
        return None;
    }
    Some((format!("{before_hash}.{field_name}"), start, end))
}

/// Compute the byte bounds of the record access centered on `hash_idx`.
/// Walks identifier bytes leftward (the variable) and rightward (the
/// `tag.field` suffix).
fn erlang_record_access_bounds(text: &str, hash_idx: usize) -> Option<(usize, usize)> {
    if hash_idx >= text.len() || !text.is_char_boundary(hash_idx) {
        return None;
    }
    let bytes = text.as_bytes();
    // Left edge: walk back over the variable name.
    let mut start = hash_idx;
    while start > 0 && erlang_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    // Reject `#tag` with no preceding variable — that's record creation,
    // not access.
    if start == hash_idx {
        return None;
    }
    // Right edge: walk past `tag` then require a `.`, then walk past
    // `field`.
    let mut record_end = hash_idx + 1;
    while record_end < bytes.len() && erlang_ident_byte(bytes[record_end]) {
        record_end += 1;
    }
    if record_end == hash_idx + 1 || bytes.get(record_end) != Some(&b'.') {
        return None;
    }
    let field_start = record_end + 1;
    let mut end = field_start;
    while end < bytes.len() && erlang_ident_byte(bytes[end]) {
        end += 1;
    }
    if end == field_start {
        return None;
    }
    Some((start, end))
}

/// `true` if `text` matches Erlang's variable lexical form
/// (uppercase or `_` start, ident chars after).
fn erlang_variable_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
        && chars.all(|ch| ch == '_' || ch == '@' || ch.is_ascii_alphanumeric())
}

/// `true` if `text` matches Erlang's bare-atom lexical form (lowercase
/// or `_` start, ident chars after — no `@`, since that's variable-only).
fn erlang_atom_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// `true` if `byte` is part of an Erlang identifier (`_`, `@`, alnum).
fn erlang_ident_byte(byte: u8) -> bool {
    byte == b'_' || byte == b'@' || byte.is_ascii_alphanumeric()
}

/// Append `value` to `values` unless it is empty or already present.
fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

/// Parse a complete `maps:get(key, M)` or `maps:get(key, M, Default)`
/// expression and return its place path `M.key`.
fn erlang_maps_get_access(text: &str) -> Option<String> {
    let text = text.trim();
    let body = text
        .strip_prefix("maps:get(")
        .and_then(|rest| rest.strip_suffix(')'))?;
    let args = split_top_level_args(body);
    erlang_maps_get_access_from_args(&args)
}

/// Build a place path from already-split `maps:get` argument strings.
/// Requires both a fixed key and a clean map identifier — bails on
/// dynamic keys or expression-shaped maps.
fn erlang_maps_get_access_from_args(args: &[String]) -> Option<String> {
    if args.len() < 2 {
        return None;
    }
    let key = erlang_fixed_map_key(&args[0])?;
    let map = args[1].trim();
    // The map argument must be an identifier-shaped name; otherwise the
    // place path would be ambiguous.
    if map.is_empty()
        || !map
            .chars()
            .all(|ch| ch == '_' || ch == '@' || ch == '$' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(format!("{map}.{key}"))
}

/// `true` if `name` denotes the `maps:get` BIF in either remote-call
/// or normalized dotted form.
fn erlang_maps_get_callee_name(name: &str) -> bool {
    let trimmed = name.trim();
    trimmed == "maps:get" || trimmed == "maps.get"
}

/// Validate an Erlang map key as an atom-shaped fixed value. Returns
/// the cleaned key (no quotes, no leading colon) when valid.
fn erlang_fixed_map_key(text: &str) -> Option<String> {
    let key = text
        .trim()
        .trim_start_matches(':')
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if key.is_empty() {
        return None;
    }
    let mut chars = key.chars();
    // First char must look like the start of an atom.
    if !chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
    {
        return None;
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(key.to_string())
}

/// Split a comma-separated argument list at the top nesting level,
/// trimming each piece. Respects parens / brackets / braces / quotes
/// so commas inside nested structures stay in place.
fn split_top_level_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut arg_start = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
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
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(text[arg_start..idx].trim().to_string());
                arg_start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    args.push(text[arg_start..].trim().to_string());
    args
}

/// Collect every function name in `-export([f/arity, g/arity, ...]).`
/// attributes. Functions not exported are module-private; they are
/// visible inside the module but not callable from other modules.
fn collect_erlang_exported_names(tree: &tree_sitter::Tree, src: &[u8]) -> std::collections::HashSet<String> {
    let mut exported_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for export_node in collect_kinds(tree, &["export_attribute"]) {
        // Walk for any `atom` descendant; export entries look like
        // `f/2` so the function name is the leading atom of each
        // `arity_qualifier` child. Be permissive: any atom inside
        // an export_attribute is treated as an exported name.
        let mut stack = vec![export_node];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "atom" | "function_name") {
                let name_text = node_text(&node, src).trim();
                if !name_text.is_empty() {
                    exported_names.insert(name_text.to_string());
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    exported_names
}

#[cfg(test)]
mod tests;
