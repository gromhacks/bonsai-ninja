//! Elixir language adapter.
//!
//! Elixir's `def` and `defp` are macros, not keywords — tree-sitter-elixir
//! parses them as `call` nodes whose target is the identifier `def` or
//! `defp`. We use `call` as the function-kind and filter by the target
//! identifier in the grammar handler. Constructs with `do ... end`
//! blocks (function bodies, branches, loops) all share the `do_block`
//! grammar kind.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node, collect_kinds, first_named_child_of_kind, language_from_pack, node_text,
        parse_with, span_of,
    },
    with_fn_kinds, AdapterContext, AdapterError, DeclIndex, GrammarHandler, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath, Ref, RefKind, Visibility,
};
use bonsai_lang_api::{AssignValueKind, FlowEvent};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("elixir");
const PACK_NAME: &str = "elixir";
// Elixir has no direct `function_definition` grammar node. Function
// definitions come through as `call` nodes with target `def` / `defp`.
// Accepting `call` as the fn-kind means the adapter treats every call
// as a potential function body; the walker then finds the actual name
// from the child identifier. This over-captures (macro calls that aren't
// definitions also match), but that's the cost of Elixir's macro-based
// syntax — precision upgrades would require a hand-rolled handler
// filtering by target.
const HANDLER: GrammarHandler = GrammarHandler {
    assignment_kinds: &["binary_operator"],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    // Elixir functions return their final expression; the kit emits a
    // `Return` for the last statement of the `do` block.
    tail_expression_returns: true,
    ..with_fn_kinds(&["call"])
};

#[derive(Debug, Default, Copy, Clone)]
pub struct ElixirAdapter;

impl ElixirAdapter {
    /// Construct a stateless Elixir adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ElixirAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Elixir"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ex", "exs"]
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
        // Elixir privacy: `defp` is module-private, `def` is public.
        // Both lower to `call` nodes whose target identifier names
        // the macro. Walk for `defp` call spans, then mark matching
        // decls private.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let map_field_assigns = collect_elixir_map_literal_field_assigns(&tree, src, file);
            let value_field_access_spans = collect_elixir_value_field_access_spans(&tree, file);
            let local_callable_invocations = collect_elixir_local_callable_invocations(&tree, src, file);
            decl_index
                .refs
                .extend(synthesize_elixir_value_field_reads(&tree, src, file));
            let module_spans = collect_elixir_module_spans(&tree, src, file);
            if module_spans.is_empty() {
                bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
            } else {
                apply_elixir_module_identity(&mut decl_index, &module_spans);
            }
            for decl in &mut decl_index.defs {
                if let Some(params) = elixir_clause_param_slots(snapshot.text.as_ref(), decl.span, &decl.name)
                {
                    decl.params = params;
                    augment_elixir_param_pattern_bindings(decl, snapshot.text.as_ref());
                }
                inject_elixir_local_callable_invocations(decl, &local_callable_invocations);
                insert_elixir_map_field_assigns_in_events(&mut decl.flow_events, &map_field_assigns);
                remove_elixir_value_field_access_calls(&mut decl.flow_events, &value_field_access_spans);
                normalize_elixir_control_expression_assignments(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                );
                bonsai_lang_api::kit::annotate_tuple_call_result_bindings(&mut decl.flow_events, &tree, src);
            }
            let private_spans = collect_elixir_defp_spans(&tree, src);
            for decl in &mut decl_index.defs {
                let body_start = decl.body_span.map(|s| s.start).unwrap_or(decl.span.start);
                let body_end = decl.body_span.map(|s| s.end).unwrap_or(decl.span.end);
                // Match either by exact body-span anchor, or by an
                // enclosing span that aligns with the decl's start —
                // the walker may have anchored to either depending on
                // whether a `do` block was seen.
                if private_spans.iter().any(|(defp_start, defp_end)| {
                    *defp_start == body_start
                        || (*defp_start >= body_start
                            && *defp_end <= body_end
                            && *defp_start == decl.span.start)
                }) {
                    decl.visibility = Visibility::Module;
                }
            }
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        }
        // Recognised Elixir lifecycle transitions. Elixir's
        // tree-sitter call names land as bare atoms (e.g.
        // `:gen_server.stop` reads as `:gen_server.stop`); the
        // matcher's call-name comparison strips the leading colon
        // when the rule key omits it. Bare `close`/`cancel` cover
        // ad-hoc resource APIs that follow the same convention.
        const ELIXIR_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: ":gen_server.stop",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: ":ets.delete",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "Process.exit",
                transition: "cancelled",
                arg_index: 0,
            },
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
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, ELIXIR_LIFECYCLE_TRANSITIONS);
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

/// Elixir invokes a function value as `binding.()`. Tree-sitter represents
/// the callee as a `dot` node with only a left operand, so the generic call
/// extractor (which expects a named member on the right) correctly refuses
/// to invent a method name. Lower that exact CST shape to an ordinary local
/// call fact here; the callgraph/IDG then resolves `binding` through its
/// assignment to the nested function declaration.
fn collect_elixir_local_callable_invocations(tree: &Tree, src: &[u8], file: FileId) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let Some(arguments) = call
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call, "arguments"))
        else {
            continue;
        };
        let Some(target) = call.child_by_field_name("target").or_else(|| call.named_child(0)) else {
            continue;
        };
        if target.kind() != "dot" || target.child_by_field_name("right").is_some() {
            continue;
        }
        let Some(left) = target
            .child_by_field_name("left")
            .or_else(|| target.named_child(0))
        else {
            continue;
        };
        if left.kind() != "identifier" || target.named_child_count() != 1 {
            continue;
        }
        let name = node_text(&left, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let mut args = Vec::new();
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            if let Some(argument) = call_arg_from_node(argument, file, src, None) {
                args.push(argument);
            }
        }
        out.push(FlowEvent::Call {
            span: span_of(file, &target),
            name,
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args,
        });
    }
    out.sort_by_key(|event| (event.span().start, event.span().end));
    out.dedup_by_key(|event| event.span());
    out
}

fn inject_elixir_local_callable_invocations(decl: &mut bonsai_lang_api::Decl, invocations: &[FlowEvent]) {
    let owner = decl.body_span.unwrap_or(decl.span);
    for invocation in invocations {
        let span = invocation.span();
        if span.file != owner.file || span.start < owner.start || span.end > owner.end {
            continue;
        }
        let FlowEvent::Call {
            name,
            receiver,
            receiver_types,
            call_kind,
            args,
            ..
        } = invocation
        else {
            continue;
        };
        if normalize_elixir_local_callable_call(
            &mut decl.flow_events,
            span,
            name,
            receiver.as_deref(),
            receiver_types,
            *call_kind,
            args,
        ) {
            continue;
        }
        if flow_events_contain_call_span(&decl.flow_events, span) {
            continue;
        }
        decl.flow_events.push(invocation.clone());
    }
    decl.flow_events
        .sort_by_key(|event| (event.span().start, event.span().end));
}

#[allow(clippy::too_many_arguments)]
fn normalize_elixir_local_callable_call(
    events: &mut [FlowEvent],
    target: bonsai_common::Span,
    name: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: bonsai_lang_api::CallKind,
    args: &[bonsai_lang_api::CallArg],
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name: event_name,
                receiver: event_receiver,
                receiver_types: event_receiver_types,
                call_kind: event_call_kind,
                args: event_args,
            } if *span == target => {
                event_name.clear();
                event_name.push_str(name);
                *event_receiver = receiver.map(str::to_string);
                event_receiver_types.clear();
                event_receiver_types.extend_from_slice(receiver_types);
                *event_call_kind = call_kind;
                event_args.clear();
                event_args.extend_from_slice(args);
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if normalize_elixir_local_callable_call(
                    then_events,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) || normalize_elixir_local_callable_call(
                    else_events,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if normalize_elixir_local_callable_call(
                    body,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if normalize_elixir_local_callable_call(
                    body,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) || normalize_elixir_local_callable_call(
                    catch_events,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) || normalize_elixir_local_callable_call(
                    finally_events,
                    target,
                    name,
                    receiver,
                    receiver_types,
                    call_kind,
                    args,
                ) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn flow_events_contain_call_span(events: &[FlowEvent], target: bonsai_common::Span) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Call { span, .. } => *span == target,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            flow_events_contain_call_span(then_events, target)
                || flow_events_contain_call_span(else_events, target)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            flow_events_contain_call_span(body, target)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            flow_events_contain_call_span(body, target)
                || flow_events_contain_call_span(catch_events, target)
                || flow_events_contain_call_span(finally_events, target)
        }
        _ => false,
    })
}

#[derive(Clone, Debug)]
struct ElixirMapFieldAssigns {
    assign_span: bonsai_common::Span,
    target: String,
    fields: Vec<FlowEvent>,
}

fn collect_elixir_map_literal_field_assigns(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<ElixirMapFieldAssigns> {
    let mut out = Vec::new();
    for assignment in collect_kinds(tree, &["binary_operator"]) {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if right.kind() != "map" {
            continue;
        }
        let target = node_text(&left, src).trim().to_string();
        if target.is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        for pair in elixir_direct_map_pairs(right) {
            let Some(key_node) = pair.child_by_field_name("key") else {
                continue;
            };
            let Some(value_node) = pair.child_by_field_name("value") else {
                continue;
            };
            let Some(key) = elixir_map_key(key_node, src) else {
                continue;
            };
            let sources = elixir_value_source_names(value_node, src);
            fields.push(FlowEvent::Assign {
                span: span_of(file, &value_node),
                target: format!("{target}.{key}"),
                source_name: (sources.len() == 1).then(|| sources[0].clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: sources,
                declares_new_binding: false,
                value_kind: Some(AssignValueKind::Compound),
            });
        }
        if !fields.is_empty() {
            out.push(ElixirMapFieldAssigns {
                assign_span: span_of(file, &assignment),
                target,
                fields,
            });
        }
    }
    out
}

fn elixir_direct_map_pairs(map: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut pending = vec![map];
    while let Some(node) = pending.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "pair" {
                out.push(child);
            } else if matches!(child.kind(), "map_content" | "keywords") {
                pending.push(child);
            }
        }
    }
    out.sort_by_key(|pair| pair.start_byte());
    out
}

fn elixir_map_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let key = raw
        .trim_end_matches(':')
        .trim()
        .trim_start_matches(':')
        .trim_matches(['"', '\'']);
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch == '_' || ch == '@' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(key.to_string())
}

fn elixir_value_source_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    fn collect(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        match node.kind() {
            "identifier" => {
                let source = node_text(&node, src).trim();
                if !source.is_empty() {
                    out.push(source.to_string());
                }
                return;
            }
            // Strings and charlists are not always literals in Elixir: their
            // CST may contain interpolation children (`"#{raw}"`). Walk
            // those children so the AST, rather than a text/name table,
            // determines the field's value dependencies.
            "integer" | "float" | "atom" | "true" | "false" | "nil" => {
                return;
            }
            "call" => {
                if node.child_by_field_name("arguments").is_none() {
                    if let Some(target) = node.child_by_field_name("target") {
                        if target.kind() == "dot" {
                            let source = node_text(&target, src).replace([' ', '\t', '\n', '\r'], "");
                            if !source.is_empty() {
                                out.push(source);
                            }
                            return;
                        }
                    }
                }
            }
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

fn insert_elixir_map_field_assigns_in_events(
    events: &mut Vec<FlowEvent>,
    field_assigns: &[ElixirMapFieldAssigns],
) {
    let mut index = 0usize;
    while index < events.len() {
        match &mut events[index] {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                insert_elixir_map_field_assigns_in_events(then_events, field_assigns);
                insert_elixir_map_field_assigns_in_events(else_events, field_assigns);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                insert_elixir_map_field_assigns_in_events(body, field_assigns);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                insert_elixir_map_field_assigns_in_events(body, field_assigns);
                insert_elixir_map_field_assigns_in_events(catch_events, field_assigns);
                insert_elixir_map_field_assigns_in_events(finally_events, field_assigns);
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

#[derive(Clone, Debug)]
struct ElixirModuleSpan {
    span: bonsai_common::Span,
    module: String,
}

fn collect_elixir_module_spans(tree: &Tree, src: &[u8], file: FileId) -> Vec<ElixirModuleSpan> {
    let mut raw = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        if call_target_text(&call_node, src).as_deref() != Some("defmodule") {
            continue;
        }
        let Some(args_node) = call_node
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call_node, "arguments"))
        else {
            continue;
        };
        let mut args_cursor = args_node.walk();
        let Some(module_node) = args_node
            .named_children(&mut args_cursor)
            .find(|child| child.kind() == "alias")
        else {
            continue;
        };
        let module = node_text(&module_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        raw.push((span_of(file, &call_node), module));
    }

    raw.sort_by_key(|(span, _)| (span.start, std::cmp::Reverse(span.end)));
    let mut resolved = Vec::new();
    for (idx, (span, module)) in raw.iter().enumerate() {
        let parent = raw
            .iter()
            .enumerate()
            .filter(|(parent_idx, (parent_span, _))| {
                *parent_idx != idx
                    && parent_span.start <= span.start
                    && parent_span.end >= span.end
                    && (parent_span.start, parent_span.end) != (span.start, span.end)
            })
            .min_by_key(|(_, (parent_span, _))| parent_span.end.saturating_sub(parent_span.start))
            .and_then(|(parent_idx, _)| resolved_module_for_raw_index(parent_idx, &raw, &resolved));
        let full_module = if module.contains('.') {
            module.clone()
        } else if let Some(parent) = parent {
            format!("{parent}.{module}")
        } else {
            module.clone()
        };
        resolved.push(ElixirModuleSpan {
            span: *span,
            module: full_module,
        });
    }
    resolved
}

fn resolved_module_for_raw_index(
    raw_idx: usize,
    raw: &[(bonsai_common::Span, String)],
    resolved: &[ElixirModuleSpan],
) -> Option<String> {
    let (span, module) = raw.get(raw_idx)?;
    resolved
        .iter()
        .find(|entry| entry.span.start == span.start && entry.span.end == span.end)
        .map(|entry| entry.module.clone())
        .or_else(|| module.contains('.').then(|| module.clone()))
}

fn apply_elixir_module_identity(idx: &mut DeclIndex, modules: &[ElixirModuleSpan]) {
    for decl in &mut idx.defs {
        let Some(module) = innermost_module_for_span(modules, decl.span) else {
            continue;
        };
        let segments: Vec<String> = module.split('.').map(str::to_string).collect();
        decl.module_path = ModulePath::from_segments(segments);
        decl.qualified_name = Some(format!("{module}.{}", decl.name));
    }
}

fn innermost_module_for_span(modules: &[ElixirModuleSpan], span: bonsai_common::Span) -> Option<&str> {
    modules
        .iter()
        .filter(|module| module.span.start <= span.start && module.span.end >= span.end)
        .min_by_key(|module| module.span.end.saturating_sub(module.span.start))
        .map(|module| module.module.as_str())
}

fn elixir_clause_param_slots(src: &str, span: bonsai_common::Span, name: &str) -> Option<Vec<String>> {
    let args = elixir_clause_raw_params(src, span, name)?;
    Some(
        args.iter()
            .enumerate()
            .map(|(idx, arg)| elixir_pattern_param_name(arg).unwrap_or_else(|| format!("_arg{idx}")))
            .collect(),
    )
}

fn elixir_clause_raw_params(src: &str, span: bonsai_common::Span, name: &str) -> Option<Vec<String>> {
    let text = elixir_span_text(src, span)?;
    let name_start = find_elixir_clause_name(text, name)?;
    let after_name = &text[name_start + name.len()..];
    let leading_ws = after_name.len().saturating_sub(after_name.trim_start().len());
    let after_name = &after_name[leading_ws..];
    if !after_name.starts_with('(') {
        return Some(Vec::new());
    }
    let close = find_matching_elixir_delim(after_name, 0, '(', ')')?;
    Some(split_elixir_top_level_args(&after_name[1..close]))
}

fn find_elixir_clause_name(text: &str, name: &str) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    text.match_indices(name).find_map(|(idx, _)| {
        let before = text[..idx].chars().next_back();
        let after = text[idx + name.len()..].chars().next();
        let before_ok = before.is_none_or(|ch| !elixir_ident_char(ch));
        let after_ok = after.is_none_or(|ch| !elixir_ident_char(ch));
        (before_ok && after_ok).then_some(idx)
    })
}

fn elixir_ident_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn elixir_span_text(src: &str, span: bonsai_common::Span) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?.min(src.len());
    let end = usize::try_from(span.end).ok()?.min(src.len());
    if start >= end || !src.is_char_boundary(start) || !src.is_char_boundary(end) {
        return None;
    }
    Some(&src[start..end])
}

fn elixir_pattern_param_name(arg: &str) -> Option<String> {
    let arg = arg.trim();
    if elixir_variable_name(arg) {
        return Some(arg.to_string());
    }
    if let Some((left, right)) = split_elixir_top_level_match(arg) {
        for candidate in [left.trim(), right.trim()] {
            if elixir_variable_name(candidate) {
                return Some(candidate.to_string());
            }
        }
    }
    if let Some((_, binding)) = split_elixir_top_level_on(arg, ':') {
        let binding = binding.trim();
        if elixir_variable_name(binding) {
            return Some(binding.to_string());
        }
    }
    // A default argument keeps the binding on its left side. This is a
    // grammar shape, not an inventory of parameter names.
    if let Some((binding, _)) = arg.split_once("\\\\") {
        let binding = binding.trim();
        if elixir_variable_name(binding) {
            return Some(binding.to_string());
        }
    }
    None
}

fn split_elixir_top_level_match(text: &str) -> Option<(&str, &str)> {
    split_elixir_top_level_on(text, '=')
}

fn split_elixir_top_level_on(text: &str, separator: char) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open {
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
            ch if ch == separator && depth == 0 => {
                return Some((&text[..idx], &text[idx + ch.len_utf8()..]));
            }
            _ => {}
        }
    }
    None
}

/// Lower destructured function-head parameters into explicit storage reads.
/// A head such as `%Envelope{cmd: cmd}` has one argument slot (`_arg0`) and
/// one AST-proven binding (`cmd = _arg0.cmd`). Keeping the slot distinct from
/// the binding prevents interprocedural field forwarding from inventing
/// `cmd.cmd` when the body reads the scalar `cmd`.
fn augment_elixir_param_pattern_bindings(decl: &mut bonsai_lang_api::Decl, src: &str) {
    let Some(args) = elixir_clause_raw_params(src, decl.span, &decl.name) else {
        return;
    };
    let mut bindings = Vec::new();
    for (idx, arg) in args.iter().enumerate() {
        let Some(slot) = decl.params.get(idx).cloned() else {
            continue;
        };
        for (field, target) in elixir_map_pattern_bindings(arg) {
            let source = format!("{slot}.{field}");
            bindings.push(FlowEvent::Assign {
                span: decl.name_span,
                target,
                source_name: Some(source.clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: vec![source],
                declares_new_binding: false,
                value_kind: None,
            });
        }
    }
    if !bindings.is_empty() {
        bindings.append(&mut decl.flow_events);
        decl.flow_events = bindings;
    }
}

fn elixir_map_pattern_bindings(text: &str) -> Vec<(String, String)> {
    let Some(open) = text.find('{') else {
        return Vec::new();
    };
    let Some(close) = find_matching_elixir_delim(text, open, '{', '}') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for field in split_elixir_top_level_args(&text[open + 1..close]) {
        let Some((key, value)) = field.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_start_matches(':').trim_matches(['"', '\'']);
        let value = value.trim();
        if !key.is_empty()
            && key
                .chars()
                .all(|ch| ch == '_' || ch == '@' || ch.is_ascii_alphanumeric())
            && elixir_variable_name(value)
        {
            out.push((key.to_string(), value.to_string()));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn elixir_variable_name(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_lowercase())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !matches!(text, "do" | "end" | "fn" | "true" | "false" | "nil")
}

fn normalize_elixir_control_expression_assignments(events: &mut [FlowEvent], src: &str) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } if source_call
                .as_deref()
                .is_some_and(elixir_control_expression_macro) =>
            {
                if let Some(branch_sources) = elixir_control_expression_value_sources(src, *span) {
                    *source_call = None;
                    source_call_args.clear();
                    *source_names = branch_sources;
                    *value_kind = Some(if source_names.is_empty() {
                        AssignValueKind::Literal
                    } else {
                        AssignValueKind::Compound
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_elixir_control_expression_assignments(then_events, src);
                normalize_elixir_control_expression_assignments(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_elixir_control_expression_assignments(body, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_elixir_control_expression_assignments(body, src);
                normalize_elixir_control_expression_assignments(catch_events, src);
                normalize_elixir_control_expression_assignments(finally_events, src);
            }
            _ => {}
        }
    }
}

fn elixir_control_expression_macro(name: &str) -> bool {
    matches!(name, "if" | "unless")
}

fn elixir_control_expression_value_sources(src: &str, span: bonsai_common::Span) -> Option<Vec<String>> {
    let text = elixir_span_text(src, span)?;
    let rhs = text.split_once('=').map_or(text, |(_, rhs)| rhs).trim();
    let body = elixir_do_else_body(rhs)?;
    let mut out = Vec::new();
    collect_elixir_branch_value_names(body.then_body, &mut out);
    if let Some(else_body) = body.else_body {
        collect_elixir_branch_value_names(else_body, &mut out);
    }
    out.sort();
    out.dedup();
    Some(out)
}

#[derive(Copy, Clone)]
struct ElixirDoElseBody<'a> {
    then_body: &'a str,
    else_body: Option<&'a str>,
}

fn elixir_do_else_body(text: &str) -> Option<ElixirDoElseBody<'_>> {
    // Inline keyword-list form first: `if cond, do: <then>[, else: <else>]`.
    // The block form below requires a standalone `do` AND a closing `end`; the
    // inline form has neither (`do`/`else` are keyword-pair keys, no `end`), so
    // the block parser returned None and the assignment never got its branch
    // sources -> taint was dropped (e.g. `cmd = if flag, do: input, else: ""`).
    if let Some(inline) = elixir_inline_keyword_do_else_body(text) {
        return Some(inline);
    }
    let mut scanner = ElixirKeywordScanner::new(text);
    let mut do_end = None;
    let mut else_range = None;
    let mut end_start = None;
    let mut depth = 0usize;
    while let Some((word, start, end)) = scanner.next_word() {
        match word {
            "do" => {
                depth = depth.saturating_add(1);
                do_end.get_or_insert(end);
            }
            "else" if depth == 1 => {
                else_range = Some((start, end));
            }
            "end" if depth > 0 => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end_start = Some(start);
                    break;
                }
            }
            _ => {}
        }
    }
    let do_end = do_end?;
    let end_start = end_start?;
    let (then_end, else_body) = if let Some((else_start, else_end)) = else_range {
        (else_start, Some(text[else_end..end_start].trim()))
    } else {
        (end_start, None)
    };
    Some(ElixirDoElseBody {
        then_body: text[do_end..then_end].trim(),
        else_body,
    })
}

/// Parse the INLINE keyword-list conditional form `if cond, do: then[, else: else]`
/// (also `unless`). Returns `None` for the block `do ... end` form (handled by the
/// caller's block parser) — distinguished by whether the standalone `do` word is
/// immediately followed by `:`. Everything after `do:` is returned as the branch
/// text: it carries BOTH the then-value and any `else:`-value identifiers, while
/// the condition (which precedes `do:`) is excluded. `else:` and string literals
/// are harmless to over-collect (never tainted); the value-name collector skips
/// string contents.
fn elixir_inline_keyword_do_else_body(text: &str) -> Option<ElixirDoElseBody<'_>> {
    let mut scanner = ElixirKeywordScanner::new(text);
    while let Some((word, _start, end)) = scanner.next_word() {
        if word == "do" {
            return if text[end..].starts_with(':') {
                Some(ElixirDoElseBody {
                    then_body: text[end + 1..].trim(),
                    else_body: None,
                })
            } else {
                // Standalone `do` -> block form; let the block parser handle it.
                None
            };
        }
    }
    None
}

struct ElixirKeywordScanner<'a> {
    text: &'a str,
    offset: usize,
    quote: Option<char>,
    escaped: bool,
}

impl<'a> ElixirKeywordScanner<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            offset: 0,
            quote: None,
            escaped: false,
        }
    }

    fn next_word(&mut self) -> Option<(&'a str, usize, usize)> {
        while self.offset < self.text.len() {
            let rest = &self.text[self.offset..];
            let mut chars = rest.char_indices();
            let (_, ch) = chars.next()?;
            let ch_len = ch.len_utf8();
            if let Some(open_quote) = self.quote {
                self.offset += ch_len;
                if self.escaped {
                    self.escaped = false;
                } else if ch == '\\' {
                    self.escaped = true;
                } else if ch == open_quote {
                    self.quote = None;
                }
                continue;
            }
            if matches!(ch, '"' | '\'') {
                self.quote = Some(ch);
                self.offset += ch_len;
                continue;
            }
            if !elixir_ident_char(ch) {
                self.offset += ch_len;
                continue;
            }
            let start = self.offset;
            let mut end = self.offset + ch_len;
            for (relative_idx, next) in chars {
                if !elixir_ident_char(next) {
                    break;
                }
                end = self.offset + relative_idx + next.len_utf8();
            }
            self.offset = end;
            return Some((&self.text[start..end], start, end));
        }
        None
    }
}

fn collect_elixir_branch_value_names(text: &str, out: &mut Vec<String>) {
    let mut scanner = ElixirKeywordScanner::new(text);
    while let Some((word, _, _)) = scanner.next_word() {
        if elixir_variable_name(word) && !out.iter().any(|existing| existing == word) {
            out.push(word.to_string());
        }
    }
}

fn find_matching_elixir_delim(text: &str, open_idx: usize, open: char, close: char) -> Option<usize> {
    if !text.is_char_boundary(open_idx) || !text[open_idx..].starts_with(open) {
        return None;
    }
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices().skip_while(|(idx, _)| *idx < open_idx) {
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
        if ch == open {
            depth = depth.saturating_add(1);
        } else if ch == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn split_elixir_top_level_args(text: &str) -> Vec<String> {
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
        if matches!(ch, '"' | '\'') {
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

/// Extract `alias`, `import`, `require`, `use` directives from an Elixir
/// tree into the canonical `ImportSpec` shape.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Elixir's `alias`, `import`, `require`, `use` are all macro calls —
    // `call` nodes whose target is the corresponding identifier and whose
    // first argument is the module alias. `alias MyApp.Foo, as: F` adds
    // the alias-rename via a keywords-pair child.
    for call_node in collect_kinds(tree, &["call"]) {
        let Some(target_node) = call_node.child_by_field_name("target") else {
            continue;
        };
        let target_text = node_text(&target_node, src);
        // Filter to the four directive macros — every other call slips
        // through unchanged.
        if !matches!(target_text, "alias" | "import" | "require" | "use") {
            continue;
        }
        let Some(args_node) = call_node
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call_node, "arguments"))
        else {
            continue;
        };
        // First positional arg must be an `alias` (Elixir's name for a
        // module identifier like `MyApp.Foo`). Anything else is unsupported
        // (e.g. `import :erlang_module` atom form).
        let mut args_cursor = args_node.walk();
        let mut named_args = args_node.named_children(&mut args_cursor);
        let module_node = match named_args.next() {
            Some(arg) if arg.kind() == "alias" => arg,
            _ => continue,
        };
        let module = node_text(&module_node, src).to_string();
        // `as: F` rename appears as a keyword list: `keywords > pair { key, value }`.
        let explicit_alias = first_named_child_of_kind(&args_node, "keywords")
            .and_then(|keywords| first_named_child_of_kind(&keywords, "pair"))
            .and_then(|pair| {
                let key_node = pair.child_by_field_name("key")?;
                let key_text = node_text(&key_node, src).trim().trim_end_matches(':');
                if key_text == "as" {
                    pair.child_by_field_name("value")
                        .map(|value_node| node_text(&value_node, src).to_string())
                } else {
                    None
                }
            });
        // Elixir's `alias MyApp.AuthService` (no `as:` rename) binds
        // the leaf segment as the local name — `AuthService` becomes
        // a path head usable as `AuthService.run(x)`. When no
        // explicit `as:` is provided, mirror Elixir's binding rule
        // so the resolver knows `AuthService` resolves into the
        // workspace's `MyApp.AuthService` module.
        let alias = explicit_alias.or_else(|| match target_text {
            "alias" => module
                .rsplit('.')
                .next()
                .map(str::trim)
                .filter(|leaf| !leaf.is_empty())
                .map(str::to_string),
            _ => None,
        });
        imports.push(ImportSpec {
            span: span_of(file, &call_node),
            module: module.clone(),
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if target_text == "import" {
            imports.push(ImportSpec {
                span: span_of(file, &call_node),
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

/// Elixir parses value-field syntax (`map.field`, with no argument list) as
/// a `call` node whose target is `dot`. Classify it from the CST shape so the
/// IDG sees a field projection rather than an unresolved receiver method.
fn elixir_value_field_nodes<'tree>(call_node: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    if call_node.kind() != "call"
        || call_node.child_by_field_name("arguments").is_some()
        || first_named_child_of_kind(&call_node, "arguments").is_some()
    {
        return None;
    }
    let target = call_node.child_by_field_name("target")?;
    if target.kind() != "dot" {
        return None;
    }
    let mut cursor = target.walk();
    let children = target.named_children(&mut cursor).collect::<Vec<_>>();
    let receiver = target
        .child_by_field_name("left")
        .or_else(|| children.first().copied())?;
    let field = target
        .child_by_field_name("right")
        .or_else(|| children.last().copied())?;
    let receiver_is_value = receiver.kind() == "identifier"
        || (receiver.kind() == "call" && elixir_value_field_nodes(receiver).is_some());
    (receiver_is_value && field.kind() == "identifier").then_some((receiver, field))
}

fn collect_elixir_value_field_access_spans(tree: &Tree, file: FileId) -> Vec<bonsai_common::Span> {
    collect_kinds(tree, &["call"])
        .into_iter()
        .filter(|call| elixir_value_field_nodes(*call).is_some())
        .map(|call| span_of(file, &call))
        .collect()
}

/// Surface every syntax-proven value-field access as a read reference. Rule
/// matching decides which field names matter; the adapter does not carry a
/// framework-specific field-name table.
fn synthesize_elixir_value_field_reads(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    let mut refs = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        let Some((_, field_node)) = elixir_value_field_nodes(call_node) else {
            continue;
        };
        let name = node_text(&field_node, src).trim();
        if name.is_empty() {
            continue;
        }
        refs.push(Ref {
            span: span_of(file, &field_node),
            name: name.to_string(),
            kind: RefKind::Read,
            scope: None,
            resolved: None,
        });
    }
    refs
}

fn remove_elixir_value_field_access_calls(
    events: &mut Vec<FlowEvent>,
    field_access_spans: &[bonsai_common::Span],
) {
    let original = std::mem::take(events);
    for mut event in original {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                remove_elixir_value_field_access_calls(then_events, field_access_spans);
                remove_elixir_value_field_access_calls(else_events, field_access_spans);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                remove_elixir_value_field_access_calls(body, field_access_spans);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                remove_elixir_value_field_access_calls(body, field_access_spans);
                remove_elixir_value_field_access_calls(catch_events, field_access_spans);
                remove_elixir_value_field_access_calls(finally_events, field_access_spans);
            }
            _ => {}
        }
        let is_value_field_call = matches!(
            &event,
            FlowEvent::Call { span, args, .. }
                if args.is_empty()
                    && field_access_spans.iter().any(|field_span| {
                        field_span.file == span.file
                            && field_span.start < span.end
                            && span.start < field_span.end
                    })
        );
        if !is_value_field_call {
            events.push(event);
        }
    }
}

fn call_target_text(call_node: &Node<'_>, src: &[u8]) -> Option<String> {
    call_node
        .child_by_field_name("target")
        .or_else(|| {
            let mut cursor = call_node.walk();
            let first = call_node.named_children(&mut cursor).next();
            first
        })
        .map(|target| node_text(&target, src).trim().to_string())
}

/// Find every `defp` call site in the tree and return its byte span.
/// Adapter uses these to mark matching decls as Visibility::Module
/// (Elixir's module-private visibility).
fn collect_elixir_defp_spans(tree: &tree_sitter::Tree, src: &[u8]) -> Vec<(u64, u64)> {
    let mut defp_spans = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        let field_target = call_node.child_by_field_name("target");
        // Prefer the `target:` field; older grammar revisions don't expose
        // it, so fall back to the first named child.
        let target_node = match field_target {
            Some(target) => target,
            None => {
                let mut call_cursor = call_node.walk();
                let first_named = call_node.named_children(&mut call_cursor).next();
                match first_named {
                    Some(first_child) => first_child,
                    None => continue,
                }
            }
        };
        let target_text = node_text(&target_node, src).trim();
        if target_text == "defp" {
            defp_spans.push((
                u64::try_from(call_node.start_byte()).unwrap_or(u64::MAX),
                u64::try_from(call_node.end_byte()).unwrap_or(u64::MAX),
            ));
        }
    }
    defp_spans
}

#[cfg(test)]
mod tests;
