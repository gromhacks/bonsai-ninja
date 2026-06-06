//! Rust language adapter.

use bonsai_common::FileId;
use bonsai_lang_api::{
    collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, CapabilityLevel, DeclIndex, FieldWrite, FlowEvent, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    TypeAliasVocabulary, Visibility,
};

const RUST_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_item"],
    param_kinds: &["parameter"],
    name_field: "pattern",
    type_field: "type",
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("rust");
const PACK_NAME: &str = "rust";

/// Rust lifecycle transitions: `drop` and ownership-transfer calls.
const RUST_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
    bonsai_lang_api::LifecycleTransition {
        call_match: "drop",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "std::mem::drop",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "mem::drop",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Box::from_raw",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Box::into_raw",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "mem::replace",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "mem::take",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "std::mem::replace",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "std::mem::take",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "ptr::drop_in_place",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "std::ptr::drop_in_place",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "ManuallyDrop::drop",
        transition: "freed",
        arg_index: 0,
    },
];

const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &["function_item"],
    class_kinds: &["struct_item", "enum_item", "trait_item", "union_item"],
    method_kinds: &[],
    method_context_kinds: &["impl_item", "trait_item"],
    constructor_method_kinds: &[],
    constructor_names: &["new"],
    // `if_expression` is the canonical conditional. `match_expression`
    // joins it so each arm's pattern bindings (e.g. `Some(v) => sink(v)`)
    // are emitted as Assigns scoped to the arm body. Without this the
    // bound name `v` is invisible to the taint engine and full-match
    // arm flows are lost (audit task #132). `if_let_expression` is the
    // sugar form covered by the same binding extraction path.
    if_kinds: &["if_expression", "match_expression", "if_let_expression"],
    for_kinds: &["for_expression"],
    foreach_kinds: &[],
    while_kinds: &["while_expression"],
    do_kinds: &[],
    // Rust's unconditional `loop { }` has no condition or init/update —
    // map to `LoopKind::Loop` rather than misclassifying as DoWhile.
    loop_kinds: &["loop_expression"],
    call_kinds: &["call_expression", "macro_invocation"],
    assignment_kinds: &[
        "assignment_expression",
        "compound_assignment_expr",
        "let_declaration",
    ],
    return_kinds: &["return_expression"],
    throw_kinds: &[],
    lambda_kinds: &["closure_expression"],
    // Constructs beyond the core-flow set: Rust try expressions use `?`
    // postfix rather than a named kind, so the try set is empty. Break /
    // continue / await / yield rely on the grammar's default node names
    // (`break_expression`, etc.) already in the generic handler.
    try_kinds: &[],
    catch_kinds: &[],
    finally_kinds: &[],
    break_kinds: &[],
    continue_kinds: &[],
    yield_kinds: &["yield_expression"],
    await_kinds: &["await_expression"],
    defer_kinds: &[],
    using_kinds: &[],
    method_receiver_param_index: Some(0),
    implicit_receiver_names: &["self"],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: true,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct RustAdapter;

impl RustAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for RustAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Rust"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["rs"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            modules: CapabilityLevel::Partial,
            generics: CapabilityLevel::Partial,
            macros: CapabilityLevel::Partial,
            dynamic_dispatch: CapabilityLevel::Partial,
            exceptions: CapabilityLevel::Unsupported,
            // Async/await: the adapter wraps the body of detached
            // futures (`tokio::spawn`, `async_std::task::spawn`,
            // `std::thread::spawn`) in a `Defer` event so its taint
            // effects don't propagate to the caller's continuation
            // state. The spawned future runs concurrently; from the
            // caller's perspective, taint flowing into its body
            // can't reach a sequential post-spawn statement (that's
            // a happens-before guarantee Rust's type system gives
            // for free with `'static + Send` futures).
            async_await: CapabilityLevel::Exact,
            coroutines: CapabilityLevel::Unsupported,
            reflection: CapabilityLevel::Unsupported,
            ffi: CapabilityLevel::Partial,
            pattern_matching: CapabilityLevel::Exact,
            receiver_types: CapabilityLevel::Partial,
            module_export_aliases: &[],
            // Rust has no constructor keyword; the idiomatic
            // associated function is `new`. The cross-language
            // fallback also accepts `new`, but declaring it here
            // narrows other-language entries (`__init__`,
            // `__construct`, `init`) so a same-named Rust method
            // isn't mis-recognised as a constructor.
            constructor_method_names: &["new"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["self"],
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `fn f() -> T {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            let arm_spans = collect_rust_match_arm_spans(&tree, src, file);
            let spawn_body_spans = collect_rust_spawn_body_spans(&tree, src, file);
            let struct_literal_field_assigns = collect_rust_struct_literal_field_assigns(&tree, file, src);
            for decl in &mut idx.defs {
                enrich_rust_struct_literal_field_assigns(
                    &mut decl.flow_events,
                    &struct_literal_field_assigns,
                );
                bonsai_lang_api::kit::split_match_arms_in_branch_events(&mut decl.flow_events, &arm_spans);
                isolate_rust_spawn_bodies(&mut decl.flow_events, &spawn_body_spans);
                enrich_rust_format_macro_operands(&mut decl.flow_events);
                enrich_rust_tail_return_sources(&mut decl.flow_events, &decl.params);
                enrich_rust_constructor_field_writes(decl);
            }
        }
        // Rust module_path: relative file path under workspace root,
        // dropping `src/` and `lib.rs`/`mod.rs`/`<name>.rs` to produce
        // a `crate::mod::sub`-shaped path. Falls back to file-stem.
        let segments = ctx
            .workspace_relative_path(file)
            .map(|path| rust_module_segments(&path))
            .unwrap_or_default();
        if !segments.is_empty() {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        // Rust visibility from `pub`, `pub(crate)`, `pub(super)`,
        // `pub(in path)`. Absence = private (file/mod-scoped).
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let visibility_by_span = collect_rust_visibility(tree.root_node(), file, src);
            let alias_map = collect_param_type_aliases(&tree, file, src, &RUST_TYPE_ALIASES);
            let tuple_struct_bases = collect_rust_tuple_struct_bases(&tree, file, src);
            let tuple_struct_field_aliases = collect_rust_tuple_struct_field_aliases(&tree, src);
            let impl_method_parents = collect_rust_impl_method_parents(&tree, file, src);
            let impl_method_parent_symbols = impl_method_parents
                .iter()
                .filter_map(|(span, type_name)| {
                    idx.defs
                        .iter()
                        .find(|candidate| {
                            candidate.name == *type_name
                                && matches!(
                                    candidate.kind,
                                    bonsai_lang_api::DeclKind::Class
                                        | bonsai_lang_api::DeclKind::Struct
                                        | bonsai_lang_api::DeclKind::Trait
                                        | bonsai_lang_api::DeclKind::Interface
                                )
                        })
                        .map(|parent| (*span, parent.symbol))
                })
                .collect::<Vec<_>>();
            for decl in &mut idx.defs {
                if let Some(vis) = visibility_by_span.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(bases) = tuple_struct_bases.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
                if decl.parent.is_none() {
                    if let Some(parent_symbol) = impl_method_parent_symbols
                        .iter()
                        .find_map(|(span, parent_symbol)| (*span == decl.span).then_some(*parent_symbol))
                    {
                        decl.parent = Some(parent_symbol);
                    }
                }
            }
            apply_rust_tuple_struct_field_aliases(&mut idx, &tuple_struct_field_aliases);
            enrich_rust_self_tuple_constructor_returns(&mut idx);
        }
        // Append `FlowEvent::Lifecycle` for recognised Rust
        // resource transitions (`drop`, `Box::from_raw`,
        // `mem::replace`, `mem::take`).
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, RUST_LIFECYCLE_TRANSITIONS);
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
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

fn enrich_rust_format_macro_operands(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    for capture in rust_format_named_captures(&arg.value_text) {
                        if !arg.source_names.iter().any(|existing| existing == &capture) {
                            arg.source_names.push(capture);
                        }
                    }
                }
            }
            FlowEvent::Assign {
                source_names,
                source_call_args,
                ..
            } => {
                for arg in source_call_args {
                    for capture in rust_format_named_captures(arg) {
                        if !source_names.iter().any(|existing| existing == &capture) {
                            source_names.push(capture);
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_format_macro_operands(then_events);
                enrich_rust_format_macro_operands(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_format_macro_operands(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_format_macro_operands(body);
                enrich_rust_format_macro_operands(catch_events);
                enrich_rust_format_macro_operands(finally_events);
            }
            _ => {}
        }
    }
}

fn enrich_rust_tail_return_sources(events: &mut [FlowEvent], params: &[String]) {
    for event in events {
        match event {
            FlowEvent::Return {
                value_name,
                value_text,
                ..
            } => {
                if value_name.is_none() {
                    if let Some(text) = value_text.as_deref() {
                        *value_name = rust_tail_return_source_name(text, params);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_tail_return_sources(then_events, params);
                enrich_rust_tail_return_sources(else_events, params);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_tail_return_sources(body, params);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_tail_return_sources(body, params);
                enrich_rust_tail_return_sources(catch_events, params);
                enrich_rust_tail_return_sources(finally_events, params);
            }
            _ => {}
        }
    }
}

fn rust_tail_return_source_name(text: &str, params: &[String]) -> Option<String> {
    let expr = strip_rust_reference_prefix(text.trim());
    if rust_self_field_place(expr) {
        return Some(expr.to_string());
    }
    rust_single_param_struct_literal_source(expr, params)
}

fn enrich_rust_constructor_field_writes(decl: &mut bonsai_lang_api::Decl) {
    if decl.name != "new" || decl.params.is_empty() {
        return;
    }
    for event in &decl.flow_events {
        let FlowEvent::Return {
            span,
            value_text: Some(value_text),
            ..
        } = event
        else {
            continue;
        };
        for (field, value) in rust_struct_literal_field_values(value_text) {
            let Some(source_idx) = decl.params.iter().position(|param| param == &value) else {
                continue;
            };
            decl.receiver_field_writes.push(FieldWrite {
                span: *span,
                target: format!("self.{field}"),
                source_param_indices: vec![source_idx],
            });
        }
    }
    decl.receiver_field_writes
        .sort_by_key(|write| (write.span.start, write.target.clone()));
    decl.receiver_field_writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
}

#[derive(Clone, Debug)]
struct RustConstructorFieldSource {
    target_suffix: String,
    source_param_index: usize,
}

fn enrich_rust_self_tuple_constructor_returns(idx: &mut DeclIndex) {
    let class_name_by_symbol = idx
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Class
                    | bonsai_lang_api::DeclKind::Struct
                    | bonsai_lang_api::DeclKind::Trait
                    | bonsai_lang_api::DeclKind::Interface
            )
        })
        .map(|decl| (decl.symbol, decl.name.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let mut constructor_fields: std::collections::HashMap<(String, String), Vec<RustConstructorFieldSource>> =
        std::collections::HashMap::new();
    for decl in &idx.defs {
        let Some(parent) = decl.parent.and_then(|symbol| class_name_by_symbol.get(&symbol)) else {
            continue;
        };
        for write in &decl.receiver_field_writes {
            let Some(target_suffix) = write.target.trim().strip_prefix("self.") else {
                continue;
            };
            if target_suffix.is_empty() {
                continue;
            }
            for source_param_index in &write.source_param_indices {
                constructor_fields
                    .entry((parent.clone(), decl.name.clone()))
                    .or_default()
                    .push(RustConstructorFieldSource {
                        target_suffix: target_suffix.to_string(),
                        source_param_index: *source_param_index,
                    });
            }
        }
    }
    if constructor_fields.is_empty() {
        return;
    }

    for decl in &mut idx.defs {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        let returns_self = decl.return_type.as_deref().is_some_and(|ty| ty.trim() == "Self");
        let mut writes = Vec::new();
        collect_rust_self_tuple_constructor_return_writes(
            &decl.flow_events,
            &decl.params,
            returns_self,
            &constructor_fields,
            &mut writes,
        );
        if writes.is_empty() {
            continue;
        }
        decl.receiver_field_writes.extend(writes);
        decl.receiver_field_writes
            .sort_by_key(|write| (write.span.start, write.target.clone()));
        decl.receiver_field_writes.dedup_by(|a, b| {
            a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
        });
        decl.kind = bonsai_lang_api::DeclKind::Constructor;
    }
}

fn collect_rust_self_tuple_constructor_return_writes(
    events: &[FlowEvent],
    params: &[String],
    returns_self: bool,
    constructor_fields: &std::collections::HashMap<(String, String), Vec<RustConstructorFieldSource>>,
    out: &mut Vec<FieldWrite>,
) {
    for event in events {
        match event {
            FlowEvent::Return {
                span,
                value_text: Some(value_text),
                ..
            } => {
                if !returns_self && !value_text.trim_start().starts_with("Self(") {
                    continue;
                }
                let Some(args) = rust_self_tuple_constructor_args(value_text) else {
                    continue;
                };
                for (tuple_idx, arg) in args.iter().enumerate() {
                    if let Some((owner, ctor, ctor_args)) = rust_constructor_call_parts(arg) {
                        if let Some(fields) = constructor_fields.get(&(owner, ctor)) {
                            for field in fields {
                                let Some(source_arg) = ctor_args.get(field.source_param_index) else {
                                    continue;
                                };
                                let Some(source_param_index) =
                                    rust_param_index_for_bare_arg(source_arg, params)
                                else {
                                    continue;
                                };
                                out.push(FieldWrite {
                                    span: *span,
                                    target: format!("self.{tuple_idx}.{}", field.target_suffix),
                                    source_param_indices: vec![source_param_index],
                                });
                            }
                        }
                    } else if let Some(source_param_index) = rust_param_index_for_bare_arg(arg, params) {
                        out.push(FieldWrite {
                            span: *span,
                            target: format!("self.{tuple_idx}"),
                            source_param_indices: vec![source_param_index],
                        });
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_rust_self_tuple_constructor_return_writes(
                    then_events,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
                collect_rust_self_tuple_constructor_return_writes(
                    else_events,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_rust_self_tuple_constructor_return_writes(
                    body,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_rust_self_tuple_constructor_return_writes(
                    body,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
                collect_rust_self_tuple_constructor_return_writes(
                    catch_events,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
                collect_rust_self_tuple_constructor_return_writes(
                    finally_events,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn rust_param_index_for_bare_arg(arg: &str, params: &[String]) -> Option<usize> {
    let arg = strip_rust_reference_prefix(arg.trim());
    if !rust_bare_identifier(arg) {
        return None;
    }
    params.iter().position(|param| param == arg)
}

fn rust_self_tuple_constructor_args(text: &str) -> Option<Vec<String>> {
    let expr = strip_rust_reference_prefix(text.trim());
    let inner = rust_call_inner_for_prefix(expr, "Self")?;
    Some(
        split_top_level_commas(inner)
            .into_iter()
            .map(str::trim)
            .filter(|arg| !arg.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn rust_constructor_call_parts(text: &str) -> Option<(String, String, Vec<String>)> {
    let expr = strip_rust_reference_prefix(text.trim());
    let open = expr.find('(')?;
    let callee = expr[..open].trim();
    let (owner, ctor) = callee.rsplit_once("::")?;
    let owner = rust_type_tail(owner)?;
    if !rust_bare_identifier(ctor) {
        return None;
    }
    let inner = rust_call_inner_for_prefix(expr, callee)?;
    let args = split_top_level_commas(inner)
        .into_iter()
        .map(str::trim)
        .filter(|arg| !arg.is_empty())
        .map(str::to_string)
        .collect();
    Some((owner, ctor.to_string(), args))
}

fn rust_call_inner_for_prefix<'a>(expr: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = expr.strip_prefix(prefix)?.trim_start();
    let rest = rest.strip_prefix('(')?;
    let close = matching_call_close(rest)?;
    if !rest[close + 1..].trim().is_empty() {
        return None;
    }
    Some(&rest[..close])
}

fn matching_call_close(text_after_open: &str) -> Option<usize> {
    let mut depth = 1i32;
    let mut quote: Option<char> = None;
    let mut escape = false;
    for (idx, ch) in text_after_open.char_indices() {
        if let Some(q) = quote {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' | '{' | '<' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            ']' | '}' | '>' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn collect_rust_struct_literal_field_assigns(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<FlowEvent>> {
    let mut out = std::collections::HashMap::new();
    for node in collect_kinds(tree, &["let_declaration", "assignment_expression"]) {
        let Some(target_node) = node
            .child_by_field_name("pattern")
            .or_else(|| node.child_by_field_name("left"))
            .or_else(|| node.child_by_field_name("target"))
        else {
            continue;
        };
        let target = node_text(&target_node, src).trim();
        if !rust_bare_identifier(target) {
            continue;
        }
        let Some(value_node) = node
            .child_by_field_name("value")
            .or_else(|| node.child_by_field_name("right"))
        else {
            continue;
        };
        let target_type = node
            .child_by_field_name("type")
            .and_then(|ty| rust_type_tail(node_text(&ty, src)));
        let struct_nodes = rust_struct_literal_nodes_for_assignment(value_node, target_type.as_deref(), src);
        if struct_nodes.is_empty() {
            continue;
        }
        let mut events = Vec::new();
        for struct_node in struct_nodes {
            collect_rust_struct_literal_field_events(target, struct_node, file, src, &mut events);
        }
        if !events.is_empty() {
            events.sort_by_key(|event| event_span_start(event));
            events.dedup_by(|a, b| flow_event_assign_key(a) == flow_event_assign_key(b));
            out.insert(span_of(file, &node), events);
        }
    }
    out
}

fn enrich_rust_struct_literal_field_assigns(
    events: &mut Vec<FlowEvent>,
    field_assigns: &std::collections::HashMap<bonsai_common::Span, Vec<FlowEvent>>,
) {
    let mut enriched = Vec::with_capacity(events.len());
    for mut event in std::mem::take(events) {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_struct_literal_field_assigns(then_events, field_assigns);
                enrich_rust_struct_literal_field_assigns(else_events, field_assigns);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_struct_literal_field_assigns(body, field_assigns);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_struct_literal_field_assigns(body, field_assigns);
                enrich_rust_struct_literal_field_assigns(catch_events, field_assigns);
                enrich_rust_struct_literal_field_assigns(finally_events, field_assigns);
            }
            _ => {}
        }
        let extra = match &event {
            FlowEvent::Assign { span, .. } => field_assigns.get(span).cloned(),
            _ => None,
        };
        enriched.push(event);
        if let Some(extra) = extra {
            enriched.extend(extra);
        }
    }
    *events = enriched;
}

fn rust_struct_literal_nodes_for_assignment<'tree>(
    value_node: Node<'tree>,
    target_type: Option<&str>,
    src: &[u8],
) -> Vec<Node<'tree>> {
    if value_node.kind() == "struct_expression" {
        return vec![value_node];
    }
    let Some(target_type) = target_type else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack = vec![value_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "struct_expression"
            && rust_struct_expression_name(node, src).as_deref() == Some(target_type)
        {
            out.push(node);
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn collect_rust_struct_literal_field_events(
    target: &str,
    struct_node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<FlowEvent>,
) {
    let Some(body) = first_named_child_of_kind_local(struct_node, "field_initializer_list") else {
        return;
    };
    let mut cursor = body.walk();
    for field_node in body.named_children(&mut cursor) {
        match field_node.kind() {
            "field_initializer" => {
                let Some(field) = field_node.child_by_field_name("field") else {
                    continue;
                };
                let Some(value) = field_node.child_by_field_name("value") else {
                    continue;
                };
                let field_name = node_text(&field, src).trim();
                if !rust_bare_identifier(field_name) {
                    continue;
                }
                let value_text = node_text(&value, src).trim();
                let source_names = rust_value_source_names(value_text);
                if source_names.is_empty() {
                    continue;
                }
                out.push(FlowEvent::Assign {
                    span: span_of(file, &field_node),
                    target: format!("{target}.{field_name}"),
                    source_name: rust_bare_identifier(value_text).then(|| value_text.to_string()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names,
                    declares_new_binding: false,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                });
            }
            "shorthand_field_initializer" => {
                let value_text = node_text(&field_node, src).trim();
                if !rust_bare_identifier(value_text) {
                    continue;
                }
                out.push(FlowEvent::Assign {
                    span: span_of(file, &field_node),
                    target: format!("{target}.{value_text}"),
                    source_name: Some(value_text.to_string()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: vec![value_text.to_string()],
                    declares_new_binding: false,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                });
            }
            _ => {}
        }
    }
}

fn rust_struct_expression_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("type"))
        .or_else(|| first_named_child_of_kind_local(node, "type_identifier"))?;
    rust_type_tail(node_text(&name, src))
}

fn rust_type_tail(text: &str) -> Option<String> {
    let tail = text
        .trim()
        .trim_matches('&')
        .trim()
        .rsplit("::")
        .next()
        .unwrap_or(text)
        .trim();
    (rust_bare_identifier(tail)).then(|| tail.to_string())
}

fn rust_value_source_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in rust_identifier_chains_outside_strings(text) {
        push_rust_source_token(&mut out, &token);
    }
    out.sort();
    out.dedup();
    out
}

fn rust_identifier_chains_outside_strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    let mut in_string: Option<char> = None;
    let mut escape = false;
    while let Some(ch) = chars.next() {
        if let Some(quote) = in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                push_rust_identifier_chain(&mut out, &mut current);
                in_string = Some(ch);
            }
            ':' if chars.peek() == Some(&':') => {
                current.push_str("::");
                let _ = chars.next();
            }
            '.' => current.push('.'),
            '_' | 'a'..='z' | 'A'..='Z' | '0'..='9' => current.push(ch),
            _ => push_rust_identifier_chain(&mut out, &mut current),
        }
    }
    push_rust_identifier_chain(&mut out, &mut current);
    out
}

fn push_rust_identifier_chain(out: &mut Vec<String>, current: &mut String) {
    let token = current.trim_matches('.').trim_matches(':').trim();
    if !token.is_empty()
        && token
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        out.push(token.to_string());
    }
    current.clear();
}

fn push_rust_source_token(out: &mut Vec<String>, token: &str) {
    let token = token.trim_end_matches('!');
    if token.is_empty() {
        return;
    }
    out.push(token.to_string());
    for sep in [".", "::"] {
        if token.contains(sep) {
            let parts = token.split(sep).collect::<Vec<_>>();
            for split in 1..parts.len() {
                let prefix = parts[..split].join(sep);
                if !prefix.is_empty() {
                    out.push(prefix);
                }
            }
        }
    }
}

fn first_named_child_of_kind_local<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let found = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == kind);
    found
}

fn event_span_start(event: &FlowEvent) -> u64 {
    match event {
        FlowEvent::Assign { span, .. }
        | FlowEvent::Call { span, .. }
        | FlowEvent::Return { span, .. }
        | FlowEvent::Throw { span, .. }
        | FlowEvent::Branch { span, .. }
        | FlowEvent::Loop { span, .. }
        | FlowEvent::Break { span, .. }
        | FlowEvent::Continue { span, .. }
        | FlowEvent::Yield { span, .. }
        | FlowEvent::Await { span, .. }
        | FlowEvent::Defer { span, .. }
        | FlowEvent::Using { span, .. }
        | FlowEvent::Try { span, .. }
        | FlowEvent::Lifecycle { span, .. } => span.start,
    }
}

fn flow_event_assign_key(event: &FlowEvent) -> Option<(bonsai_common::Span, String)> {
    match event {
        FlowEvent::Assign { span, target, .. } => Some((*span, target.clone())),
        _ => None,
    }
}

fn rust_struct_literal_field_values(expr: &str) -> Vec<(String, String)> {
    let expr = strip_rust_reference_prefix(expr.trim());
    let Some(open) = expr.find('{') else {
        return Vec::new();
    };
    let Some(close) = expr.rfind('}') else {
        return Vec::new();
    };
    if close <= open || !expr[close + 1..].trim().is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for field in expr[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
    {
        let (target, value) = field
            .split_once(':')
            .map(|(target, value)| (target.trim(), value.trim()))
            .unwrap_or((field, field));
        if rust_bare_identifier(target) && rust_bare_identifier(value) {
            out.push((target.to_string(), value.to_string()));
        }
    }
    out
}

fn strip_rust_reference_prefix(mut expr: &str) -> &str {
    loop {
        let trimmed = expr.trim_start();
        if let Some(rest) = trimmed.strip_prefix('&') {
            let rest = rest.trim_start();
            expr = rest.strip_prefix("mut ").unwrap_or(rest);
            continue;
        }
        return trimmed;
    }
}

fn rust_self_field_place(expr: &str) -> bool {
    let Some(rest) = expr.strip_prefix("self.") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .chars()
            .all(|ch| ch == '.' || ch == '_' || ch.is_ascii_alphanumeric())
}

fn rust_single_param_struct_literal_source(expr: &str, params: &[String]) -> Option<String> {
    let open = expr.find('{')?;
    if !expr[..open]
        .trim()
        .chars()
        .all(|ch| ch == ':' || ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    let close = expr.rfind('}')?;
    if close <= open || !expr[close + 1..].trim().is_empty() {
        return None;
    }
    let fields = &expr[open + 1..close];
    let mut sources = Vec::new();
    for field in fields.split(',').map(str::trim).filter(|field| !field.is_empty()) {
        let source = field
            .split_once(':')
            .map(|(_, value)| value.trim())
            .unwrap_or(field);
        if rust_bare_identifier(source) && params.iter().any(|param| param == source) {
            sources.push(source.to_string());
        }
    }
    sources.sort();
    sources.dedup();
    (sources.len() == 1).then(|| sources.remove(0))
}

fn rust_bare_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn rust_format_named_captures(text: &str) -> Vec<String> {
    let trimmed = text.trim_start();
    let Some(after_macro) = trimmed
        .strip_prefix("format!")
        .or_else(|| trimmed.strip_prefix("format_args!"))
    else {
        return Vec::new();
    };
    let Some(open) = after_macro.find('(') else {
        return Vec::new();
    };
    let args = &after_macro[open + 1..];
    let Some((literal, _)) = first_rust_string_literal(args) else {
        return Vec::new();
    };
    rust_format_named_captures_from_literal(literal)
}

fn first_rust_string_literal(text: &str) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'"' {
            let start = idx + 1;
            idx += 1;
            let mut escaped = false;
            while idx < bytes.len() {
                let byte = bytes[idx];
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    return Some((&text[start..idx], idx + 1));
                }
                idx += 1;
            }
            return None;
        }
        idx += 1;
    }
    None
}

fn rust_format_named_captures_from_literal(literal: &str) -> Vec<String> {
    let bytes = literal.as_bytes();
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] != b'{' {
            idx += 1;
            continue;
        }
        if bytes.get(idx + 1) == Some(&b'{') {
            idx += 2;
            continue;
        }
        let start = idx + 1;
        if start >= bytes.len() || !is_rust_ident_start(bytes[start]) {
            idx += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() && is_rust_ident_continue(bytes[end]) {
            end += 1;
        }
        let name = &literal[start..end];
        if !out.iter().any(|existing| existing == name) {
            out.push(name.to_string());
        }
        idx = end;
    }
    out
}

fn is_rust_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_rust_ident_continue(byte: u8) -> bool {
    is_rust_ident_start(byte) || byte.is_ascii_digit()
}

/// Per-arm body spans for every `match_expression` in the file.
/// Mirrors the Scala/Swift collectors; passed to the kit's
/// `split_match_arms_in_branch_events` to peel the kit-emitted flat
/// Branch into per-arm forks.
fn collect_rust_match_arm_spans(tree: &Tree, _src: &[u8], file: FileId) -> Vec<Vec<bonsai_common::Span>> {
    let mut out: Vec<Vec<bonsai_common::Span>> = Vec::new();
    for match_node in collect_kinds(tree, &["match_expression"]) {
        let mut arm_body_spans: Vec<bonsai_common::Span> = Vec::new();
        let body = match_node
            .child_by_field_name("body")
            .or_else(|| match_node.child_by_field_name("block"));
        let Some(body) = body else { continue };
        let mut bcur = body.walk();
        for arm in body.named_children(&mut bcur) {
            if !matches!(
                arm.kind(),
                "match_arm" | "match_block_arm" | "match_expression_arm"
            ) {
                continue;
            }
            // The arm's body is in the `value` field (or the last
            // named child for grammars without a labeled value field).
            let arm_body = arm
                .child_by_field_name("value")
                .or_else(|| arm.child_by_field_name("body"));
            if let Some(body_node) = arm_body {
                arm_body_spans.push(span_of(file, &body_node));
            }
        }
        if !arm_body_spans.is_empty() {
            out.push(arm_body_spans);
        }
    }
    out
}

/// Spans of `async_block` / closure arguments to detached-future
/// spawn calls (`tokio::spawn`, `async_std::task::spawn`,
/// `std::thread::spawn`). Events whose span falls inside any of
/// these get wrapped in a `Defer` so the engine isolates them from
/// the caller's continuation state.
fn collect_rust_spawn_body_spans(tree: &Tree, src: &[u8], file: FileId) -> Vec<bonsai_common::Span> {
    let mut spawn_body_spans = Vec::new();
    for call_node in collect_kinds(tree, &["call_expression"]) {
        // Only the `name` of the callee — `tokio::spawn` / `thread::spawn`
        // / etc. — gates the rewrite. Method calls and unrelated
        // expressions skip outright.
        let Some(callee_node) = call_node.child_by_field_name("function") else {
            continue;
        };
        let callee_path = node_text(&callee_node, src).trim();
        if !is_rust_spawn_callee(callee_path) {
            continue;
        }
        let Some(args_node) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        // The body to isolate is the `async { ... }` or closure
        // argument — that's the future being detached. Plain values
        // passed to spawn (rare; usually a pre-built future) don't
        // need wrapping because their flow_events are already part of
        // the caller's continuation, not a detached body.
        let mut arg_cursor = args_node.walk();
        for arg_node in args_node.named_children(&mut arg_cursor) {
            if matches!(arg_node.kind(), "async_block" | "closure_expression") {
                spawn_body_spans.push(span_of(file, &arg_node));
            }
        }
    }
    spawn_body_spans
}

/// Hardcoded set of Rust APIs that detach a future from the caller's
/// continuation. `block_on` is included because its body genuinely
/// runs to completion before continuing — the caller's post-call
/// state isn't poisoned by intermediate work.
fn is_rust_spawn_callee(callee_path: &str) -> bool {
    matches!(
        callee_path,
        "tokio::spawn"
            | "tokio::task::spawn"
            | "async_std::task::spawn"
            | "std::thread::spawn"
            | "thread::spawn"
            | "smol::spawn"
            | "futures::executor::block_on"
            | "rayon::spawn"
    )
}

/// Walk `events` and, for any event whose span lies inside one of
/// `spawn_body_spans`, wrap that event in a `Defer` so the engine
/// observes it without propagating its state to the post-spawn
/// continuation.
fn isolate_rust_spawn_bodies(
    events: &mut Vec<bonsai_lang_api::FlowEvent>,
    spawn_body_spans: &[bonsai_common::Span],
) {
    use bonsai_lang_api::FlowEvent;
    if spawn_body_spans.is_empty() {
        return;
    }
    let mut new_events: Vec<FlowEvent> = Vec::with_capacity(events.len());
    let mut buffered_spawn: Option<(bonsai_common::Span, Vec<FlowEvent>)> = None;
    for ev in events.drain(..) {
        // Recurse into nested containers first.
        let span = match &ev {
            FlowEvent::Call { span, .. }
            | FlowEvent::Assign { span, .. }
            | FlowEvent::Return { span, .. }
            | FlowEvent::Throw { span, .. }
            | FlowEvent::Branch { span, .. }
            | FlowEvent::Loop { span, .. }
            | FlowEvent::Try { span, .. }
            | FlowEvent::Defer { span, .. }
            | FlowEvent::Using { span, .. }
            | FlowEvent::Yield { span, .. }
            | FlowEvent::Await { span, .. }
            | FlowEvent::Break { span, .. }
            | FlowEvent::Continue { span, .. }
            | FlowEvent::Lifecycle { span, .. } => *span,
        };
        let mut ev = ev;
        match &mut ev {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                isolate_rust_spawn_bodies(then_events, spawn_body_spans);
                isolate_rust_spawn_bodies(else_events, spawn_body_spans);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                isolate_rust_spawn_bodies(body, spawn_body_spans);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                isolate_rust_spawn_bodies(body, spawn_body_spans);
                isolate_rust_spawn_bodies(catch_events, spawn_body_spans);
                isolate_rust_spawn_bodies(finally_events, spawn_body_spans);
            }
            _ => {}
        }
        let inside_spawn = spawn_body_spans
            .iter()
            .find(|s| span.file == s.file && span.start >= s.start && span.end <= s.end);
        let flush = |slot: &mut Option<(bonsai_common::Span, Vec<FlowEvent>)>, out: &mut Vec<FlowEvent>| {
            if let Some((prev_span, prev_buf)) = slot.take() {
                out.push(FlowEvent::Defer {
                    span: prev_span,
                    body: prev_buf,
                });
            }
        };
        match (inside_spawn, &mut buffered_spawn) {
            // Continue accumulating into the current spawn buffer.
            (Some(s), Some((cur_span, buf))) if cur_span == s => {
                buf.push(ev);
            }
            // Switching to a new spawn region — flush old buffer first.
            (Some(s), _) => {
                flush(&mut buffered_spawn, &mut new_events);
                buffered_spawn = Some((*s, vec![ev]));
            }
            // Outside any spawn region — flush any buffered spawn,
            // then emit the event sequentially.
            (None, _) => {
                flush(&mut buffered_spawn, &mut new_events);
                new_events.push(ev);
            }
        }
    }
    if let Some((prev_span, prev_buf)) = buffered_spawn.take() {
        new_events.push(FlowEvent::Defer {
            span: prev_span,
            body: prev_buf,
        });
    }
    *events = new_events;
}

/// Walk the Rust tree and map function/struct/enum/trait/impl spans
/// to their syntactic Visibility:
///
/// - `pub` → Public
/// - `pub(crate)` → Crate
/// - `pub(super)` / `pub(in path)` → Module (treated as parent-scoped)
/// - no `pub` modifier → Private (mod-private; with empty
///   module_path treated as file-private by the resolver)
fn collect_rust_visibility(
    root: Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Visibility> {
    let mut out = std::collections::HashMap::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let is_decl = matches!(
            kind,
            "function_item"
                | "struct_item"
                | "enum_item"
                | "trait_item"
                | "impl_item"
                | "mod_item"
                | "type_item"
        );
        if is_decl {
            out.insert(span_of(file, &node), rust_node_visibility(&node, src));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn rust_node_visibility(node: &Node<'_>, src: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "visibility_modifier" {
            continue;
        }
        let text = node_text(&child, src);
        if text == "pub" {
            return Visibility::Public;
        }
        if text.starts_with("pub(crate") {
            return Visibility::Crate;
        }
        if text.starts_with("pub(super") || text.starts_with("pub(in") {
            return Visibility::Module;
        }
        // `pub(self)` is private to the current module — same as no
        // modifier in practice.
        return Visibility::Private;
    }
    Visibility::Private
}

fn collect_rust_tuple_struct_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, &["struct_item"]) {
        let name = node
            .child_by_field_name("name")
            .map(|n| node_text(&n, src).to_string())
            .unwrap_or_default();
        let text = node_text(&node, src);
        let Some(open) = text.find('(') else {
            continue;
        };
        let Some(close) = text[open + 1..].find(')').map(|idx| open + 1 + idx) else {
            continue;
        };
        if text[..open].contains('{') {
            continue;
        }
        let mut bases = Vec::new();
        for field in text[open + 1..close].split(',') {
            let field = field.trim();
            if field.is_empty() {
                continue;
            }
            let ty = field
                .split(':')
                .next_back()
                .unwrap_or(field)
                .trim()
                .trim_start_matches("pub ")
                .trim();
            let ty = ty
                .split(|ch: char| !(ch == '_' || ch == ':' || ch.is_ascii_alphanumeric()))
                .find(|part| !part.is_empty())
                .unwrap_or("");
            let Some(base) = ty.rsplit("::").next().filter(|base| {
                base.chars()
                    .next()
                    .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
            }) else {
                continue;
            };
            if !bases.iter().any(|existing| existing == base) {
                bases.push(base.to_string());
            }
        }
        if !bases.is_empty() {
            out.push((span_of(file, &node), name, bases));
        }
    }
    out
}

fn collect_rust_tuple_struct_field_aliases(
    tree: &Tree,
    src: &[u8],
) -> Vec<(String, Vec<bonsai_lang_api::TypeAliasBinding>)> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, &["struct_item"]) {
        let name = node
            .child_by_field_name("name")
            .map(|n| node_text(&n, src).to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let text = node_text(&node, src);
        let Some(open) = text.find('(') else {
            continue;
        };
        let Some(close) = text[open + 1..].find(')').map(|idx| open + 1 + idx) else {
            continue;
        };
        if text[..open].contains('{') {
            continue;
        }
        let mut aliases = Vec::new();
        for (idx, field) in text[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|field| !field.is_empty())
            .enumerate()
        {
            let Some(type_name) = rust_tuple_struct_field_type(field) else {
                continue;
            };
            aliases.push(bonsai_lang_api::TypeAliasBinding {
                name: format!("self.{idx}"),
                type_name,
            });
        }
        if !aliases.is_empty() {
            out.push((name, aliases));
        }
    }
    out
}

fn rust_tuple_struct_field_type(field: &str) -> Option<String> {
    let ty = field
        .split(':')
        .next_back()
        .unwrap_or(field)
        .trim()
        .trim_start_matches("pub ")
        .trim();
    let ty = ty
        .split(|ch: char| !(ch == '_' || ch == ':' || ch.is_ascii_alphanumeric()))
        .find(|part| !part.is_empty())
        .unwrap_or("");
    ty.rsplit("::")
        .next()
        .filter(|base| {
            base.chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
        })
        .map(ToString::to_string)
}

fn apply_rust_tuple_struct_field_aliases(
    idx: &mut DeclIndex,
    tuple_struct_field_aliases: &[(String, Vec<bonsai_lang_api::TypeAliasBinding>)],
) {
    if tuple_struct_field_aliases.is_empty() {
        return;
    }
    let aliases_by_class = tuple_struct_field_aliases
        .iter()
        .map(|(name, aliases)| (name.as_str(), aliases))
        .collect::<std::collections::HashMap<_, _>>();
    let class_name_by_symbol = idx
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Class
                    | bonsai_lang_api::DeclKind::Struct
                    | bonsai_lang_api::DeclKind::Trait
                    | bonsai_lang_api::DeclKind::Interface
            )
        })
        .map(|decl| (decl.symbol, decl.name.clone()))
        .collect::<std::collections::HashMap<_, _>>();

    for decl in &mut idx.defs {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        let Some(parent) = decl.parent else { continue };
        let Some(class_name) = class_name_by_symbol.get(&parent) else {
            continue;
        };
        let Some(aliases) = aliases_by_class.get(class_name.as_str()) else {
            continue;
        };
        for alias in *aliases {
            if !decl.type_aliases.contains(alias) {
                decl.type_aliases.push((*alias).clone());
            }
        }
    }
}

fn collect_rust_impl_method_parents(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String)> {
    let functions = collect_kinds(tree, &["function_item"]);
    let mut out = Vec::new();
    for impl_node in collect_kinds(tree, &["impl_item"]) {
        let Some(type_name) = rust_impl_self_type(node_text(&impl_node, src)) else {
            continue;
        };
        let impl_span = span_of(file, &impl_node);
        for function in &functions {
            let fn_span = span_of(file, function);
            if fn_span.start >= impl_span.start && fn_span.end <= impl_span.end {
                out.push((fn_span, type_name.clone()));
            }
        }
    }
    out
}

fn rust_impl_self_type(text: &str) -> Option<String> {
    let header = text.split('{').next()?.trim();
    let rest = header.strip_prefix("impl")?.trim();
    let self_type = if let Some((_, rhs)) = rest.rsplit_once(" for ") {
        rhs.trim()
    } else {
        let mut rest = rest;
        if rest.starts_with('<') {
            if let Some(end) = matching_angle_close(rest) {
                rest = rest[end + 1..].trim();
            }
        }
        rest
    };
    let candidate = self_type
        .split(|ch: char| !(ch == '_' || ch == ':' || ch.is_ascii_alphanumeric()))
        .find(|part| !part.is_empty())?;
    candidate
        .rsplit("::")
        .next()
        .filter(|tail| {
            tail.chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
        })
        .map(str::to_string)
}

fn matching_angle_close(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '<' => depth = depth.saturating_add(1),
            '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, &["mod_item"]) {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let module = node_text(&name_node, src).trim();
        if module.is_empty() {
            continue;
        }
        out.push(ImportSpec {
            span: span_of(file, &node),
            module: module.to_string(),
            alias: Some(module.to_string()),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    for node in collect_kinds(tree, &["use_declaration"]) {
        let text = node_text(&node, src)
            .trim_start_matches("use ")
            .trim_end_matches(';')
            .trim()
            .to_string();
        // Base entry — full use-tree text as the module string so the
        // name is searchable verbatim. Skipped for brace-list imports
        // (`use X::{A, B};`) because the per-member entries emitted
        // below already carry the prefix as module — a redundant row
        // with the literal `{A, B}` string is noise.
        let has_brace_list = text.contains('{');
        if !has_brace_list {
            out.push(ImportSpec {
                span: span_of(file, &node),
                module: text.clone(),
                alias: None,
                is_wildcard: text.ends_with('*'),
                original_name: None,
                scope: ImportScope::Module,
            });
            // Self-binding namespace alias for workspace-internal
            // module imports (`use crate::executor;`, `use self::x;`,
            // `use super::y;`). Without this, calls like
            // `executor::execute(c)` cannot be resolved to the
            // workspace `executor` module — `mod_item` declarations
            // already bind their own name, but plain `use` imports
            // don't, leaving cross-module call edges unresolved.
            //
            // Limited to lowercase leaves (Rust's module convention)
            // so type imports (`use crate::Envelope;`) don't get a
            // bogus namespace alias that would let
            // `Envelope::method` rewrite to a spurious workspace
            // function via the resolver's bare-name fallback.
            if !text.contains(" as ") && !text.ends_with('*') {
                if let Some(leaf) = workspace_use_leaf(text.as_str()) {
                    out.push(ImportSpec {
                        span: span_of(file, &node),
                        module: leaf.to_string(),
                        alias: Some(leaf.to_string()),
                        is_wildcard: false,
                        original_name: None,
                        scope: ImportScope::Module,
                    });
                }
            }
        }
        // Additional entries for `as`-renamed bindings. Handles:
        //   `use X::Y as Z;`               (single rename)
        //   `use X::{A, B as C, D};`       (rename inside a use-list)
        //   `use X::{A::{B, C}, D};`       (nested brace-list)
        // Brace-depth-aware split is required — `inside.split(',')`
        // would naively split inside a nested group.
        let body = text.trim_end_matches(';').trim();
        if body.contains('{') {
            let span = span_of(file, &node);
            collect_use_tree_imports(body, file, span, &mut out);
        } else if let Some((path, alias)) = body.rsplit_once(" as ") {
            let alias_trim = alias.trim().to_string();
            // Split the path into prefix::last_segment.
            let (prefix, last) = path.rsplit_once("::").unwrap_or(("", path));
            let last_trim = last.trim().to_string();
            if !alias_trim.is_empty() && !last_trim.is_empty() {
                out.push(ImportSpec {
                    span: span_of(file, &node),
                    module: prefix.to_string(),
                    alias: Some(alias_trim),
                    is_wildcard: false,
                    original_name: Some(last_trim),
                    scope: ImportScope::Module,
                });
            }
        }
    }
    out
}

/// Walk a Rust use-tree text form (`X::{A, B::{C, D as E}, F}`) and
/// emit one `ImportSpec` per leaf binding. Brace-depth-aware so the
/// split correctly handles nested groups; recurses into each
/// brace-suffixed prefix. `//` and `/* */` comments are stripped
/// up front so a `use foo::{ /* X, */ A }` selector list isn't
/// fooled by commas / braces inside the comment.
fn collect_use_tree_imports(body: &str, file: FileId, span: bonsai_common::Span, out: &mut Vec<ImportSpec>) {
    let cleaned = strip_use_tree_comments(body);
    let body = cleaned.trim();
    if body.is_empty() {
        return;
    }
    let Some(brace_open) = body.find('{') else {
        // Leaf without braces — already handled by the caller's
        // top-level emission. No nested decomposition needed.
        return;
    };
    let prefix = body[..brace_open].trim_end_matches("::").trim();
    // Find the matching `}` by depth-tracking.
    let inside_start = brace_open + 1;
    let bytes = body.as_bytes();
    let mut depth: i32 = 1;
    let mut close: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate().skip(inside_start) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else { return };
    let inside = &body[inside_start..close];
    for part in split_top_level_commas(inside) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.contains('{') {
            // Nested brace group: prepend our prefix and recurse so
            // `X::{A::{B, C}}` emits `X::A` :: B and `X::A` :: C.
            let nested = if prefix.is_empty() {
                part.to_string()
            } else {
                format!("{prefix}::{part}")
            };
            collect_use_tree_imports(&nested, file, span, out);
            continue;
        }
        // Braced glob: `use foo::{*}` brings every item in `foo`
        // into scope just like `use foo::*;`. Without setting
        // `is_wildcard` here the resolver would treat `*` as an
        // ordinary symbol name.
        if part == "*" {
            out.push(ImportSpec {
                span,
                module: prefix.to_string(),
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Module,
            });
            continue;
        }
        // Self-binding: `use foo::{self, bar}` re-exports `foo`
        // itself under its own name. Emit it as a module-level
        // alias so `alias_map_from_imports` registers `foo →
        // foo` rather than mapping a meaningless `self` symbol.
        // Tokenise on whitespace so `self  as  Foo` (multi-space,
        // valid Rust) parses identically to `self as Foo`.
        let tokens: Vec<&str> = part.split_whitespace().collect();
        if tokens.first().copied() == Some("self") {
            let alias_name = match tokens.as_slice() {
                ["self"] => prefix.rsplit("::").next().map(str::to_string),
                ["self", "as", name] => Some((*name).to_string()),
                _ => None,
            }
            .filter(|s| !s.is_empty());
            if let Some(local) = alias_name {
                out.push(ImportSpec {
                    span,
                    module: prefix.to_string(),
                    alias: Some(local),
                    is_wildcard: false,
                    original_name: None,
                    scope: ImportScope::Module,
                });
            }
            continue;
        }
        if let Some((orig, alias)) = part.rsplit_once(" as ") {
            let orig_trim = orig.trim();
            let alias_trim = alias.trim();
            if !orig_trim.is_empty() && !alias_trim.is_empty() {
                out.push(ImportSpec {
                    span,
                    module: prefix.to_string(),
                    alias: Some(alias_trim.to_string()),
                    is_wildcard: false,
                    original_name: Some(orig_trim.to_string()),
                    scope: ImportScope::Module,
                });
            }
        } else {
            out.push(ImportSpec {
                span,
                module: prefix.to_string(),
                alias: None,
                is_wildcard: false,
                original_name: Some(part.to_string()),
                scope: ImportScope::Module,
            });
        }
    }
}

/// Strip `//` line comments and `/* ... */` block comments from a
/// use-tree text form. Walks `char` boundaries so non-ASCII module
/// names (Rust permits Unicode XID identifiers) survive intact.
fn strip_use_tree_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch == '/' {
            match chars.peek().map(|&(_, c)| c) {
                Some('/') => {
                    // Line comment — consume to next newline (or EOF).
                    chars.next();
                    while let Some(&(_, c)) = chars.peek() {
                        if c == '\n' {
                            break;
                        }
                        chars.next();
                    }
                    continue;
                }
                Some('*') => {
                    chars.next(); // consume the '*'
                    let mut prev = '\0';
                    for (_, c) in chars.by_ref() {
                        if prev == '*' && c == '/' {
                            break;
                        }
                        prev = c;
                    }
                    // Replace the comment span with a single space
                    // so identifiers don't accidentally fuse. If the
                    // block comment was unterminated (tree-sitter
                    // would normally reject this), we still emit the
                    // space and exit naturally.
                    out.push(' ');
                    continue;
                }
                _ => {}
            }
        }
        // Avoid Unicode-corrupting `bytes[i] as char` — push the
        // full char as-is.
        out.push(ch);
    }
    out
}

/// Last `::`-separated segment of a `use` path, when the path is
/// rooted at a workspace prefix (`crate::`, `super::`, `self::`).
/// Returns `Some(leaf)` so `use crate::executor;` binds `executor`
/// as a workspace-namespace alias the resolver can follow.
///
/// Type imports (`use crate::Envelope;`) get the same alias —
/// the resolver's bare-name fallback is filtered by the alias
/// target's module path, so a `Envelope::method` call on a name
/// that doesn't actually live in workspace module `Envelope`
/// produces no candidates instead of stitching together an
/// unrelated workspace function. External imports
/// (`use std::process::Command;`) skip this path because their
/// path doesn't start with a workspace prefix; the alias would
/// have nothing to point at and `module_target_matches_decl_module_path`
/// would reject every workspace candidate anyway.
fn workspace_use_leaf(text: &str) -> Option<&str> {
    let body = text.trim_end_matches(';').trim();
    if body.is_empty() || body.contains('{') || body.contains(" as ") {
        return None;
    }
    let stripped = body
        .strip_prefix("crate::")
        .or_else(|| body.strip_prefix("self::"))
        .or_else(|| {
            let mut rest = body;
            let mut stripped_any = false;
            while let Some(next) = rest.strip_prefix("super::") {
                rest = next;
                stripped_any = true;
            }
            stripped_any.then_some(rest)
        })?;
    let leaf = stripped.rsplit("::").next()?.trim();
    (!leaf.is_empty()).then_some(leaf)
}

/// Split a brace-list body on top-level (depth-0) commas only.
fn split_top_level_commas(input: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0;
    for (i, ch) in input.char_indices() {
        match ch {
            '{' | '<' | '(' | '[' => depth += 1,
            '}' | '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&input[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start <= input.len() {
        out.push(&input[start..]);
    }
    out
}

fn rust_module_segments(path: &std::path::Path) -> Vec<String> {
    let mut segs: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    // Drop the trailing `<name>.rs` and any `src/` or `lib.rs`/`mod.rs`
    // sentinels so two files in the same crate share the same prefix.
    if let Some(last) = segs.last_mut() {
        let stem = {
            let path = std::path::Path::new(last);
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                .then(|| path.file_stem().map(|stem| stem.to_string_lossy().into_owned()))
                .flatten()
        };
        if let Some(stem) = stem {
            *last = stem;
        }
    }
    if matches!(segs.last().map(String::as_str), Some("lib" | "mod" | "main")) {
        segs.pop();
    }
    segs.retain(|s| s != "src" && !s.is_empty());
    segs
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
