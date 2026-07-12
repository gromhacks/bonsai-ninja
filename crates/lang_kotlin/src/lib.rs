//! Kotlin language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    collect_modifier_visibility, decl_index_with_handler, extract_imports_via,
    kit::{
        collect_assign_targets, collect_kinds, collect_receiver_field_writes, first_named_child_of_kind,
        language_from_pack, node_text, package_module_segments_with_workspace_prefix, parse_with, span_of,
        walk_flow_events, with_fn_kinds_and_implicit_receivers,
    },
    rewrite_implicit_member_reads, AdapterContext, AdapterError, CallKind, Decl, DeclIndex, DeclKind,
    FieldWrite, FlowEvent, GrammarHandler, ImplicitMemberReadCall, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, ModifierVocabulary, TypeAliasBinding, Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("kotlin");
const PACK_NAME: &str = "kotlin";
// `getter` and `setter` are property accessor bodies in
// tree-sitter-kotlin. Treating them as function-declaration kinds
// gives each accessor its own Decl with its own flow_events, so
// taint that flows through `var x: String get() = … set(v) { … }`
// is observed end-to-end. Without this, the whole property collapses
// into a single Field decl and accessor body events disappear
// (audit task #131).
const HANDLER: GrammarHandler = GrammarHandler {
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    ..with_fn_kinds_and_implicit_receivers(
        &["function_declaration", "getter", "setter"],
        &["this", "super"],
        &[],
    )
};

const KOTLIN_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "function_declaration",
        "class_declaration",
        "object_declaration",
        "property_declaration",
        "secondary_constructor",
    ],
    modifier_container_kinds: &["modifiers", "visibility_modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("internal", Visibility::Crate),
        ("protected", Visibility::Protected),
        ("public", Visibility::Public),
    ],
    // Kotlin's default visibility is `public`.
    default_visibility: Visibility::Public,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct KotlinAdapter;

impl KotlinAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for KotlinAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Kotlin"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["kt", "kts"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Exceptions: the adapter populates `Throw::thrown_type` from
        // `throw IOException(...)` and `Try::catch_types` from
        // `catch (e: IOException) { }`. Kotlin doesn't have multi-
        // catch syntax (uses `is` checks inside the body for that),
        // so each arm contributes one type.
        LanguageCapabilities {
            exceptions: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Parse once and thread the snapshot + tree through every
        // post-process step (object synthesis, package detection,
        // visibility / type-alias / class-base enrichment, exception
        // types). The kit caches per-file parses on the snapshot, but
        // calling `parse_with` four separate times re-walks bookkeeping
        // we can avoid by hoisting.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `fun f(): T {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            // Kotlin's `object Foo { fun bar() { ... } }` parses as
            // `infix_expression` (with `object` as the operator) in
            // tree-sitter-kotlin, so the kit's class-kind detection
            // doesn't see a class node. Synthesize a class decl for
            // each such pattern and re-parent the contained methods so
            // `Foo.bar(...)` dispatches correctly.
            synthesize_kotlin_object_decls(&mut idx, file, &tree, src);
            synthesize_kotlin_constructor_decls(&mut idx, file, &tree, src);
            synthesize_kotlin_property_getter_decls(&mut idx, file, &tree, src);
            // Module path from `package com.foo.bar` declaration; falls
            // back to file-stem when absent.
            if let Some(segments) = extract_kotlin_package(tree.root_node(), src) {
                let segments = package_module_segments_with_workspace_prefix(file, ctx, segments);
                bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
            } else {
                bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
            }
            let vis_map = collect_modifier_visibility(tree.root_node(), file, src, &KOTLIN_VOCAB);
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
            }
            // type_aliases for `[Type, method]` rule resolution.
            // Per-method walk for `name: Type` parameter shapes.
            let aliases_by_span = collect_kotlin_type_aliases(&tree, file, src);
            for decl in &mut idx.defs {
                if let Some(aliases) = aliases_by_span.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                classify_kotlin_constructor_calls(&mut decl.flow_events, &decl.type_aliases);
            }
            let class_aliases_by_span = collect_kotlin_class_type_aliases(&tree, file, src);
            let class_spans_by_symbol: std::collections::HashMap<_, _> = idx
                .defs
                .iter()
                .filter(|decl| is_class_like(decl.kind))
                .map(|decl| (decl.symbol, decl.span))
                .collect();
            for decl in &mut idx.defs {
                let Some(parent) = decl.parent else { continue };
                let Some(parent_span) = class_spans_by_symbol.get(&parent) else {
                    continue;
                };
                let Some(class_aliases) = class_aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == *parent_span).then_some(aliases))
                else {
                    continue;
                };
                for alias in class_aliases {
                    if !decl.type_aliases.contains(alias) {
                        decl.type_aliases.push(alias.clone());
                    }
                }
            }
            // Per-class `bases`: `class Echo : WebSocketHandler(), Mixin {...}`
            // → ["WebSocketHandler", "Mixin"]. Kotlin lists every
            // parent (super-class call + interface types) as
            // `delegation_specifier` siblings of the class name.
            let bases_by_span = collect_kotlin_class_bases(&tree, file, src);
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
            // Throw::thrown_type and Try::catch_types — done after
            // any flow_events mutation so this final enrichment is
            // the authoritative type fact.
            for decl in &mut idx.defs {
                inject_kotlin_function_reference_aliases(&mut decl.flow_events, src);
                populate_kotlin_exception_types(&mut decl.flow_events, &tree, src);
            }
        } else {
            // Parse failed; still run the file-stem fallback so the
            // semantic-identity pass doesn't leave decls without
            // module paths.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        // Same JVM library surface as Java.
        const KOTLIN_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "shutdown",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "unlock",
                transition: "unlocked",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "release",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "dispose",
                transition: "freed",
                arg_index: 0,
            },
        ];
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            synthesize_kotlin_data_copy_fields(&mut decl.flow_events, &decl.type_aliases);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, KOTLIN_LIFECYCLE_TRANSITIONS);
        }
        qualify_kotlin_implicit_member_reads(&mut idx);
        bonsai_lang_api::kit::qualify_bare_hierarchy_member_calls(&mut idx);
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`val c = Foo()` →
        // `c: Foo`) so `c.method(...)` carries a resolved receiver type
        // for `receiver_type_in` / `[Type, method]` rules. Kotlin class
        // names are PascalCase; the constructor heuristic is reliable.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Lower Kotlin data-class `copy(field = value, ...)` results into exact
/// field writes on the enclosing assignment target. `copy` is a
/// compiler-generated data-class operation; receiver type evidence and named
/// arguments come from tree-sitter facts, and the IDG remains API agnostic.
fn synthesize_kotlin_data_copy_fields(events: &mut Vec<FlowEvent>, type_aliases: &[TypeAliasBinding]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                synthesize_kotlin_data_copy_fields(then_events, type_aliases);
                synthesize_kotlin_data_copy_fields(else_events, type_aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                synthesize_kotlin_data_copy_fields(body, type_aliases)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                synthesize_kotlin_data_copy_fields(body, type_aliases);
                synthesize_kotlin_data_copy_fields(catch_events, type_aliases);
                synthesize_kotlin_data_copy_fields(finally_events, type_aliases);
            }
            _ => {}
        }
    }

    let mut additions = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let FlowEvent::Assign { span, target, .. } = event else {
            continue;
        };
        let mut fields = Vec::new();
        for candidate in events.iter() {
            let FlowEvent::Call {
                span: call_span,
                name,
                receiver: Some(receiver),
                receiver_types,
                args,
                ..
            } = candidate
            else {
                continue;
            };
            let receiver_root = receiver.split('.').next().unwrap_or(receiver).trim();
            let receiver_is_typed = !receiver_types.is_empty()
                || type_aliases
                    .iter()
                    .any(|alias| alias.name == receiver_root && !alias.type_name.is_empty());
            if !receiver_is_typed
                || kotlin_call_tail(name) != "copy"
                || call_span.file != span.file
                || call_span.start < span.start
                || span.end < call_span.end
            {
                continue;
            }
            for arg in args {
                let Some(name) = arg.name.as_ref().filter(|name| !name.is_empty()) else {
                    continue;
                };
                let value = arg.place.as_ref().map_or_else(
                    || bonsai_lang_api::ExpressionFlow::from_source_names(arg.source_names.clone()),
                    bonsai_lang_api::ExpressionFlow::from_place,
                );
                fields.push(bonsai_lang_api::ExpressionField {
                    name: name.clone(),
                    value,
                });
            }
        }
        if !fields.is_empty() {
            additions.push((
                index + 1,
                FlowEvent::AggregateAssign {
                    span: *span,
                    target: target.clone(),
                    type_name: None,
                    value_flow: bonsai_lang_api::ExpressionFlow {
                        aggregate_fields: fields,
                        ..Default::default()
                    },
                },
            ));
        }
    }
    for (index, event) in additions.into_iter().rev() {
        events.insert(index, event);
    }
}

/// Reclassify Kotlin call expressions as constructors when the surrounding
/// property binding supplies matching static type evidence.
///
/// The Kotlin CST uses the same `call_expression` node for `File(...)` and a
/// top-level function call, so syntax alone cannot distinguish them. The
/// adapter's property pass has already produced `target -> Type` aliases from
/// explicit annotations or constructor-shaped RHS syntax. Joining that fact
/// with the exact assignment/call span gives downstream graph builders a real
/// `CallKind::Constructor` without teaching them class or API names.
fn classify_kotlin_constructor_calls(events: &mut [FlowEvent], type_aliases: &[TypeAliasBinding]) {
    let constructor_assignments = events
        .iter()
        .filter_map(|event| {
            let FlowEvent::Assign {
                span,
                target,
                source_call: Some(source_call),
                ..
            } = event
            else {
                return None;
            };
            let bound_type = type_aliases
                .iter()
                .find(|alias| alias.name == *target)
                .map(|alias| kotlin_call_tail(&alias.type_name))?;
            (kotlin_call_tail(source_call) == bound_type).then(|| (*span, source_call.clone()))
        })
        .collect::<Vec<_>>();

    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                call_kind,
                ..
            } if matches!(call_kind, CallKind::Function | CallKind::Method)
                && constructor_assignments.iter().any(|(assign_span, source_call)| {
                    assign_span.file == span.file
                        && assign_span.start <= span.start
                        && span.end <= assign_span.end
                        && source_call == name
                }) =>
            {
                *call_kind = CallKind::Constructor;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                classify_kotlin_constructor_calls(then_events, type_aliases);
                classify_kotlin_constructor_calls(else_events, type_aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                classify_kotlin_constructor_calls(body, type_aliases);
                classify_kotlin_constructor_calls(catch_events, type_aliases);
                classify_kotlin_constructor_calls(finally_events, type_aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                classify_kotlin_constructor_calls(body, type_aliases);
            }
            _ => {}
        }
    }
}

fn kotlin_call_tail(name: &str) -> &str {
    name.rsplit(['.', ':', '\\']).next().unwrap_or(name).trim()
}

fn qualify_kotlin_implicit_member_reads(index: &mut DeclIndex) {
    use std::collections::HashSet;
    let getter_names: HashSet<String> = index
        .defs
        .iter()
        .filter(|decl| {
            matches!(decl.kind, DeclKind::Method | DeclKind::Function)
                && decl.params.is_empty()
                && !decl.name.is_empty()
        })
        .map(|decl| decl.name.clone())
        .collect();
    if getter_names.is_empty() {
        return;
    }
    for decl in &mut index.defs {
        if decl.flow_events.is_empty() {
            continue;
        }
        let mut locals: HashSet<String> = decl.params.iter().cloned().collect();
        collect_assign_targets(&decl.flow_events, &mut locals);
        rewrite_implicit_member_reads(&mut decl.flow_events, &getter_names, &locals, |name| {
            ImplicitMemberReadCall {
                source_call: format!("this.{name}"),
                call_name: format!("this.{name}"),
                receiver: Some("this".to_string()),
                call_kind: CallKind::Method,
            }
        });
    }
}

/// Add exact callable-alias facts for Kotlin function references such
/// as `val cb = ::helper`.
fn inject_kotlin_function_reference_aliases(events: &mut Vec<FlowEvent>, src: &[u8]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_kotlin_function_reference_aliases(then_events, src);
                inject_kotlin_function_reference_aliases(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_kotlin_function_reference_aliases(body, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_kotlin_function_reference_aliases(body, src);
                inject_kotlin_function_reference_aliases(catch_events, src);
                inject_kotlin_function_reference_aliases(finally_events, src);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let alias = kotlin_function_reference_alias_assignment(&event, src);
        rewritten.push(event);
        if let Some(alias) = alias {
            rewritten.push(alias);
        }
    }
    *events = rewritten;
}

fn kotlin_function_reference_alias_assignment(event: &FlowEvent, src: &[u8]) -> Option<FlowEvent> {
    let FlowEvent::Assign { span, target, .. } = event else {
        return None;
    };
    let rhs = span_rhs_text(src, *span)?;
    let source_name = kotlin_function_reference_rhs(&rhs)?;
    Some(FlowEvent::Assign {
        span: *span,
        target: target.trim().to_string(),
        source_name: Some(source_name),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    })
}

fn span_rhs_text(src: &[u8], span: bonsai_common::Span) -> Option<String> {
    let start = usize::try_from(span.start).ok()?.min(src.len());
    let end = usize::try_from(span.end).ok()?.min(src.len());
    if start >= end {
        return None;
    }
    let text = std::str::from_utf8(&src[start..end]).ok()?;
    let (_, rhs) = text.split_once('=')?;
    Some(rhs.trim().trim_end_matches(';').trim().to_string())
}

fn kotlin_function_reference_rhs(rhs: &str) -> Option<String> {
    let name = rhs.trim().strip_prefix("::")?.trim();
    if name.is_empty() || !name.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(name.to_string())
}

/// Lift each `import_header` into an `ImportSpec`. The aliased shape
/// (`import x.y.z as Z`) needs special care so the matcher doesn't
/// double-resolve the terminal symbol — see the inline comment.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Kotlin shapes:
    //   `import x.y.z`       → bare import
    //   `import x.y.z as Z`  → with `as` alias
    //   `import x.y.*`       → wildcard
    for import_node in collect_kinds(tree, &["import_header"]) {
        let text = node_text(&import_node, src)
            .trim_start_matches("import ")
            .trim_end_matches(';')
            .trim();
        if text.is_empty() {
            continue;
        }
        let (head, explicit_alias) = if let Some((module_part, alias_part)) = text.rsplit_once(" as ") {
            (
                module_part.trim().to_string(),
                Some(alias_part.trim().to_string()),
            )
        } else {
            (text.to_string(), None)
        };
        let is_wildcard = head.ends_with(".*");
        let full_path = head.trim_end_matches(".*").to_string();
        // `import x.y.z as Z` — record the terminal symbol as
        // `original_name` and store ONLY the namespace prefix as
        // `module`. Otherwise `kit::alias_map_from_imports` reads
        // `Member { module: "x.y.z", member: "z" }` and the matcher
        // expands `Z(...)` to `"x.y.z.z(...)"` (double tail). The
        // unaliased shape preserves the full path as `module` to
        // keep query-by-module-path semantics for downstream rule
        // lookup.
        let (module, alias, original_name) = if explicit_alias.is_some() {
            match full_path.rsplit_once('.') {
                Some((prefix, terminal_symbol)) => (
                    prefix.to_string(),
                    explicit_alias,
                    Some(terminal_symbol.to_string()),
                ),
                None => (String::new(), explicit_alias, Some(full_path.clone())),
            }
        } else if is_wildcard {
            (full_path, None, None)
        } else {
            let alias = import_tail_binding(&full_path);
            (full_path, alias, None)
        };
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module,
            alias,
            is_wildcard,
            original_name,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn import_tail_binding(module: &str) -> Option<String> {
    let tail = module
        .rsplit_once('.')
        .map(|(_, tail)| tail)
        .unwrap_or(module)
        .trim();
    (!tail.is_empty() && tail != module).then(|| tail.to_string())
}

/// Walk `decl.flow_events` recursively and populate
/// `Throw::thrown_type` / `Try::catch_types` from the Kotlin parse
/// tree. Kotlin syntax:
///   throw IOException("...")  → thrown_type: "IOException" (no `new`)
///   throw e                   → thrown_type: None (need data-flow)
///   `try { } catch (e: IOException) { } catch (e: A) { }`
///                             → `catch_types = vec!["IOException", "A"]`
fn populate_kotlin_exception_types(
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
                    &["jump_expression", "throw_expression", "throw_statement"],
                ) {
                    if let Some(name) = kotlin_thrown_type_for_node(node, src) {
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
                ..
            } => {
                if catch_types.is_empty() {
                    if let Some(node) = bonsai_lang_api::kit::node_at_span(
                        tree.root_node(),
                        *span,
                        &["try_expression", "try_statement"],
                    ) {
                        *catch_types = collect_kotlin_catch_types(node, src);
                    }
                }
                populate_kotlin_exception_types(body, tree, src);
                populate_kotlin_exception_types(catch_events, tree, src);
                populate_kotlin_exception_types(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                populate_kotlin_exception_types(then_events, tree, src);
                populate_kotlin_exception_types(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                populate_kotlin_exception_types(body, tree, src);
            }
            _ => {}
        }
    }
}

/// Pull the constructor type out of `throw Foo(...)`. Kotlin omits the
/// `new` keyword, so a throw is just a call expression whose head is
/// the type name. Returns `None` for re-throws (`throw e`).
fn kotlin_thrown_type_for_node(throw_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    // throw_expression > call_expression > simple_identifier (the constructor name)
    let mut throw_cursor = throw_node.walk();
    for child in throw_node.named_children(&mut throw_cursor) {
        if child.kind() == "call_expression" {
            // Constructor call: first child is usually the type name
            let mut call_cursor = child.walk();
            for sub in child.named_children(&mut call_cursor) {
                if matches!(
                    sub.kind(),
                    "simple_identifier" | "user_type" | "navigation_expression"
                ) {
                    return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                        &sub, src,
                    )));
                }
            }
        }
    }
    None
}

/// Collect the `catch (e: T)` types in source order. Each arm
/// contributes one type (Kotlin has no multi-catch syntax — code uses
/// `is` checks inside the body for that case).
fn collect_kotlin_catch_types(try_node: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut catch_types: Vec<String> = Vec::new();
    let mut try_cursor = try_node.walk();
    for child in try_node.named_children(&mut try_cursor) {
        if child.kind() != "catch_block" {
            continue;
        }
        // Kotlin catch_block layout (tree-sitter-kotlin):
        //   catch_block
        //     simple_identifier   <- param name (skip)
        //     user_type           <- the catch type wrapper
        //       type_identifier   <- canonical name
        //     statements          <- catch body (skip)
        // We pick out the *type wrappers* (`user_type` / `type_reference`)
        // and read their type_identifier descendant; never read a top-level
        // `simple_identifier` directly because that's the param name.
        let mut catch_cursor = child.walk();
        for sub in child.named_children(&mut catch_cursor) {
            if matches!(sub.kind(), "user_type" | "type_reference") {
                // Find the inner `type_identifier` descendant; for nested
                // generics we want the leftmost type name.
                let mut found: Option<String> = None;
                let mut wrapper_cursor = sub.walk();
                let mut work_stack: Vec<tree_sitter::Node<'_>> =
                    sub.named_children(&mut wrapper_cursor).collect();
                while let Some(node) = work_stack.pop() {
                    if node.kind() == "type_identifier" {
                        found = Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                            &node, src,
                        )));
                        break;
                    }
                    let mut inner_cursor = node.walk();
                    for inner_child in node.named_children(&mut inner_cursor) {
                        work_stack.push(inner_child);
                    }
                }
                // Fallback to the wrapper's text — covers grammar
                // shapes that don't have a `type_identifier` descendant
                // (e.g. some `nullable_type` wrappers).
                let name = found.unwrap_or_else(|| {
                    bonsai_lang_api::kit::canonical_simple_type_name(node_text(&sub, src))
                });
                if !name.is_empty() && !catch_types.iter().any(|existing| existing == &name) {
                    catch_types.push(name);
                }
            }
        }
    }
    catch_types
}

/// Find the `package com.foo.bar` declaration at the top of a Kotlin
/// file and return its segments.
fn extract_kotlin_package(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut root_cursor = root.walk();
    for child in root.children(&mut root_cursor) {
        if child.kind() != "package_header" {
            continue;
        }
        let mut header_cursor = child.walk();
        for header_child in child.children(&mut header_cursor) {
            if matches!(header_child.kind(), "identifier" | "qualified_identifier") {
                let text = node_text(&header_child, src);
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
    }
    None
}

/// Walk Kotlin function declarations and collect local receiver type
/// evidence (`name: Type` parameters and constructor-shaped
/// `val name = Type(...)` locals) as `TypeAliasBinding`. Used by the
/// resolver to narrow `[Type, method]` rule dispatch through adapter
/// facts instead of local receiver-name guesses.
fn collect_kotlin_type_aliases(
    tree: &Tree,
    file: bonsai_common::FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    let mut aliases_by_span = std::collections::HashMap::new();
    for fn_node in collect_kinds(tree, &["function_declaration"]) {
        let mut aliases = Vec::new();
        // DFS: walks every `parameter` / `class_parameter` descendant
        // (lambda receivers, default-value expressions, etc. all get
        // their parameters extracted).
        let mut work_stack = vec![fn_node];
        while let Some(node) = work_stack.pop() {
            if node != fn_node
                && matches!(
                    node.kind(),
                    "function_declaration"
                        | "class_declaration"
                        | "object_declaration"
                        | "interface_declaration"
                )
            {
                continue;
            }
            if matches!(
                node.kind(),
                "parameter" | "class_parameter" | "property_declaration"
            ) {
                if let Some(binding) = kotlin_param_alias(node, src) {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                work_stack.push(child);
            }
        }
        if !aliases.is_empty() {
            aliases_by_span.insert(span_of(file, &fn_node), aliases);
        }
    }
    aliases_by_span
}

/// Synthesize class decls for Kotlin's `object Foo { ... }` pattern
/// because tree-sitter-kotlin parses it as `infix_expression` (with
/// `object` as the operator-literal, the name as a `simple_identifier`,
/// and the body as a `lambda_literal`) rather than a dedicated
/// `object_declaration` kind. Without a class decl there's no parent
/// for the contained methods, so `Foo.bar(args)` calls have nothing
/// to dispatch into. The synthesized class carries the
/// infix_expression span so any subsequent post-process keyed on
/// span (e.g. `apply_class_field_type_aliases`) lines up.
fn synthesize_kotlin_object_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let mut next_symbol_raw = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(0, |m| m + 1);
    for infix in collect_kinds(tree, &["infix_expression"]) {
        // NOTE: `object Foo { ... }` actually surfaces the `object` keyword
        // in the `operator` FIELD (see the kit's `pseudo_call.rs`
        // detection), not as a child of kind `object_literal`, so this gate
        // never matches and the synthesis is currently INERT. Enabling it
        // (gating on the operator field) is correct in isolation but
        // re-parents the object's methods under the synthesized class,
        // which regresses interprocedural taint dispatch through
        // `Foo.method(...)` (matrix cell R_06/kotlin: the call resolves to
        // the method but no longer flows taint into its body). Making
        // singleton-object method dispatch work end-to-end is the
        // prerequisite for turning this on — left inert until then rather
        // than shipping that regression.
        let mut cursor = infix.walk();
        let mut object_keyword = false;
        let mut name_node: Option<Node<'_>> = None;
        let mut lambda_node: Option<Node<'_>> = None;
        for child in infix.named_children(&mut cursor) {
            match child.kind() {
                "object_literal" => object_keyword = true,
                "simple_identifier" if name_node.is_none() => name_node = Some(child),
                "lambda_literal" => lambda_node = Some(child),
                _ => {}
            }
        }
        if !object_keyword {
            continue;
        }
        let (Some(name_node), Some(lambda_node)) = (name_node, lambda_node) else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let class_span = span_of(file, &infix);
        if idx.defs.iter().any(|d| d.span == class_span) {
            continue;
        }
        let class_symbol = bonsai_common::SymbolId::new(next_symbol_raw);
        next_symbol_raw += 1;
        let class_module_path = idx
            .defs
            .iter()
            .find(|d| !d.module_path.is_empty())
            .map(|d| d.module_path.clone())
            .unwrap_or_default();
        idx.defs.push(bonsai_lang_api::Decl {
            symbol: class_symbol,
            kind: DeclKind::Class,
            name: name.clone(),
            qualified_name: None,
            module_path: class_module_path,
            span: class_span,
            name_span: span_of(file, &name_node),
            visibility: bonsai_lang_api::Visibility::Public,
            parent: None,
            body_span: Some(span_of(file, &lambda_node)),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
        // Re-parent every method-like decl whose span is contained
        // by the lambda body to the synthesized class.
        let lambda_span = span_of(file, &lambda_node);
        for decl in &mut idx.defs {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            if decl.parent.is_some() {
                continue;
            }
            if decl.span.start >= lambda_span.start && decl.span.end <= lambda_span.end {
                decl.parent = Some(class_symbol);
                decl.kind = DeclKind::Method;
            }
        }
    }
}

fn synthesize_kotlin_constructor_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
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
        .map(|decl| (decl.span, decl.symbol, decl.name.clone(), decl.name_span))
        .collect::<Vec<_>>();
    let mut next = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    for class_node in collect_kinds(tree, &["class_declaration"]) {
        let class_span = span_of(file, &class_node);
        let Some((_, class_symbol, class_name, class_name_span)) =
            classes.iter().find(|(span, _, _, _)| *span == class_span)
        else {
            continue;
        };
        if let Some(primary) = first_named_child_of_kind(&class_node, "primary_constructor") {
            let body = first_named_child_of_kind(&class_node, "class_body");
            let mut flow_events =
                kotlin_primary_constructor_delegation_events(class_node, file, src, &class_names);
            flow_events.extend(
                body.map(|body| walk_flow_events(body, file, src, &HANDLER, &class_names))
                    .unwrap_or_default(),
            );
            let params = constructor_param_names(primary, src);
            let receiver_field_writes = kotlin_primary_constructor_field_writes(primary, file, src, &params);
            // A primary constructor exists semantically even when it has no
            // property parameters or body initializers. Keep the declaration
            // so constructor calls resolve through the class hierarchy; the
            // delegation events above model the AST-proven base invocation.
            idx.defs.push(kotlin_constructor_decl(
                bonsai_common::SymbolId::new(next),
                *class_symbol,
                class_name,
                KotlinConstructorSpans {
                    name: *class_name_span,
                    decl: class_span,
                    body: body.map_or_else(|| span_of(file, &primary), |body| span_of(file, &body)),
                },
                params,
                flow_events,
                receiver_field_writes,
            ));
            next = next.saturating_add(1);
        }
        for secondary in collect_descendant_kinds(class_node, &["secondary_constructor"]) {
            let body = first_named_child_of_kind(&secondary, "statements").unwrap_or(secondary);
            let flow_events = walk_flow_events(body, file, src, &HANDLER, &class_names);
            let params = constructor_param_names(secondary, src);
            let receiver_field_writes =
                collect_receiver_field_writes(&flow_events, &params, None, &["this", "super"], &[]);
            idx.defs.push(kotlin_constructor_decl(
                bonsai_common::SymbolId::new(next),
                *class_symbol,
                class_name,
                KotlinConstructorSpans {
                    name: *class_name_span,
                    decl: span_of(file, &secondary),
                    body: span_of(file, &body),
                },
                params,
                flow_events,
                receiver_field_writes,
            ));
            next = next.saturating_add(1);
        }
    }
}

/// Lower direct superclass constructor invocations from the class header into
/// the synthetic primary constructor. Tree-sitter exposes these as
/// `delegation_specifier > constructor_invocation`; walking only direct class
/// children prevents nested class/method calls from leaking into the parent
/// constructor.
fn kotlin_primary_constructor_delegation_events(
    class_node: Node<'_>,
    file: FileId,
    src: &[u8],
    class_names: &[String],
) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    let mut cursor = class_node.walk();
    for child in class_node.named_children(&mut cursor) {
        if child.kind() != "delegation_specifier"
            || first_named_child_of_kind(&child, "constructor_invocation").is_none()
        {
            continue;
        }
        let mut events = walk_flow_events(child, file, src, &HANDLER, class_names);
        for event in &mut events {
            if let FlowEvent::Call { call_kind, .. } = event {
                // A superclass delegation call constructs the ancestor part
                // of the current instance; it is not a fresh allocation.
                // Preserve constructor kind; the resolver proves that the
                // target is an ancestor of the synthetic constructor owner,
                // which lets the IDG stitch outbound state to the adapter's
                // canonical receiver without a source-language token here.
                *call_kind = CallKind::Constructor;
            }
        }
        out.extend(events);
    }
    out
}

fn synthesize_kotlin_property_getter_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
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
                decl.body_span.unwrap_or(decl.span),
                decl.symbol,
                decl.module_path.clone(),
            )
        })
        .collect::<Vec<_>>();
    if classes.is_empty() {
        return;
    }

    let mut next = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let mut synthesized = Vec::new();
    for property in collect_kinds(tree, &["property_declaration"]) {
        let Some(getter) = first_named_child_of_kind(&property, "getter") else {
            continue;
        };
        let Some(name_node) = kotlin_property_name_node(property) else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        let property_span = span_of(file, &property);
        let Some((_, parent, module_path)) = classes
            .iter()
            .filter(|(body_span, _, _)| span_contains(*body_span, property_span))
            .min_by_key(|(body_span, _, _)| body_span.end.saturating_sub(body_span.start))
        else {
            continue;
        };
        if idx
            .defs
            .iter()
            .chain(synthesized.iter())
            .any(|decl| decl.parent == Some(*parent) && decl.name == name && decl.params.is_empty())
        {
            continue;
        }
        let body = first_named_child_of_kind(&getter, "function_body").unwrap_or(getter);
        let body_span = span_of(file, &body);
        let mut flow_events = walk_flow_events(body, file, src, &HANDLER, &class_names);
        if !flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Return { .. }))
        {
            if let Some(expr) = kotlin_getter_expression_text(body, src) {
                let expression_node = body.named_child(0).unwrap_or(body);
                flow_events.push(FlowEvent::Return {
                    span: body_span,
                    value_text: Some(expr.clone()),
                    value_name: kotlin_bare_identifier(&expr),
                    value_flow: bonsai_lang_api::kit::expression_flow_from_node(expression_node, file, src),
                });
            }
        }
        if flow_events.is_empty() {
            continue;
        }
        synthesized.push(Decl {
            symbol: bonsai_common::SymbolId::new(next),
            kind: DeclKind::Method,
            name,
            qualified_name: None,
            module_path: module_path.clone(),
            span: span_of(file, &getter),
            name_span: span_of(file, &name_node),
            visibility: Visibility::Public,
            parent: Some(*parent),
            body_span: Some(body_span),
            flow_events,
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: vec!["this".to_string(), "super".to_string()],
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
        next = next.saturating_add(1);
    }
    idx.defs.extend(synthesized);
}

fn kotlin_property_name_node(property: Node<'_>) -> Option<Node<'_>> {
    let variable = first_named_child_of_kind(&property, "variable_declaration")?;
    first_named_child_of_kind(&variable, "simple_identifier")
        .or_else(|| first_named_child_of_kind(&variable, "identifier"))
}

fn kotlin_getter_expression_text(body: Node<'_>, src: &[u8]) -> Option<String> {
    let mut text = node_text(&body, src).trim().trim_end_matches(';').trim();
    if let Some(rest) = text.strip_prefix('=') {
        text = rest.trim();
    }
    (!text.is_empty()).then(|| text.to_string())
}

fn kotlin_bare_identifier(text: &str) -> Option<String> {
    let text = text.trim();
    let mut chars = text.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    chars
        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        .then(|| text.to_string())
}

fn span_contains(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

struct KotlinConstructorSpans {
    name: bonsai_common::Span,
    decl: bonsai_common::Span,
    body: bonsai_common::Span,
}

fn kotlin_constructor_decl(
    symbol: bonsai_common::SymbolId,
    parent: bonsai_common::SymbolId,
    class_name: &str,
    spans: KotlinConstructorSpans,
    params: Vec<String>,
    flow_events: Vec<FlowEvent>,
    receiver_field_writes: Vec<FieldWrite>,
) -> Decl {
    Decl {
        symbol,
        kind: DeclKind::Constructor,
        name: class_name.to_string(),
        qualified_name: None,
        module_path: bonsai_lang_api::ModulePath::default(),
        span: spans.decl,
        name_span: spans.name,
        visibility: Visibility::Public,
        parent: Some(parent),
        body_span: Some(spans.body),
        flow_events,
        has_implicit_returns: false,
        params,
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes,
        implicit_receiver_names: vec!["this".to_string(), "super".to_string()],
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn kotlin_primary_constructor_field_writes(
    primary: Node<'_>,
    file: FileId,
    src: &[u8],
    params: &[String],
) -> Vec<FieldWrite> {
    let mut writes = Vec::new();
    for param in collect_descendant_kinds(primary, &["class_parameter"]) {
        if !kotlin_class_parameter_declares_property(param, src) {
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
    writes.sort_by_key(|write| (write.span.start, write.target.clone()));
    writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
    writes
}

fn kotlin_class_parameter_declares_property(param: Node<'_>, src: &[u8]) -> bool {
    node_text(&param, src)
        .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .any(|token| matches!(token, "val" | "var"))
}

fn collect_descendant_kinds<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if kinds.contains(&current.kind()) {
            out.push(current);
        }
        let mut cursor = current.walk();
        let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    out
}

fn constructor_param_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    collect_descendant_kinds(node, &["class_parameter", "parameter"])
        .into_iter()
        .filter_map(|param| parameter_binding_name(param, src))
        .collect()
}

fn parameter_binding_name(param: Node<'_>, src: &[u8]) -> Option<String> {
    let mut names = Vec::new();
    collect_binding_identifiers(param, src, &mut names);
    names.into_iter().find(|name| name != "_")
}

fn collect_binding_identifiers(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if matches!(node.kind(), "simple_identifier" | "identifier") {
        let name = node_text(&node, src).trim();
        if !name.is_empty() {
            out.push(name.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "user_type" | "type_identifier") {
            continue;
        }
        collect_binding_identifiers(child, src, out);
    }
}

/// Collect receiver-visible type aliases declared by Kotlin class
/// constructor properties / fields and attach them to methods through
/// `Decl.parent`. Example: `class H(private val conn: Connection)` makes
/// `conn: Connection` available inside every method of `H`.
fn collect_kotlin_class_type_aliases(
    tree: &Tree,
    file: bonsai_common::FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, &["class_declaration", "object_declaration"]) {
        let mut aliases = Vec::new();
        collect_kotlin_class_aliases_from_node(class_node, src, &mut aliases);
        if !aliases.is_empty() {
            out.push((span_of(file, &class_node), aliases));
        }
    }
    out
}

fn collect_kotlin_class_aliases_from_node(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    match node.kind() {
        "function_declaration" | "getter" | "setter" | "secondary_constructor" => return,
        "class_parameter" | "property_declaration" => {
            if let Some(binding) = kotlin_param_alias(node, src) {
                if !aliases.contains(&binding) {
                    aliases.push(binding);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_kotlin_class_aliases_from_node(child, src, aliases);
    }
}

/// Extract a single `name: Type` pair from a `parameter` /
/// `class_parameter` node. Returns `None` when either side is missing
/// or when the binding name happens to equal the type (no useful alias).
fn kotlin_param_alias(node: Node<'_>, src: &[u8]) -> Option<TypeAliasBinding> {
    // tree-sitter-kotlin's `parameter` exposes the binding identifier
    // and type as unnamed `simple_identifier` and `user_type`
    // children rather than `name`/`type` fields. Walk by kind so
    // both shapes resolve.
    let mut name_node: Option<Node<'_>> = node.child_by_field_name("name");
    let mut type_node: Option<Node<'_>> = node.child_by_field_name("type");
    if name_node.is_none() || type_node.is_none() {
        let mut child_cursor = node.walk();
        for child in node.named_children(&mut child_cursor) {
            match child.kind() {
                "simple_identifier" | "identifier" if name_node.is_none() => {
                    name_node = Some(child);
                }
                // `property_declaration` wraps the binding identifier
                // inside a `variable_declaration` node — descend so
                // type-inferred fields like `private val x = Y()` get
                // a name. The explicit type annotation (`val c: Foo`)
                // also lives INSIDE the variable_declaration, so pull
                // it from there too; otherwise typed locals
                // (`val c: Foo = make()` — WS2 cast / factory case)
                // fall through to the type-inferred path and lose `Foo`.
                "variable_declaration" if name_node.is_none() => {
                    let mut inner = child.walk();
                    for grandchild in child.named_children(&mut inner) {
                        match grandchild.kind() {
                            "simple_identifier" | "identifier" if name_node.is_none() => {
                                name_node = Some(grandchild);
                            }
                            "user_type" | "type_identifier" | "function_type" | "nullable_type"
                                if type_node.is_none() =>
                            {
                                type_node = Some(grandchild);
                            }
                            _ => {}
                        }
                    }
                }
                "user_type" | "type_identifier" | "function_type" | "nullable_type"
                    if type_node.is_none() =>
                {
                    type_node = Some(child);
                }
                _ => {}
            }
        }
    }
    let name_node = name_node?;
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let type_short = if let Some(type_node) = type_node {
        canonical_short_type(node_text(&type_node, src))?
    } else {
        // Type-inferred property (`val x = Y()`): tree-sitter does not
        // resolve types, so fall back to constructor-shape inference
        // when the RHS is a `call_expression` whose callee is a
        // PascalCase identifier — that's a constructor call by Kotlin
        // convention and binds the property's type for receiver
        // dispatch. Without this, classes that use idiomatic
        // type-inferred field initialization (`private val authService
        // = AuthService()`) lose receiver-type info downstream.
        // WS2: `val c = make() as Foo` / `as?` — the cast on the RHS is
        // the only type signal for an inferred local; prefer it, then fall
        // back to the constructor-shape inference.
        kotlin_property_cast_type(node, src).or_else(|| kotlin_property_constructor_type(node, src))?
    };
    if name == type_short {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: type_short,
    })
}

/// WS2: when an inferred local is initialized by a Kotlin `as` / `as?`
/// cast (`val c = make() as Foo`), the cast's right operand is the static
/// type. Scans the property's named children for the `as_expression` that
/// is the RHS and returns its canonical type. Returns `None` for any
/// non-cast RHS so only a genuine cast types the local.
fn kotlin_property_cast_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "as_expression" {
            // The cast target is a `user_type` / `type_identifier` /
            // `nullable_type` operand of the `as_expression` (the grammar
            // exposes operands as positional children, not a `right`
            // field).
            let mut inner = child.walk();
            for operand in child.named_children(&mut inner) {
                if matches!(operand.kind(), "user_type" | "type_identifier" | "nullable_type") {
                    return canonical_short_type(node_text(&operand, src));
                }
            }
        }
    }
    None
}

/// When a `property_declaration` lacks an explicit type annotation,
/// look at its `expression` (RHS) for a `call_expression` whose
/// callee is a PascalCase identifier — that's a constructor call by
/// Kotlin convention, so the property's static type is the callee
/// name. Returns the canonical short type, or `None` when the RHS
/// isn't a constructor-shaped expression.
fn kotlin_property_constructor_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let rhs = node.child_by_field_name("expression").or_else(|| {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.named_children(&mut cursor) {
            if child.kind() == "call_expression" {
                found = Some(child);
                break;
            }
        }
        found
    })?;
    if rhs.kind() != "call_expression" {
        return None;
    }
    let callee = rhs.child_by_field_name("function").or_else(|| {
        let mut cursor = rhs.walk();
        let mut found = None;
        for child in rhs.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "simple_identifier" | "identifier" | "navigation_expression" | "user_type"
            ) {
                found = Some(child);
                break;
            }
        }
        found
    })?;
    let callee_text = node_text(&callee, src);
    let canonical = canonical_short_type(callee_text)?;
    // Pascal-case head identifies a constructor — Kotlin requires
    // class names to be capitalized, while regular function names are
    // lowercase by convention. Without the capital-letter check we'd
    // bind every typed local to the function it was initialized from,
    // which is not the same fact at all.
    canonical
        .chars()
        .next()
        .filter(|first| first.is_ascii_uppercase())?;
    Some(canonical)
}

/// Strip a Kotlin type literal down to its bare class name. Drops
/// generics (`List<String>` -> `List`), array brackets, the nullable
/// `?` suffix, and namespace qualification (`kotlin.String` -> `String`).
fn canonical_short_type(raw: &str) -> Option<String> {
    let no_generics = raw.split('<').next().unwrap_or(raw);
    let no_arrays = no_generics.split('[').next().unwrap_or(no_generics);
    let stripped = no_arrays.trim().trim_end_matches('?');
    let short = stripped.rsplit('.').next().unwrap_or(stripped).trim();
    // Accept any letter prefix — Kotlin types are typically capital
    // (`String`, `List`, `HttpRequest`) but lowercase primitives
    // (`int`, `boolean` via Java interop) are valid too.
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

/// True for decl kinds that can carry a `bases` list. Shared with the
/// post-processing loop that copies `bases_by_span` onto matching decls.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Kotlin `class_declaration` / `object_declaration` /
/// `interface_declaration` nodes and collect bare base type names.
/// Kotlin grammar shape (verified via tree-sitter `to_sexp`):
///
///   `class Echo : WebSocketHandler(), Mixin { ... }` →
///     (class_declaration (type_identifier)
///        (delegation_specifier (constructor_invocation (user_type (type_identifier))))
///        (delegation_specifier (user_type (type_identifier))))
///
/// Each delegation_specifier wraps either a `constructor_invocation`
/// (parent class with init args) or a bare `user_type` (interface).
/// Both expose a `user_type` whose first `type_identifier` descendant
/// is the bare base name.
fn collect_kotlin_class_bases(
    tree: &Tree,
    file: bonsai_common::FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_table = Vec::new();
    let class_kinds = &["class_declaration", "object_declaration", "interface_declaration"];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for child in class_node.named_children(&mut class_cursor) {
            if child.kind() != "delegation_specifier" {
                continue;
            }
            // `delegation_specifier`'s first named child is the
            // parent type — `constructor_invocation` (super-class
            // with args) or bare `user_type` (interface) or
            // `explicit_delegation`.
            let mut spec_cursor = child.walk();
            for spec_child in child.named_children(&mut spec_cursor) {
                if let Some(name) = kotlin_base_name_from(spec_child, src) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                    break;
                }
            }
        }
        if !bases.is_empty() {
            bases_table.push((span_of(file, &class_node), bases));
        }
    }
    bases_table
}

/// Resolve one `delegation_specifier` child to a bare base type name,
/// dispatching on the three shapes Kotlin uses (super call, interface
/// reference, `by`-delegation). Returns `None` for any node that
/// isn't a delegation target.
fn kotlin_base_name_from(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "constructor_invocation" => {
            // Has a `user_type` child carrying the parent class name.
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                if child.kind() == "user_type" {
                    return canonical_short_type(node_text(&child, src));
                }
            }
            None
        }
        "user_type" => canonical_short_type(node_text(&node, src)),
        "explicit_delegation" => {
            // `Foo by bar` — the type is the leading user_type.
            let mut child_cursor = node.walk();
            for child in node.named_children(&mut child_cursor) {
                if child.kind() == "user_type" {
                    return canonical_short_type(node_text(&child, src));
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
