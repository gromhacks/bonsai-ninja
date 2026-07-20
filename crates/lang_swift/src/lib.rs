//! Swift language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_assign_targets, collect_modifier_visibility, collect_param_type_aliases, decl_index_with_handler,
    extract_imports_via,
    kit::{
        canonical_simple_type_name, collect_kinds, collect_receiver_field_writes, first_named_child_of_kind,
        language_from_pack, node_text, parse_with, span_of, walk_flow_events,
        with_fn_kinds_and_implicit_receivers,
    },
    rewrite_implicit_member_reads, AdapterContext, AdapterError, CallKind, Decl, DeclIndex, DeclKind,
    FlowEvent, GrammarHandler, ImplicitMemberReadCall, ImportIndex, ImportScope, ImportSpec, LanguageAdapter,
    LanguageCapabilities, LanguageId, ModifierVocabulary, SyntaxSpecialForm, TypeAliasBinding,
    TypeAliasVocabulary, Visibility,
};
use tree_sitter::Node;

const SWIFT_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_declaration", "init_declaration"],
    // `property_declaration` captures typed locals (`let c: Foo = make()`,
    // `let c = x as Foo`) so cast / factory-typed receivers resolve
    // `receiver_type_in`; the name is recovered outside the type span.
    param_kinds: &["parameter", "property_declaration"],
    name_field: "name",
    type_field: "type",
};

const SWIFT_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "function_declaration",
        "class_declaration",
        "struct_declaration",
        "enum_declaration",
        "protocol_declaration",
        "init_declaration",
        "deinit_declaration",
        "property_declaration",
    ],
    modifier_container_kinds: &["modifiers", "visibility_modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("fileprivate", Visibility::Private),
        ("internal", Visibility::Module),
        ("public", Visibility::Public),
        ("open", Visibility::Public),
    ],
    // Swift's true default is `internal`: visible across the same
    // module, not across unrelated modules.
    default_visibility: Visibility::Module,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("swift");
const PACK_NAME: &str = "swift";
const HANDLER: GrammarHandler = GrammarHandler {
    constructor_names: &["init"],
    special_forms: &[SyntaxSpecialForm::TrailingClosureDefer],
    ..with_fn_kinds_and_implicit_receivers(&["function_declaration"], &["self", "super"], &[])
};

#[derive(Debug, Default, Copy, Clone)]
pub struct SwiftAdapter;

impl SwiftAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for SwiftAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Swift"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["swift"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Pattern matching: the adapter post-processes flat `Branch`
        // events emitted for `switch_statement`s into nested `Branch`
        // chains so the engine forks state per arm. Same approach as
        // the Scala adapter.
        LanguageCapabilities {
            pattern_matching: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: &["init"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["self"],
            same_directory_unqualified_calls: true,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        apply_swift_semantic_identity(&mut idx, ctx);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `func f() -> T {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            let arm_spans = collect_swift_switch_arm_spans(&tree, src, file);
            for decl in &mut idx.defs {
                bonsai_lang_api::kit::split_match_arms_in_branch_events(&mut decl.flow_events, &arm_spans);
            }
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_modifier_visibility(tree.root_node(), file, src, &SWIFT_VOCAB);
            let alias_map = collect_param_type_aliases(&tree, file, src, &SWIFT_TYPE_ALIASES);
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
            }
            // Class-level property type bindings — `let
            // authService = AuthService()` makes `authService :
            // AuthService` available inside every method of the
            // enclosing class so receiver dispatch reaches the real
            // method decl.
            let class_field_aliases = collect_swift_class_field_aliases(&tree, file, src);
            let function_param_names = collect_swift_function_param_names(file, &tree, src);
            synthesize_swift_constructor_decls(&mut idx, file, &tree, src);
            // Swift structs (`struct Envelope { var kind, var cmd, ... }`)
            // get a compiler-synthesized **memberwise init** — no
            // explicit `init` block, but `Envelope(kind:, cmd:, ...)`
            // is callable. Without surfacing this as a Constructor
            // decl with `receiver_field_writes` for each stored
            // property, `new Envelope(...)` never field-projects
            // `envelope.cmd ← arg` onto the caller's allocation and
            // the entire mega_flow chain stalls at handle_request.
            synthesize_swift_memberwise_struct_inits(&mut idx, file, &tree, src);
            // Swift computed properties (`var cmd: String { data.cmd }`)
            // are wrapped in `property_declaration` with a
            // `computed_value: computed_property` child rather than a
            // function_declaration — the kit's fn-kind extraction
            // misses them entirely. Synthesize a zero-arg Method per
            // computed property so `let c = cmd` (resolved via the
            // qualify pass below) finds a callable getter.
            synthesize_swift_computed_property_decls(&mut idx, file, &tree, src);
            // Synthesize a `Return` whose value_text is the param list
            // on each Constructor that lacks one. Tokenization
            // bridges the param identifiers to the Return, which
            // the standard callee-Return → caller-CallRet edge then
            // carries onto the allocation target — making `repo`
            // whole-object tainted (Java-style) so the receiver-
            // field bridge fires for `repo.run()` even when only
            // `repo.data.cmd` is field-precisely tainted. Mirrors
            // `synthesize_csharp_constructor_implicit_returns`.
            synthesize_swift_constructor_implicit_returns(&mut idx);
            apply_swift_semantic_identity(&mut idx, ctx);
            let class_span_for_parent: std::collections::HashMap<bonsai_common::SymbolId, Span> = idx
                .defs
                .iter()
                .filter(|candidate| is_class_like(candidate.kind))
                .map(|candidate| (candidate.symbol, candidate.span))
                .collect();
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                let mut aliases = alias_map.get(&decl.span).cloned().unwrap_or_default();
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
                if matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
                    if let Some(params) = function_param_names
                        .iter()
                        .find_map(|(span, params)| (*span == decl.span).then_some(params))
                    {
                        decl.params = params.clone();
                    }
                }
                normalize_swift_parameter_names(decl);
            }
            // Per-class `bases`: `class Echo: WebSocketHandler, Mixin`
            // → ["WebSocketHandler", "Mixin"]. Swift exposes each
            // parent type as a separate `inheritance_specifier`
            // child of the class node, with `inherits_from:` field
            // pointing at a `user_type`.
            let bases_by_span = collect_swift_class_bases(&tree, file, src);
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
        // Recognised Swift lifecycle transitions. `cancel` for
        // tasks / publishers / network requests, `close` for
        // streams, `release` for manual ARC reach-arounds,
        // `deinit` for the destructor, and `invalidate` for
        // timers / observers.
        const SWIFT_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "release",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "deinit",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "invalidate",
                transition: "cancelled",
                arg_index: 0,
            },
        ];
        let constructor_field_params = swift_constructor_field_params(&idx);
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            if !constructor_field_params.is_empty() {
                synthesize_swift_constructor_field_assignments(
                    &mut decl.flow_events,
                    &constructor_field_params,
                );
            }
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, SWIFT_LIFECYCLE_TRANSITIONS);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`let c = Foo()` →
        // `c: Foo`) so `c.method(...)` carries a resolved receiver type
        // for `receiver_type_in` / `[Type, method]` rules. Swift type
        // names are UpperCamelCase; the constructor heuristic is reliable.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let declared_aliases = collect_swift_declared_type_aliases(&tree, snapshot.text.as_bytes());
            apply_swift_declared_type_aliases(&mut idx, &declared_aliases);
        }
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

fn apply_swift_semantic_identity(idx: &mut DeclIndex, ctx: &AdapterContext<'_>) {
    let module_segments = swift_module_segments(idx.file, ctx);
    let module_path = bonsai_lang_api::ModulePath::from_segments(module_segments.iter().cloned());
    let qualified_prefix =
        swift_qualified_prefix(idx.file, ctx).unwrap_or_else(|| module_segments.join("::"));
    for decl in &mut idx.defs {
        if decl.qualified_name.is_none() {
            decl.qualified_name = Some(if qualified_prefix.is_empty() {
                decl.name.clone()
            } else {
                format!("{qualified_prefix}::{}", decl.name)
            });
        }
        decl.module_path = module_path.clone();
    }
}

fn swift_module_segments(file: FileId, ctx: &AdapterContext<'_>) -> Vec<String> {
    if let Some(relative) = ctx.workspace_relative_path(file) {
        let components = swift_path_components(&relative);
        for marker in ["Sources", "Tests"] {
            if let Some(index) = components.iter().position(|part| part == marker) {
                if let Some(target) = components.get(index + 1) {
                    let mut segments = components[..index]
                        .iter()
                        .map(|part| sanitize_swift_module_segment(part))
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>();
                    segments.push(sanitize_swift_module_segment(target));
                    return segments;
                }
            }
        }
    }
    if let Some(root_path) = ctx.workspace_root {
        let mut segments = root_path
            .file_name()
            .map(|name| vec![sanitize_swift_module_segment(&name.to_string_lossy())])
            .unwrap_or_default();
        if let Some(relative) = ctx.workspace_relative_path(file) {
            if let Some(parent) = relative.parent() {
                segments.extend(
                    swift_path_components(parent)
                        .into_iter()
                        .map(|part| sanitize_swift_module_segment(&part))
                        .filter(|part| !part.is_empty()),
                );
            }
        }
        if !segments.is_empty() {
            return segments;
        }
    }
    vec!["swift".to_string()]
}

fn swift_qualified_prefix(file: FileId, ctx: &AdapterContext<'_>) -> Option<String> {
    let path = ctx
        .workspace_relative_path(file)
        .or_else(|| ctx.vfs.path(file).ok().map(|p| (*p).clone()))?;
    let mut segments = swift_path_components(&path);
    let last = segments.last_mut()?;
    if let Some((stem, _)) = last.rsplit_once('.') {
        *last = stem.to_string();
    }
    segments.retain(|segment| !segment.is_empty());
    (!segments.is_empty()).then(|| segments.join("::"))
}

fn swift_path_components(path: &std::path::Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => {
                let text = part.to_string_lossy();
                (!text.is_empty()).then(|| text.into_owned())
            }
            _ => None,
        })
        .collect()
}

fn sanitize_swift_module_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "swift".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_swift_parameter_names(decl: &mut bonsai_lang_api::Decl) {
    if !matches!(
        decl.kind,
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
    ) || decl.type_aliases.is_empty()
    {
        return;
    }
    let type_names = decl
        .type_aliases
        .iter()
        .map(|alias| alias.type_name.clone())
        .collect::<std::collections::HashSet<_>>();
    let alias_names = decl
        .type_aliases
        .iter()
        .map(|alias| alias.name.clone())
        .collect::<std::collections::HashSet<_>>();
    decl.params
        .retain(|param| !type_names.contains(param) || alias_names.contains(param));
}

fn collect_swift_declared_type_aliases(tree: &Tree, src: &[u8]) -> std::collections::HashMap<String, String> {
    let mut aliases = std::collections::HashMap::new();
    for declaration in collect_kinds(tree, &["typealias_declaration"]) {
        // Tree-sitter preserves source order here: the first named child is
        // the alias declaration name and the second is its target type. Do
        // not use the generic stack collector, whose LIFO traversal reverses
        // siblings and would invert `Alias = Target`.
        let mut cursor = declaration.walk();
        let mut children = declaration.named_children(&mut cursor);
        let Some(alias_node) = children.next() else {
            continue;
        };
        let Some(target_node) = children.next() else {
            continue;
        };
        let alias = node_text(&alias_node, src).trim();
        let target = node_text(&target_node, src).trim();
        if !alias.is_empty() && !target.is_empty() && alias != target {
            aliases.insert(alias.to_string(), target.to_string());
        }
    }
    aliases
}

fn apply_swift_declared_type_aliases(
    index: &mut DeclIndex,
    aliases: &std::collections::HashMap<String, String>,
) {
    if aliases.is_empty() {
        return;
    }
    for decl in &mut index.defs {
        for binding in &mut decl.type_aliases {
            binding.type_name = resolve_swift_declared_type_alias(&binding.type_name, aliases);
        }
        if let Some(return_type) = &mut decl.return_type {
            *return_type = resolve_swift_declared_type_alias(return_type, aliases);
        }
        rewrite_swift_event_receiver_type_aliases(&mut decl.flow_events, aliases);
    }
}

fn resolve_swift_declared_type_alias(
    type_name: &str,
    aliases: &std::collections::HashMap<String, String>,
) -> String {
    let mut current = type_name.trim();
    let mut seen = std::collections::HashSet::new();
    while seen.insert(current.to_string()) {
        let Some(next) = aliases.get(current).map(String::as_str) else {
            break;
        };
        current = next.trim();
    }
    current.to_string()
}

fn rewrite_swift_event_receiver_type_aliases(
    events: &mut [FlowEvent],
    aliases: &std::collections::HashMap<String, String>,
) {
    for event in events {
        match event {
            FlowEvent::Call { receiver_types, .. } => {
                for receiver_type in receiver_types {
                    *receiver_type = resolve_swift_declared_type_alias(receiver_type, aliases);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_swift_event_receiver_type_aliases(then_events, aliases);
                rewrite_swift_event_receiver_type_aliases(else_events, aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_swift_event_receiver_type_aliases(body, aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_swift_event_receiver_type_aliases(body, aliases);
                rewrite_swift_event_receiver_type_aliases(catch_events, aliases);
                rewrite_swift_event_receiver_type_aliases(finally_events, aliases);
            }
            _ => {}
        }
    }
}

fn collect_swift_function_param_names(file: FileId, tree: &Tree, src: &[u8]) -> Vec<(Span, Vec<String>)> {
    collect_kinds(tree, &["function_declaration"])
        .into_iter()
        .map(|function| {
            let mut params = Vec::new();
            let mut cursor = function.walk();
            for child in function.named_children(&mut cursor) {
                if child.kind() != "parameter" {
                    continue;
                }
                if let Some(name) = parameter_binding_name(child, src) {
                    params.push(name);
                }
            }
            (span_of(file, &function), params)
        })
        .collect()
}

fn synthesize_swift_constructor_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
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

    for init in collect_kinds(tree, &["init_declaration"]) {
        let Some(class_node) = nearest_swift_class_node(init) else {
            continue;
        };
        let class_span = span_of(file, &class_node);
        let Some((_, class_symbol, class_name, class_name_span)) =
            classes.iter().find(|(span, _, _, _)| *span == class_span)
        else {
            continue;
        };
        let body = first_named_child_of_kind(&init, "function_body").unwrap_or(init);
        let flow_events = walk_flow_events(body, file, src, &HANDLER, &class_names);
        idx.defs.push(swift_constructor_decl(
            bonsai_common::SymbolId::new(next),
            *class_symbol,
            class_name,
            SwiftConstructorSpans {
                name: *class_name_span,
                decl: span_of(file, &init),
                body: span_of(file, &body),
            },
            constructor_param_names(init, src),
            flow_events,
        ));
        next = next.saturating_add(1);
    }
}

fn nearest_swift_class_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "class_declaration" | "struct_declaration" | "enum_declaration" | "extension_declaration"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

struct SwiftConstructorSpans {
    name: Span,
    decl: Span,
    body: Span,
}

fn swift_constructor_decl(
    symbol: bonsai_common::SymbolId,
    parent: bonsai_common::SymbolId,
    class_name: &str,
    spans: SwiftConstructorSpans,
    params: Vec<String>,
    flow_events: Vec<bonsai_lang_api::FlowEvent>,
) -> Decl {
    let receiver_field_writes =
        collect_receiver_field_writes(&flow_events, &params, None, &["self", "super"], &[]);
    Decl {
        symbol,
        kind: DeclKind::Constructor,
        name: class_name.to_string(),
        qualified_name: None,
        module_path: bonsai_lang_api::ModulePath::default(),
        span: spans.decl,
        name_span: spans.name,
        visibility: Visibility::Module,
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
        implicit_receiver_names: vec!["self".to_string(), "super".to_string()],
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn constructor_param_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    collect_descendant_kinds(node, &["parameter"])
        .into_iter()
        .filter_map(|param| parameter_binding_name(param, src))
        .collect()
}

fn parameter_binding_name(param: Node<'_>, src: &[u8]) -> Option<String> {
    let mut names = Vec::new();
    collect_binding_identifiers(param, src, &mut names);
    names.into_iter().rev().find(|name| name != "_")
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

fn collect_descendant_kinds<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if kinds.contains(&current.kind()) {
            out.push(current);
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Walk every Swift class-like declaration and pull `(name, type)`
/// bindings from its `property_declaration` children. Returns
/// `(class_span, [TypeAliasBinding])` so the per-method merge can
/// attach a class's bindings to every method nested inside it.
fn collect_swift_class_field_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<TypeAliasBinding>)> {
    let class_kinds = &[
        "class_declaration",
        "struct_declaration",
        "protocol_declaration",
        "enum_declaration",
        "extension_declaration",
    ];
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![class_node];
        while let Some(node) = work.pop() {
            if node != class_node && class_kinds.contains(&node.kind()) {
                continue;
            }
            // Don't descend into method bodies — that scope is owned
            // by the per-method param-alias pass.
            if node != class_node
                && matches!(
                    node.kind(),
                    "function_declaration" | "init_declaration" | "deinit_declaration"
                )
            {
                continue;
            }
            if node.kind() == "property_declaration" {
                if let Some(binding) = swift_property_alias(node, src) {
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

/// Extract a `name: Type` binding from a Swift `property_declaration`.
/// Handles both `let x: T = ...` (explicit type) and `let x = T()`
/// (type-inferred from a PascalCase constructor-style initializer).
fn swift_property_alias(node: Node<'_>, src: &[u8]) -> Option<TypeAliasBinding> {
    let pattern = node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.named_children(&mut cursor) {
            if matches!(child.kind(), "pattern" | "simple_identifier" | "identifier") {
                found = Some(child);
                break;
            }
        }
        found
    })?;
    let name = node_text(&pattern, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let type_short = node
        .child_by_field_name("type")
        .map(|t| node_text(&t, src).to_string())
        .and_then(|t| swift_canonical_type(&t))
        .or_else(|| swift_property_constructor_type(node, src))?;
    if name == type_short {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: type_short,
    })
}

/// Find a constructor-shaped initializer (`= Foo()` / `= Foo.bar()`)
/// inside a Swift property_declaration whose static type is
/// `Foo`. Returns the canonical short type, or `None` when the
/// initializer isn't a PascalCase call.
fn swift_property_constructor_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let mut value: Option<Node<'_>> = node.child_by_field_name("value");
    if value.is_none() {
        // Newer Swift grammar emits `value:` directly; older shapes
        // wrap the initializer under a `pattern_initializer` child.
        for child in node.named_children(&mut cursor) {
            if matches!(child.kind(), "call_expression") {
                value = Some(child);
                break;
            }
            if matches!(child.kind(), "pattern_initializer") {
                let mut inner = child.walk();
                for sub in child.named_children(&mut inner) {
                    if matches!(sub.kind(), "call_expression") {
                        value = Some(sub);
                        break;
                    }
                }
                if value.is_some() {
                    break;
                }
            }
        }
    }
    let call = value?;
    if call.kind() != "call_expression" {
        return None;
    }
    let callee = call.child_by_field_name("function").or_else(|| {
        let mut inner = call.walk();
        let mut found = None;
        for child in call.named_children(&mut inner) {
            if matches!(
                child.kind(),
                "simple_identifier" | "identifier" | "navigation_expression" | "type_identifier"
            ) {
                found = Some(child);
                break;
            }
        }
        found
    })?;
    let canonical = swift_canonical_type(node_text(&callee, src))?;
    canonical
        .chars()
        .next()
        .filter(|first| first.is_ascii_uppercase())?;
    Some(canonical)
}

fn swift_canonical_type(raw: &str) -> Option<String> {
    let no_generics = raw.split('<').next().unwrap_or(raw);
    let trimmed = no_generics.trim().trim_end_matches('?').trim_end_matches('!');
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

/// True when the decl is a type-defining container that can carry `bases`.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Per-arm body spans for every `switch_statement` in the file.
///
/// Swift shape: `switch_statement > switch_entry+ > statements (the arm
/// body)`. Each `switch_entry` is one arm — `case` or `default`. We pass
/// these spans to the kit's `split_match_arms_in_branch_events` to peel
/// the kit-emitted flat Branch into per-arm forks.
fn collect_swift_switch_arm_spans(tree: &Tree, _src: &[u8], file: FileId) -> Vec<Vec<bonsai_common::Span>> {
    let mut spans_per_switch: Vec<Vec<bonsai_common::Span>> = Vec::new();
    for switch_node in collect_kinds(tree, &["switch_statement"]) {
        let mut arm_body_spans: Vec<bonsai_common::Span> = Vec::new();
        let mut switch_cursor = switch_node.walk();
        for entry in switch_node.named_children(&mut switch_cursor) {
            if entry.kind() != "switch_entry" {
                continue;
            }
            // Each `switch_entry` (case or default) has a `statements` child holding the arm body.
            let mut entry_cursor = entry.walk();
            for entry_child in entry.named_children(&mut entry_cursor) {
                if entry_child.kind() == "statements" {
                    arm_body_spans.push(span_of(file, &entry_child));
                }
            }
        }
        if !arm_body_spans.is_empty() {
            spans_per_switch.push(arm_body_spans);
        }
    }
    spans_per_switch
}

/// Walk Swift class / struct / protocol / enum / extension declarations and
/// collect bare base type names from `inheritance_specifier` children.
///
/// Grammar shape (verified):
///
///   `class Echo: WebSocketHandler, Mixin { ... }` →
///     (class_declaration name: (type_identifier)
///        (inheritance_specifier inherits_from: (user_type (type_identifier)))
///        (inheritance_specifier inherits_from: (user_type (type_identifier))))
///
/// Each `inheritance_specifier` carries one parent under the `inherits_from`
/// field. Swift doesn't distinguish super-class from protocol conformance
/// syntactically; both surface here.
fn collect_swift_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &[
        "class_declaration",
        "struct_declaration",
        "protocol_declaration",
        "enum_declaration",
        "extension_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut child_cursor = class_node.walk();
        for child in class_node.named_children(&mut child_cursor) {
            if child.kind() != "inheritance_specifier" {
                continue;
            }
            // Older grammars don't expose `inherits_from:` as a field — fall back
            // to the first user_type / type_identifier child.
            let mut fallback_cursor = child.walk();
            let fallback_child = child
                .named_children(&mut fallback_cursor)
                .find(|sub| matches!(sub.kind(), "user_type" | "type_identifier"));
            let target = child.child_by_field_name("inherits_from").or(fallback_child);
            if let Some(target_node) = target {
                if let Some(name) = canonical_swift_base_name(node_text(&target_node, src)) {
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

/// Canonicalize a Swift base reference to a bare type name.
///
/// Strips generic parameter lists (`Foo<T>` → `Foo`) and any qualifying
/// path (`pkg.Foo` → `Foo`).
fn canonical_swift_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Strip generic parameter list: `Foo<Bar>` → `Foo`.
    let head = trimmed.split('<').next().unwrap_or(trimmed).trim();
    // Strip qualifying path: `Module.Foo` → `Foo`.
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Parse `import_declaration` nodes into `ImportSpec`s.
///
/// Swift `import_declaration` is straight: `import Foundation`,
/// `import struct Foundation.URL`, `import func Foundation.exit`.
/// Per-symbol kinds are stripped; the module path still resolves
/// via short-tail matching.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for import_node in collect_kinds(tree, &["import_declaration"]) {
        // Strip any leading Swift attribute (`@testable`, `@_exported`,
        // `@available(...)`, ...) before the `import ` trim — otherwise
        // the attribute corrupts the module name and fails the package gate.
        let text = strip_swift_import_attribute_prefixes(node_text(&import_node, src))
            .trim_start_matches("import ")
            .trim();
        // Strip the optional symbol-kind keyword so the resulting module path
        // matches what callers reference at use sites.
        let module = text
            .strip_prefix("struct ")
            .or_else(|| text.strip_prefix("class "))
            .or_else(|| text.strip_prefix("func "))
            .or_else(|| text.strip_prefix("var "))
            .or_else(|| text.strip_prefix("let "))
            .or_else(|| text.strip_prefix("typealias "))
            .or_else(|| text.strip_prefix("enum "))
            .or_else(|| text.strip_prefix("protocol "))
            .unwrap_or(text)
            .trim()
            .to_string();
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module,
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Strip leading Swift attribute tokens from an `import_declaration`'s
/// text so the module name resolves cleanly. `@testable import
/// Foundation` -> `import Foundation`; `@_exported import X` -> `import
/// X`. Handles an optional `(...)` attribute argument list and multiple
/// stacked attributes. A no-op when no leading `@` is present.
fn strip_swift_import_attribute_prefixes(text: &str) -> &str {
    let mut rest = text.trim_start();
    while let Some(after_at) = rest.strip_prefix('@') {
        // Consume the attribute identifier (`testable`, `_exported`, ...).
        let ident_end = after_at
            .find(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
            .unwrap_or(after_at.len());
        if ident_end == 0 {
            break; // bare `@` with no identifier — leave untouched.
        }
        let mut after_ident = after_at[ident_end..].trim_start();
        // Optional balanced argument list, e.g. `@available(...)`.
        if let Some(after_paren) = after_ident.strip_prefix('(') {
            match after_paren.find(')') {
                Some(close) => after_ident = after_paren[close + 1..].trim_start(),
                None => break, // unbalanced — give up rather than mangle.
            }
        }
        rest = after_ident;
    }
    rest
}

/// Synthesize a zero-arg `Method` decl for each Swift computed
/// property — `var cmd: String { data.cmd }` — by extracting the
/// property name + computed-property body. The kit's fn-kind set is
/// `["function_declaration"]`, so `property_declaration` nodes (which
/// is what computed properties parse to in tree-sitter-swift) aren't
/// indexed and a bare property read `let c = cmd` resolves to
/// nothing. Each synthesized Method's body is modeled as a `Call+
/// Return` chain when the computed body is a simple dotted member
/// access (`data.cmd`) so the 1-level receiver-field bridge can
/// thread taint to the record/component accessor; otherwise it's a
/// single `Return` with the body text.
fn synthesize_swift_computed_property_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let mut next = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(1, |m| m + 1);
    let mut synthesized: Vec<Decl> = Vec::new();
    for prop in collect_kinds(tree, &["property_declaration"]) {
        // Only handle computed properties — a `computed_value:
        // computed_property` child. Stored properties (no body) are
        // already represented via `let x: T` field bindings.
        let mut pw = prop.walk();
        let Some(computed) = prop.children(&mut pw).find(|c| c.kind() == "computed_property") else {
            continue;
        };
        // Property name lives under `name: pattern > bound_identifier:
        // simple_identifier`.
        let Some(name) = swift_property_name(prop, src) else {
            continue;
        };
        // Extract the body expression text. For
        // `computed_property > statements > <expr>`, take the
        // statements' last named child.
        let body_text = swift_computed_body_text(computed, src);
        let Some(body_text) = body_text else {
            continue;
        };
        let body_span = span_of(file, &computed);
        // Find enclosing class/struct/protocol/extension decl for
        // parent + module path + visibility lookup.
        let Some((parent, module_path, visibility)) = swift_enclosing_type_decl(idx, prop, file) else {
            continue;
        };
        // Skip if a sibling decl with the same name + zero-arg
        // already exists (e.g. an explicit `get` accessor).
        if idx.defs.iter().chain(synthesized.iter()).any(|d| {
            d.parent == parent
                && d.name == name
                && d.params.is_empty()
                && matches!(d.kind, DeclKind::Method | DeclKind::Function)
        }) {
            continue;
        }
        // Body shape: Call+Return when it's a dotted member access,
        // else single Return with the body text.
        let flow_events =
            if let Some((mut call_receiver, mut call_name)) = swift_dotted_member_access_parts(&body_text) {
                let receiver_type = swift_lookup_member_type(prop, &call_receiver, src);
                // A sibling stored property is an instance field even when
                // Swift source omits `self.`. Keep the explicit compiler
                // place so the constructor's `self.<field>` write and this
                // later read share one IDG identity. The enclosing AST's
                // property declaration proves membership; no field spelling
                // is special-cased.
                if receiver_type.is_some() && !call_receiver.starts_with("self.") {
                    call_receiver = format!("self.{call_receiver}");
                    call_name = format!("self.{call_name}");
                }
                let receiver_types = receiver_type.into_iter().collect();
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
                        value_text: Some(format!("{call_name}()")),
                        value_name: None,
                        value_flow: bonsai_lang_api::ExpressionFlow {
                            call_sites: vec![body_span],
                            ..Default::default()
                        },
                    },
                ]
            } else {
                let qualified = if body_text.starts_with("self.") || body_text.starts_with("super.") {
                    body_text.clone()
                } else {
                    format!("self.{body_text}")
                };
                vec![FlowEvent::Return {
                    span: body_span,
                    value_text: Some(qualified.clone()),
                    value_name: Some(qualified.clone()),
                    value_flow: bonsai_lang_api::ExpressionFlow::from_place(qualified),
                }]
            };
        // Name span: the simple_identifier under `name: pattern`.
        let name_span = swift_property_name_span(prop, file).unwrap_or(body_span);
        synthesized.push(Decl {
            symbol: bonsai_common::SymbolId::new(next),
            kind: DeclKind::Method,
            name,
            qualified_name: None,
            module_path,
            span: name_span,
            name_span,
            visibility,
            parent,
            body_span: Some(body_span),
            flow_events,
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: vec!["self".to_string(), "super".to_string()],
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
        next += 1;
    }
    idx.defs.extend(synthesized);
    // After synthesis, rewrite bare-name reads of these getters
    // throughout the file's method bodies (`let c = cmd` → `Call cmd; Assign{source_call:cmd}`).
    qualify_swift_implicit_member_reads(idx);
}

/// Extract the property name from a `property_declaration` — the name
/// is wrapped in `name: pattern > bound_identifier: simple_identifier`
/// in tree-sitter-swift's grammar.
fn swift_property_name(prop: Node<'_>, src: &[u8]) -> Option<String> {
    let pattern = prop.child_by_field_name("name")?;
    let mut pw = pattern.walk();
    for c in pattern.children(&mut pw) {
        if c.kind() == "bound_identifier" || c.kind() == "simple_identifier" {
            // The bound_identifier wraps a simple_identifier; prefer
            // its text when present, otherwise the wrapper's own.
            let mut ic = c.walk();
            for inner in c.children(&mut ic) {
                if inner.kind() == "simple_identifier" {
                    let n = node_text(&inner, src).trim();
                    if !n.is_empty() {
                        return Some(n.to_string());
                    }
                }
            }
            let n = node_text(&c, src).trim();
            if !n.is_empty() {
                return Some(n.to_string());
            }
        }
    }
    // Fallback: the pattern node's full text (covers destructure /
    // tuple-pattern shapes that don't hit the wrapper above).
    let n = node_text(&pattern, src).trim();
    if n.is_empty() {
        None
    } else {
        Some(n.to_string())
    }
}

/// Span of a `property_declaration`'s name token, for stamping the
/// synthesized accessor's `name_span` precisely.
fn swift_property_name_span(prop: Node<'_>, file: FileId) -> Option<Span> {
    let pattern = prop.child_by_field_name("name")?;
    let mut pw = pattern.walk();
    for c in pattern.children(&mut pw) {
        if c.kind() == "bound_identifier" || c.kind() == "simple_identifier" {
            return Some(span_of(file, &c));
        }
    }
    Some(span_of(file, &pattern))
}

/// Extract the expression text from a `computed_property` body —
/// `var cmd: String { data.cmd }` → `"data.cmd"`. tree-sitter-swift
/// wraps the body in `statements`; the last named child is the
/// expression we want.
fn swift_computed_body_text(computed: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cw = computed.walk();
    let stmts = computed.children(&mut cw).find(|c| c.kind() == "statements")?;
    let mut sw = stmts.walk();
    let named: Vec<_> = stmts.children(&mut sw).filter(|c| c.is_named()).collect();
    let expr = named.last().copied()?;
    let text = node_text(&expr, src).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// If `body` is a simple dotted member-access of identifiers
/// (`data.cmd`, optionally prefixed `self.`/`super.`), return
/// `(receiver, call_name)` so the synthesized accessor can model
/// it as a method call. Returns `None` for non-trivial bodies
/// (literals, calls, complex expressions) — those keep the
/// Return-only fallback.
fn swift_dotted_member_access_parts(body: &str) -> Option<(String, String)> {
    let trimmed = body.trim();
    // Strip the implicit-receiver qualifier if present; the inner
    // text must be a pure dotted identifier path of ≥2 segments.
    let inner = trimmed
        .strip_prefix("self.")
        .or_else(|| trimmed.strip_prefix("super."))
        .unwrap_or(trimmed);
    let segments: Vec<&str> = inner.split('.').collect();
    if segments.len() < 2 {
        return None;
    }
    // Every segment must be a Rust-ASCII-style identifier.
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
    // Receiver = up-to-last-dot; call_name = full dotted form
    // (mirrors Java's `data.cmd` shape: receiver="data" name="data.cmd").
    let last_dot = inner.rfind('.')?;
    Some((inner[..last_dot].to_string(), inner.to_string()))
}

/// Walk up from `node` to the enclosing class/struct/protocol/extension/
/// enum declaration and return its symbol / module / visibility for
/// parenting synthesized accessor decls.
fn swift_enclosing_type_decl(
    idx: &DeclIndex,
    node: Node<'_>,
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
            "class_declaration"
                | "struct_declaration"
                | "protocol_declaration"
                | "extension_declaration"
                | "enum_declaration"
        ) {
            let span = span_of(file, &n);
            return idx
                .defs
                .iter()
                .find(|d| d.span == span)
                .map(|d| (Some(d.symbol), d.module_path.clone(), d.visibility));
        }
        cur = n.parent();
    }
    None
}

/// Find a sibling stored-property/let-binding named `member` in the
/// enclosing Swift type and return its canonical declared type.
fn swift_lookup_member_type(prop: Node<'_>, member: &str, src: &[u8]) -> Option<String> {
    let mut cur = prop.parent();
    let mut type_node = None;
    while let Some(n) = cur {
        if matches!(
            n.kind(),
            "class_declaration" | "struct_declaration" | "protocol_declaration" | "extension_declaration"
        ) {
            type_node = Some(n);
            break;
        }
        cur = n.parent();
    }
    let type_node = type_node?;
    let body = first_named_child_of_kind(&type_node, "class_body")
        .or_else(|| first_named_child_of_kind(&type_node, "struct_body"))
        .or_else(|| first_named_child_of_kind(&type_node, "extension_body"))?;
    let mut bw = body.walk();
    for child in body.children(&mut bw) {
        if child.kind() != "property_declaration" {
            continue;
        }
        let Some(name) = swift_property_name(child, src) else {
            continue;
        };
        if name != member {
            continue;
        }
        // Look for `type_annotation > <type>` sibling.
        let mut cw = child.walk();
        for c in child.children(&mut cw) {
            if c.kind() == "type_annotation" {
                let mut tw = c.walk();
                for t in c.children(&mut tw) {
                    if t.is_named() && t.kind() != "type_annotation" {
                        let raw = node_text(&t, src).trim();
                        if !raw.is_empty() {
                            return Some(canonical_simple_type_name(raw).to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Mirror `qualify_csharp_implicit_member_reads` / `qualify_dart_...`
/// for Swift: bare reads of a sibling zero-arg member (`let c = cmd`)
/// are compiler-style implicit-`self` member calls. Preserve that receiver
/// explicitly so resolution and receiver-field flow use the AST's lexical
/// class context rather than treating the getter as a free function.
fn qualify_swift_implicit_member_reads(index: &mut DeclIndex) {
    use std::collections::HashSet;
    let getter_names: HashSet<String> = index
        .defs
        .iter()
        .filter(|d| {
            matches!(d.kind, DeclKind::Method | DeclKind::Function)
                && d.params.is_empty()
                && !d.name.is_empty()
        })
        .map(|d| d.name.clone())
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
                source_call: format!("self.{name}"),
                call_name: format!("self.{name}"),
                receiver: Some("self".to_string()),
                call_kind: CallKind::Method,
            }
        });
    }
}

/// Synthesize a memberwise initializer (Constructor decl) for each
/// Swift struct that has no explicit `init`. Swift's compiler
/// synthesizes one automatically with one labeled param per stored
/// `var`/`let` property; without surfacing this to the IDG,
/// `Envelope(kind:, cmd:, ...)` resolves to nothing and field-
/// projection never reaches the caller's allocation.
fn synthesize_swift_memberwise_struct_inits(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    use bonsai_lang_api::FieldWrite;
    let mut next = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(1, |m| m + 1);
    let mut synthesized: Vec<Decl> = Vec::new();
    // Tree-sitter-swift unifies `class`, `struct`, `enum`, and
    // `actor` under `class_declaration`. Disambiguate by inspecting
    // the prefix text between the node's start and its `name:` child
    // — that range contains only modifiers + the immediate keyword,
    // so `struct` appearing there definitively names THIS decl as a
    // struct (avoids false positives from nested `struct Bar {}` in
    // an outer `class Foo { ... }`). Only structs get a compiler-
    // synthesized memberwise init.
    for struct_node in collect_kinds(tree, &["class_declaration"]) {
        let Some(name_node) = struct_node.child_by_field_name("name") else {
            continue;
        };
        let prefix_start = struct_node.start_byte();
        let prefix_end = name_node.start_byte();
        if prefix_end <= prefix_start || prefix_end > src.len() {
            continue;
        }
        let Ok(prefix) = std::str::from_utf8(&src[prefix_start..prefix_end]) else {
            continue;
        };
        let is_struct = prefix
            .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
            .any(|t| t == "struct");
        if !is_struct {
            continue;
        }
        let struct_span = span_of(file, &struct_node);
        let Some(struct_decl) = idx
            .defs
            .iter()
            .find(|d| d.span == struct_span && is_class_like(d.kind))
        else {
            continue;
        };
        let parent_sym = struct_decl.symbol;
        let module_path = struct_decl.module_path.clone();
        let visibility = struct_decl.visibility;
        let class_name = struct_decl.name.clone();
        let class_name_span = struct_decl.name_span;
        // Skip if an explicit Constructor already exists under this
        // parent (an `init` block).
        let has_explicit_init = idx
            .defs
            .iter()
            .any(|d| matches!(d.kind, DeclKind::Constructor) && d.parent == Some(parent_sym));
        if has_explicit_init {
            continue;
        }
        // Collect stored property names (skip computed properties).
        let body = first_named_child_of_kind(&struct_node, "class_body");
        let Some(body) = body else { continue };
        let mut params: Vec<(String, Span)> = Vec::new();
        let mut bw = body.walk();
        for child in body.children(&mut bw) {
            if child.kind() != "property_declaration" {
                continue;
            }
            // Skip computed properties (they have a `computed_value`
            // child) — those aren't part of the memberwise init.
            let mut pw = child.walk();
            let has_computed = child.children(&mut pw).any(|c| c.kind() == "computed_property");
            if has_computed {
                continue;
            }
            let Some(name) = swift_property_name(child, src) else {
                continue;
            };
            let span = swift_property_name_span(child, file).unwrap_or(span_of(file, &child));
            params.push((name, span));
        }
        if params.is_empty() {
            continue;
        }
        let param_names: Vec<String> = params.iter().map(|(n, _)| n.clone()).collect();
        let receiver_field_writes: Vec<FieldWrite> = params
            .iter()
            .enumerate()
            .map(|(idx, (name, span))| FieldWrite {
                span: *span,
                target: format!("self.{name}"),
                source_param_indices: vec![idx],
            })
            .collect();
        synthesized.push(Decl {
            symbol: bonsai_common::SymbolId::new(next),
            kind: DeclKind::Constructor,
            name: class_name.clone(),
            qualified_name: None,
            module_path: module_path.clone(),
            span: class_name_span,
            name_span: class_name_span,
            visibility,
            parent: Some(parent_sym),
            body_span: Some(class_name_span),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: param_names.clone(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes,
            implicit_receiver_names: vec!["self".to_string()],
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
        next += 1;
        // Synthesize a zero-arg accessor `Method` per stored property,
        // mirroring Java record accessors so `envelope.cmd()` resolves
        // to a callable that returns `self.<cmd>` — without this, the
        // synthesized computed-property pass for `Repository.cmd`
        // (whose body becomes `Call{data.cmd}`) can't dispatch to a
        // Method on `Envelope` and the chain stops at the struct boundary.
        for (name, span) in &params {
            let already = idx.defs.iter().chain(synthesized.iter()).any(|d| {
                d.parent == Some(parent_sym)
                    && d.name == *name
                    && d.params.is_empty()
                    && matches!(d.kind, DeclKind::Method | DeclKind::Function)
            });
            if already {
                continue;
            }
            let field = format!("self.{name}");
            synthesized.push(Decl {
                symbol: bonsai_common::SymbolId::new(next),
                kind: DeclKind::Method,
                name: name.clone(),
                qualified_name: None,
                module_path: module_path.clone(),
                span: *span,
                name_span: *span,
                visibility,
                parent: Some(parent_sym),
                body_span: Some(*span),
                flow_events: vec![FlowEvent::Return {
                    span: *span,
                    value_text: Some(field.clone()),
                    value_name: Some(field.clone()),
                    value_flow: bonsai_lang_api::ExpressionFlow::from_place(field.clone()),
                }],
                has_implicit_returns: false,
                params: Vec::new(),
                param_annotations: Vec::new(),
                type_aliases: Vec::new(),
                bases: Vec::new(),
                receiver_param_index: None,
                receiver_field_writes: Vec::new(),
                implicit_receiver_names: vec!["self".to_string()],
                receiver_state_sources: vec![field],
                return_type: None,
                is_variadic: false,
            });
            next += 1;
        }
    }
    idx.defs.extend(synthesized);
}

/// For each Swift Constructor decl that lacks a Return event,
/// synthesize one whose value_text is the joined params list so
/// `bridge_value_expr_to_node` tokenizes each param identifier to
/// `Place::Return`. The standard callee-Return → caller-CallRet edge
/// then propagates the args' taint onto the caller's allocation
/// target, making `repo` whole-object tainted (Java-style) — required
/// so the receiver-field bridge can fire for `repo.run()` even when
/// field-precise mode would otherwise only mark `repo.data.cmd`.
fn synthesize_swift_constructor_implicit_returns(index: &mut DeclIndex) {
    for decl in &mut index.defs {
        if !matches!(decl.kind, DeclKind::Constructor) {
            continue;
        }
        if decl
            .flow_events
            .iter()
            .any(|e| matches!(e, FlowEvent::Return { .. }))
        {
            continue;
        }
        if decl.params.is_empty() {
            continue;
        }
        let value_text = decl.params.join(" ");
        let span = decl.body_span.unwrap_or(decl.span);
        decl.flow_events.push(FlowEvent::Return {
            span,
            value_text: Some(value_text),
            value_name: None,
            value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(decl.params.clone()),
        });
    }
}

fn swift_constructor_field_params(
    index: &DeclIndex,
) -> std::collections::HashMap<String, Vec<(usize, String)>> {
    let mut out: std::collections::HashMap<String, Vec<(usize, String)>> = std::collections::HashMap::new();
    for decl in &index.defs {
        if !matches!(decl.kind, DeclKind::Constructor) || decl.receiver_field_writes.is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        for write in &decl.receiver_field_writes {
            let Some(field) = swift_receiver_field_tail(&write.target) else {
                continue;
            };
            for idx in &write.source_param_indices {
                fields.push((*idx, field.clone()));
            }
        }
        if !fields.is_empty() {
            fields.sort();
            fields.dedup();
            out.insert(decl.name.clone(), fields);
        }
    }
    out
}

fn swift_receiver_field_tail(target: &str) -> Option<String> {
    let mut parts = target.split('.').map(str::trim).filter(|part| !part.is_empty());
    let root = parts.next()?;
    if !matches!(root, "self" | "this" | "receiver") {
        return None;
    }
    parts.next().map(str::to_string)
}

fn synthesize_swift_constructor_field_assignments(
    events: &mut Vec<FlowEvent>,
    constructor_field_params: &std::collections::HashMap<String, Vec<(usize, String)>>,
) {
    let original = std::mem::take(events);
    let mut rewritten = Vec::with_capacity(original.len());
    let constructor_calls = (0..original.len())
        .map(|event_index| {
            swift_constructor_call_for_assignment_event(&original, event_index, constructor_field_params)
        })
        .collect::<Vec<_>>();
    for (event_index, mut event) in original.into_iter().enumerate() {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                synthesize_swift_constructor_field_assignments(then_events, constructor_field_params);
                synthesize_swift_constructor_field_assignments(else_events, constructor_field_params);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                synthesize_swift_constructor_field_assignments(body, constructor_field_params);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                synthesize_swift_constructor_field_assignments(body, constructor_field_params);
                synthesize_swift_constructor_field_assignments(catch_events, constructor_field_params);
                synthesize_swift_constructor_field_assignments(finally_events, constructor_field_params);
            }
            _ => {}
        }
        let mut synthetic = Vec::new();
        if let FlowEvent::Assign { span, target, .. } = &event {
            let target = target.trim();
            if !target.is_empty() && target != "_" {
                if let Some((constructor, args)) = constructor_calls[event_index].as_ref() {
                    let fields = constructor_field_params.get(constructor).into_iter().flatten();
                    for (param_idx, field) in fields {
                        let Some(arg) = args.get(*param_idx) else {
                            continue;
                        };
                        let source_names = swift_value_source_names_from_text(arg);
                        if source_names.is_empty() {
                            continue;
                        }
                        synthetic.push(FlowEvent::Assign {
                            span: *span,
                            target: format!("{target}.{field}"),
                            source_name: (source_names.len() == 1).then(|| source_names[0].clone()),
                            source_call: None,
                            source_call_args: Vec::new(),
                            source_names,
                            declares_new_binding: false,
                            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                        });
                    }
                }
            }
        }
        rewritten.push(event);
        rewritten.extend(synthetic);
    }
    *events = rewritten;
}

fn swift_constructor_call_for_assignment_event(
    events: &[FlowEvent],
    event_index: usize,
    constructor_field_params: &std::collections::HashMap<String, Vec<(usize, String)>>,
) -> Option<(String, Vec<String>)> {
    let FlowEvent::Assign {
        span,
        source_call,
        source_call_args,
        ..
    } = events.get(event_index)?
    else {
        return None;
    };
    if let Some(source_call) = source_call {
        let constructor = swift_constructor_call_tail(source_call).to_string();
        if constructor_field_params.contains_key(&constructor) {
            return Some((constructor, source_call_args.clone()));
        }
    }
    events.iter().skip(event_index + 1).find_map(|event| {
        let FlowEvent::Call {
            name,
            span: call_span,
            args,
            ..
        } = event
        else {
            return None;
        };
        if call_span.file != span.file || call_span.start < span.start || call_span.end > span.end {
            return None;
        }
        let constructor = swift_constructor_call_tail(name).to_string();
        constructor_field_params.contains_key(&constructor).then(|| {
            (
                constructor,
                args.iter().map(|arg| arg.value_text.clone()).collect(),
            )
        })
    })
}

fn swift_constructor_call_tail(call: &str) -> &str {
    call.split(['.', ':'])
        .filter(|part| !part.trim().is_empty())
        .next_back()
        .map(str::trim)
        .unwrap_or(call.trim())
}

fn swift_value_source_names_from_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let trimmed = text.trim();
    if trimmed.contains('.') && !trimmed.starts_with('.') {
        out.push(trimmed.to_string());
    }
    let mut token = String::new();
    for ch in trimmed.chars() {
        if ch == '_' || ch.is_ascii_alphanumeric() || ch == '$' {
            token.push(ch);
        } else {
            push_swift_value_token(&mut out, &token);
            token.clear();
        }
    }
    push_swift_value_token(&mut out, &token);
    out.sort();
    out.dedup();
    out
}

fn push_swift_value_token(out: &mut Vec<String>, token: &str) {
    let token = token.trim();
    if token.is_empty()
        || token == "_"
        || token.chars().all(|ch| ch.is_ascii_digit())
        || matches!(
            token,
            "true" | "false" | "nil" | "self" | "super" | "return" | "let" | "var"
        )
    {
        return;
    }
    out.push(token.to_string());
}
