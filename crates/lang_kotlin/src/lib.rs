//! Kotlin language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    collect_modifier_visibility, decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
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
const HANDLER: GrammarHandler = with_fn_kinds_and_implicit_receivers(
    &["function_declaration", "getter", "setter"],
    &["this", "super"],
    &[],
);

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
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Module path from `package com.foo.bar` declaration; falls
        // back to file-stem when absent.
        let segments = parse_with(PACK_NAME, file, ctx)
            .and_then(|(snapshot, tree)| extract_kotlin_package(tree.root_node(), snapshot.text.as_bytes()));
        if let Some(segments) = segments {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
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
        }
        // Populate Throw::thrown_type and Try::catch_types from the
        // parse tree. Done at the end so any prior post-processing
        // that mutates flow_events runs before this final enrichment.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            for decl in &mut idx.defs {
                populate_kotlin_exception_types(&mut decl.flow_events, &tree, src);
            }
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
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, KOTLIN_LIFECYCLE_TRANSITIONS);
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

/// Walk Kotlin function declarations and collect parameter
/// `name: Type` bindings as `TypeAliasBinding`. Used by the
/// resolver to narrow `[Type, method]` rule dispatch through
/// adapter facts instead of local receiver-name guesses.
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
            if node.kind() == "parameter" || node.kind() == "class_parameter" {
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
                // a name. Without this, every type-inferred property
                // is silently dropped from the class alias map.
                "variable_declaration" if name_node.is_none() => {
                    let mut inner = child.walk();
                    for grandchild in child.named_children(&mut inner) {
                        if matches!(grandchild.kind(), "simple_identifier" | "identifier") {
                            name_node = Some(grandchild);
                            break;
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
        kotlin_property_constructor_type(node, src)?
    };
    if name == type_short {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: type_short,
    })
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
