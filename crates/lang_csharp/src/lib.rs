//! C# language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{
        canonical_simple_type_name, collect_kinds, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasBinding, TypeAliasVocabulary, Visibility,
};

const CSHARP_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &[
        "method_declaration",
        "constructor_declaration",
        "local_function_statement",
    ],
    param_kinds: &["parameter"],
    name_field: "name",
    type_field: "type",
};

const CSHARP_DECL_KINDS: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "class_declaration",
    "struct_declaration",
    "interface_declaration",
    "record_declaration",
    "enum_declaration",
    "delegate_declaration",
    "property_declaration",
    "event_declaration",
    "field_declaration",
    "local_function_statement",
];

// C# default for type members is `private` and for top-level
// types it's `internal`, but applying that strictly when
// module_path is the file-stem fallback would block legitimate
// cross-file calls within the same project. Default to `Public`
// until real module_path coverage (namespace declarations) lands;
// tighten then.
const CSHARP_DEFAULT_VISIBILITY: Visibility = Visibility::Public;
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("csharp");
const PACK_NAME: &str = "csharp";
// `accessor_declaration` is C#'s property getter/setter body. Treating
// it as a function-declaration kind gives each accessor its own Decl
// with its own flow_events so taint that flows through `string X
// { get => …; set => _x = value; }` is observed end-to-end. Without
// this the property collapses into a Field decl and accessor body
// events disappear (audit task #131). `constructor_declaration` and
// `destructor_declaration` join the set so RAII / dtor flows surface.
const HANDLER: GrammarHandler = GrammarHandler {
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    ..with_fn_kinds_and_implicit_receivers(
        &[
            "method_declaration",
            "local_function_statement",
            "accessor_declaration",
            "constructor_declaration",
            "destructor_declaration",
        ],
        &["this", "base"],
        &[],
    )
};

#[derive(Debug, Default, Copy, Clone)]
pub struct CSharpAdapter;

impl CSharpAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for CSharpAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "C#"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.csx` is C#'s script / interactive form — same grammar and
        // lookup semantics apply.
        &["cs", "csx"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Exceptions: the adapter populates `Throw::thrown_type` from
        // `throw new IOException(...)` and `Try::catch_types` from
        // `catch (IOException e)`. Catch-all `catch { }` arms produce
        // an empty `catch_types` and the engine falls back to the
        // conservative seed-on-any-tainted-throw behavior.
        LanguageCapabilities {
            exceptions: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &["base"],
            implicit_receiver_tokens: &["this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `T Method() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            for decl in &mut idx.defs {
                populate_csharp_exception_types(&mut decl.flow_events, &tree, src);
            }
        }
        let pkg = parse_with(PACK_NAME, file, ctx).and_then(|(snapshot, tree)| {
            extract_csharp_namespace(tree.root_node(), snapshot.text.as_bytes())
        });
        if let Some(segments) = pkg {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_csharp_visibility(tree.root_node(), file, src);
            let alias_map = collect_param_type_aliases(&tree, file, src, &CSHARP_TYPE_ALIASES);
            // Class-level field/property type bindings extend each
            // method's `type_aliases`. A field declared as `private
            // readonly AuthService _authService = new AuthService();`
            // must be visible inside the class's methods so receiver
            // calls like `_authService.RunAdminCommand(...)` resolve
            // through the workspace's `AuthService` decl. The
            // class-scoped collection mirrors Java's pattern in
            // `lang_java` and applies symmetrically to property
            // declarations (`public Foo Bar { get; set; }` carries
            // the same `Bar : Foo` binding).
            let class_field_aliases = collect_csharp_class_field_aliases(&tree, file, src);
            // Pre-compute the parent class span for each method-like
            // decl so the per-decl pass below can patch `type_aliases`
            // without re-borrowing `idx.defs` while it's already
            // mutably borrowed.
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
            }
            // Per-class `bases`: `class Echo : Base, IFoo` → ["Base", "IFoo"].
            // C# uses a single `base_list` for both class super and
            // interface impls — they're indistinguishable in syntax.
            let bases_by_span = collect_csharp_class_bases(&tree, file, src);
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
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, CSHARP_LIFECYCLE_TRANSITIONS);
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

/// C# lifecycle transitions: IDisposable / CancellationTokenSource / lock release.
const CSHARP_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
    bonsai_lang_api::LifecycleTransition {
        call_match: "Dispose",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "DisposeAsync",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Close",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Cancel",
        transition: "cancelled",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Release",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "ReleaseMutex",
        transition: "unlocked",
        arg_index: 0,
    },
];

/// Lift every `using_directive` into an `ImportSpec`. C# splits the
/// alias out of the path: `using IO = System.IO` exposes `IO` as
/// `name:` and `System.IO` as the trailing qualified path child.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // `using_directive` shapes:
    //   `using System.Data;`              → qualified_name only
    //   `using static System.Math;`       → qualified_name (with `static` keyword)
    //   `using IO = System.IO;`           → name: identifier (alias) + qualified_name
    for using_node in collect_kinds(tree, &["using_directive"]) {
        let mut child_cursor = using_node.walk();
        // The path is the *last* qualified_name / identifier child that
        // isn't the alias `name:` field — this is the only shape that
        // works across all three forms above.
        let mut last_path: Option<tree_sitter::Node<'_>> = None;
        for child in using_node.named_children(&mut child_cursor) {
            if matches!(child.kind(), "qualified_name" | "identifier")
                && Some(child) != using_node.child_by_field_name("name")
            {
                last_path = Some(child);
            }
        }
        let Some(path_node) = last_path.or_else(|| using_node.child_by_field_name("name")) else {
            continue;
        };
        let module = node_text(&path_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        let alias = using_node
            .child_by_field_name("name")
            .map(|alias_node| node_text(&alias_node, src).to_string());
        imports.push(ImportSpec {
            span: span_of(file, &using_node),
            module: module.clone(),
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if csharp_using_is_static(&using_node, src) {
            imports.push(ImportSpec {
                span: span_of(file, &using_node),
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

fn csharp_using_is_static(using_node: &tree_sitter::Node<'_>, src: &[u8]) -> bool {
    node_text(using_node, src)
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .windows(2)
        .any(|window| window == ["using", "static"])
}

/// Walk every C# class-like declaration and pull `(name, type)`
/// bindings from its `field_declaration` and `property_declaration`
/// children. Returns `(class_span, [TypeAliasBinding])` so the
/// per-method merge can attach a class's bindings to every method
/// nested inside it, matching the resolver's caller-decl
/// `type_aliases` lookup contract.
fn collect_csharp_class_field_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let class_kinds = &[
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "record_struct_declaration",
        "interface_declaration",
    ];
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![class_node];
        while let Some(node) = work.pop() {
            // Don't descend into nested classes — their own iteration
            // produces the right scope for their methods. A nested
            // class's fields are visible only to its own methods, not
            // the outer class's methods.
            if node != class_node && class_kinds.contains(&node.kind()) {
                continue;
            }
            match node.kind() {
                "field_declaration" | "event_field_declaration" => {
                    extend_aliases_from_field_or_event(node, src, &mut aliases);
                }
                "property_declaration" => {
                    if let Some(binding) = property_alias_from_node(node, src) {
                        if !aliases.contains(&binding) {
                            aliases.push(binding);
                        }
                    }
                }
                _ => {}
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

fn extend_aliases_from_field_or_event(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    // C# `field_declaration` wraps a `variable_declaration` whose
    // `type` field carries the field type and whose
    // `variable_declarator` children name each binding. Multi-name
    // forms (`Foo a, b, c;`) are valid for value-type fields.
    let var_decl = node.child_by_field_name("declaration").or_else(|| {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.named_children(&mut cursor) {
            if child.kind() == "variable_declaration" {
                found = Some(child);
                break;
            }
        }
        found
    });
    let Some(var_decl) = var_decl else {
        return;
    };
    let Some(type_node) = var_decl.child_by_field_name("type") else {
        return;
    };
    let canonical = canonical_simple_type_name(node_text(&type_node, src));
    if canonical.is_empty() {
        return;
    }
    let mut cursor = var_decl.walk();
    for declarator in var_decl.named_children(&mut cursor) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let name_node = declarator.child_by_field_name("name").or_else(|| {
            let mut inner = declarator.walk();
            let mut found = None;
            for child in declarator.named_children(&mut inner) {
                if child.kind() == "identifier" {
                    found = Some(child);
                    break;
                }
            }
            found
        });
        let Some(name_node) = name_node else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() || name == canonical {
            continue;
        }
        let binding = TypeAliasBinding {
            name,
            type_name: canonical.clone(),
        };
        if !aliases.contains(&binding) {
            aliases.push(binding);
        }
    }
}

fn property_alias_from_node(node: tree_sitter::Node<'_>, src: &[u8]) -> Option<TypeAliasBinding> {
    let type_node = node.child_by_field_name("type")?;
    let canonical = canonical_simple_type_name(node_text(&type_node, src));
    if canonical.is_empty() {
        return None;
    }
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() || name == canonical {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: canonical,
    })
}

/// C#-aware visibility collector.
///
/// Differs from the generic `collect_modifier_visibility` helper in
/// that it recognises the compound forms `protected internal` (broader
/// than either alone — caller is in the same assembly OR is a derived
/// class anywhere) and `private protected` (narrower — derived classes
/// in the same assembly only). Maps to the four-level lattice in
/// `Visibility` as follows:
///
/// - `private`            → `Private`
/// - `private protected`  → `Protected` (assembly-bounded but derived-callable)
/// - `protected`          → `Protected`
/// - `protected internal` → `Crate` (visible to whole assembly)
/// - `internal`           → `Crate`
/// - `public`             → `Public`
///
/// Visibility comes from real syntax markers; per-language
/// compound-modifier handling lives in the adapter.
fn collect_csharp_visibility(
    root: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut visibility_by_span = std::collections::HashMap::new();
    // Iterative DFS over the whole tree. Every CSHARP_DECL_KINDS node
    // contributes one entry; nested classes / nested local functions
    // each get their own.
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        if CSHARP_DECL_KINDS.contains(&node.kind()) {
            visibility_by_span.insert(span_of(file, &node), csharp_node_visibility(node, src));
        }
        let mut child_cursor = node.walk();
        for child in node.children(&mut child_cursor) {
            work_stack.push(child);
        }
    }
    visibility_by_span
}

/// Resolve a single decl's visibility from its `modifier` children.
/// Compound forms (`protected internal`, `private protected`) are
/// distinct visibility levels in C# that don't map 1:1 to either side.
fn csharp_node_visibility(node: tree_sitter::Node<'_>, src: &[u8]) -> Visibility {
    let mut keywords: Vec<&str> = Vec::new();
    let mut child_cursor = node.walk();
    for child in node.children(&mut child_cursor) {
        if child.kind() == "modifier" {
            let text = node_text(&child, src);
            if matches!(text, "private" | "protected" | "internal" | "public") {
                keywords.push(text);
            }
        }
    }
    let has_private = keywords.contains(&"private");
    let has_protected = keywords.contains(&"protected");
    let has_internal = keywords.contains(&"internal");
    let has_public = keywords.contains(&"public");
    // `public` always wins — C# doesn't allow it to combine with the
    // other access modifiers.
    if has_public {
        return Visibility::Public;
    }
    if has_protected && has_internal {
        // `protected internal` — accessible in the whole assembly +
        // derived classes outside. Closest in the four-level lattice
        // is `Crate` (assembly-wide).
        return Visibility::Crate;
    }
    if has_private && has_protected {
        // `private protected` — derived classes in the same assembly
        // only. Closer to `Protected` than `Private` for resolver
        // narrowing purposes; assembly-bounded narrowing is the
        // module_path filter applied separately.
        return Visibility::Protected;
    }
    if has_protected {
        return Visibility::Protected;
    }
    if has_internal {
        return Visibility::Crate;
    }
    if has_private {
        return Visibility::Private;
    }
    CSHARP_DEFAULT_VISIBILITY
}

/// True for decl kinds that can carry a `bases` list (class super /
/// interface impl). Shared with the post-processing loop that copies
/// `bases_by_span` onto matching decls.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk C# class / struct / record / interface declarations and
/// pull bare base type names from `base_list`. Grammar shape:
///
///   `class Echo : Base, IFoo, IBar { ... }` →
///     (class_declaration name: (identifier)
///        (base_list (identifier) (identifier) (identifier))
///        body: ...)
///
/// The `base_list` lists both the parent class and any implemented
/// interfaces in source order; C# does not distinguish them
/// syntactically. Generic / qualified bases collapse to the bare tail.
fn collect_csharp_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_table = Vec::new();
    let class_kinds = &[
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "record_struct_declaration",
        "interface_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for child in class_node.named_children(&mut class_cursor) {
            if child.kind() != "base_list" {
                continue;
            }
            let mut entry_cursor = child.walk();
            for entry in child.named_children(&mut entry_cursor) {
                let raw = node_text(&entry, src);
                if let Some(name) = canonical_csharp_base_name(raw) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_table.push((span_of(file, &class_node), bases));
        }
    }
    bases_table
}

/// Strip a base entry down to the bare type name. Drops generic
/// parameters (`Foo<T>` -> `Foo`) and namespace qualification
/// (`System.IO.Stream` -> `Stream`); the resolver keys on bare names.
fn canonical_csharp_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let head = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Walk `decl.flow_events` recursively and populate
/// `Throw::thrown_type` / `Try::catch_types` from the C# parse tree.
/// C# syntax:
///   throw new IOException("...")  → thrown_type: "IOException"
///   throw err                     → thrown_type: None (need data-flow)
///   `try { } catch (IOException e) { } catch (FormatException e) { }`
///                                 → `catch_types = vec!["IOException", "FormatException"]`
///   `try { } catch { }`           → `catch_types = vec![]` (catch-all)
fn populate_csharp_exception_types(
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
                    &["throw_statement", "throw_expression"],
                ) {
                    if let Some(name) = csharp_thrown_type_for_node(node, src) {
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
                catch_param,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if catch_types.is_empty() {
                        *catch_types = collect_csharp_catch_types(node, src);
                    }
                    // The kit's generic catch_param extractor picks the
                    // type identifier (or qualified type) on C#'s
                    // `catch (T name)` shape. Fix in the adapter where
                    // we have the structural context.
                    if let Some(name) = collect_csharp_catch_param_name(node, src) {
                        *catch_param = Some(name);
                    }
                }
                populate_csharp_exception_types(body, tree, src);
                populate_csharp_exception_types(catch_events, tree, src);
                populate_csharp_exception_types(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                populate_csharp_exception_types(then_events, tree, src);
                populate_csharp_exception_types(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                populate_csharp_exception_types(body, tree, src);
            }
            _ => {}
        }
    }
}

/// Pull the constructor type out of `throw new Foo(...)`. Returns
/// `None` for re-throws (`throw e`), where the thrown type is whatever
/// data-flow eventually proves about `e` — beyond syntactic reach.
fn csharp_thrown_type_for_node(throw_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    // throw_statement > object_creation_expression > identifier (or qualified_name)
    let mut throw_cursor = throw_node.walk();
    for child in throw_node.named_children(&mut throw_cursor) {
        if child.kind() == "object_creation_expression" {
            // Newer grammar releases expose the type via the `type:` field.
            if let Some(type_node) = child.child_by_field_name("type") {
                return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                    &type_node, src,
                )));
            }
            // Older releases inline the identifier as a named child.
            let mut type_cursor = child.walk();
            for descendant in child.named_children(&mut type_cursor) {
                if matches!(
                    descendant.kind(),
                    "identifier" | "qualified_name" | "generic_name"
                ) {
                    return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                        &descendant,
                        src,
                    )));
                }
            }
        }
    }
    None
}

/// Pull the binding name out of `catch (T name)`. Returns `None` for
/// catch-all (`catch { }`) and for catch declarations that omit the
/// name (`catch (T) { }` — unusual but legal in C#).
fn collect_csharp_catch_param_name(try_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut try_cursor = try_node.walk();
    for child in try_node.named_children(&mut try_cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        let mut clause_cursor = child.walk();
        for sub in child.named_children(&mut clause_cursor) {
            if sub.kind() != "catch_declaration" {
                continue;
            }
            // The `name` field is the binding identifier; the `type`
            // field is the exception type.
            if let Some(name_node) = sub.child_by_field_name("name") {
                return Some(node_text(&name_node, src).trim().to_string());
            }
            // Fallback: rightmost named identifier after the type.
            let mut pcur = sub.walk();
            let mut last_ident: Option<tree_sitter::Node<'_>> = None;
            for n in sub.named_children(&mut pcur) {
                if n.kind() == "identifier" {
                    last_ident = Some(n);
                }
            }
            if let Some(n) = last_ident {
                return Some(node_text(&n, src).trim().to_string());
            }
        }
    }
    None
}

/// Collect the `catch (T e)` types in source order. Catch-all (`catch
/// { }`) is omitted — the engine's seed-on-any-throw path handles it.
fn collect_csharp_catch_types(try_node: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut catch_types: Vec<String> = Vec::new();
    let mut try_cursor = try_node.walk();
    for child in try_node.named_children(&mut try_cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        // catch_clause > catch_declaration > type
        let mut clause_cursor = child.walk();
        for sub in child.named_children(&mut clause_cursor) {
            if sub.kind() != "catch_declaration" {
                continue;
            }
            if let Some(type_node) = sub.child_by_field_name("type") {
                let name = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&type_node, src));
                if !name.is_empty() && !catch_types.iter().any(|existing| existing == &name) {
                    catch_types.push(name);
                }
            }
        }
    }
    catch_types
}

/// Find the file's top-level `namespace` declaration and return its
/// dotted segments. Both block-form (`namespace Foo.Bar { ... }`) and
/// file-scoped (`namespace Foo.Bar;`) shapes resolve identically.
fn extract_csharp_namespace(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut child_cursor = root.walk();
    for child in root.children(&mut child_cursor) {
        if !matches!(
            child.kind(),
            "namespace_declaration" | "file_scoped_namespace_declaration"
        ) {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            let text = node_text(&name_node, src);
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
    None
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
