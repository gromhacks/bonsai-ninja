//! Swift language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_modifier_visibility, collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, ModifierVocabulary, TypeAliasBinding,
    TypeAliasVocabulary, Visibility,
};
use tree_sitter::Node;

const SWIFT_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_declaration", "init_declaration"],
    param_kinds: &["parameter"],
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
        ("internal", Visibility::Crate),
        ("public", Visibility::Public),
        ("open", Visibility::Public),
    ],
    // Swift's true default is `internal` (visible across the same
    // module), but until adapter coverage emits a real module_path
    // from `import` / `Package.swift` data, we'd over-restrict
    // cross-file calls inside the same module. Default to `Public`
    // so the resolver behaves correctly under file-stem-fallback
    // module_path. Tighten to `Crate` once real module_path lands
    // for Swift.
    default_visibility: Visibility::Public,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("swift");
const PACK_NAME: &str = "swift";
const HANDLER: GrammarHandler =
    with_fn_kinds_and_implicit_receivers(&["function_declaration"], &["self", "super"], &[]);

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
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let arm_spans = collect_swift_switch_arm_spans(&tree, src, file);
            for decl in &mut idx.defs {
                bonsai_lang_api::kit::split_match_arms_in_branch_events(&mut decl.flow_events, &arm_spans);
            }
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_modifier_visibility(tree.root_node(), file, src, &SWIFT_VOCAB);
            let alias_map = collect_param_type_aliases(&tree, file, src, &SWIFT_TYPE_ALIASES);
            // Class-level property type bindings — `let
            // authService = AuthService()` makes `authService :
            // AuthService` available inside every method of the
            // enclosing class so receiver dispatch reaches the real
            // method decl.
            let class_field_aliases = collect_swift_class_field_aliases(&tree, file, src);
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
        for decl in &mut idx.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, SWIFT_LIFECYCLE_TRANSITIONS);
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
        let text = node_text(&import_node, src).trim_start_matches("import ").trim();
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
