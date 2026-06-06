//! TypeScript language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    collect_modifier_visibility, collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, ModifierVocabulary, TypeAliasVocabulary, Visibility,
};
use tree_sitter::Node;

const TYPESCRIPT_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_declaration", "method_definition", "method_signature"],
    param_kinds: &["required_parameter", "optional_parameter"],
    name_field: "pattern",
    type_field: "type",
};

const TYPESCRIPT_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "method_definition",
        "method_signature",
        "public_field_definition",
        "abstract_method_signature",
    ],
    modifier_container_kinds: &["accessibility_modifier"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("protected", Visibility::Protected),
        ("public", Visibility::Public),
    ],
    // TypeScript's default class-member visibility is `public`.
    default_visibility: Visibility::Public,
};
use bonsai_lang_javascript::{
    apply_javascript_getter_property_sources, apply_js_ts_commonjs_named_export_aliases,
    apply_js_ts_default_export_aliases, js_ts_imports, js_ts_require_calls,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("typescript");
const PACK_NAME: &str = "typescript";
const HANDLER: GrammarHandler = GrammarHandler {
    call_kinds: &["new_expression"],
    constructor_names: &["constructor"],
    // TypeScript exposes `abstract class Foo` under
    // `abstract_class_declaration` — the GENERIC_HANDLER default
    // only covers `class_declaration`, so without this override
    // abstract base classes are missed at decl-emission time, and
    // every subclass ends up with `decl.parent = None`. That
    // breaks Phase 3c/3d field-flow stitching: the inheritance
    // walk has no class to attach `BaseRepository` to.
    class_kinds: &[
        "class_declaration",
        "abstract_class_declaration",
        "interface_declaration",
    ],
    ..with_fn_kinds_and_implicit_receivers(
        &[
            "function_declaration",
            "method_definition",
            "method_signature",
            // Generator forms.
            "generator_function_declaration",
            "generator_function",
        ],
        &["this"],
        &[],
    )
};

#[derive(Debug, Default, Copy, Clone)]
pub struct TypeScriptAdapter;

impl TypeScriptAdapter {
    /// Construct a fresh adapter. Stateless; cheap to copy.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for TypeScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "TypeScript"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ts", "tsx"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_export_aliases: &["exports", "module.exports"],
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: &["constructor"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            apply_js_ts_commonjs_named_export_aliases(&mut decl_index, &tree, snapshot.text.as_bytes(), file);
        }
        // TS/JS module = workspace-relative file path with `.ts`/`.tsx` (etc.) stripped.
        let module_segments = ctx
            .workspace_relative_path(file)
            .map(|p| js_module_segments(&p))
            .unwrap_or_default();
        if !module_segments.is_empty() {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut decl_index, module_segments);
        } else {
            // Fall back to the file stem when the workspace root is unknown.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            apply_js_ts_default_export_aliases(&mut decl_index, &tree, src, file);
            // Phase-6 return-type extraction: `function f(): T {}` / `(): T => ...`
            // populates `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, &tree, src, &HANDLER);
            // Visibility from `public/protected/private` keywords, and parameter type aliases.
            let visibility_by_span =
                collect_modifier_visibility(tree.root_node(), file, src, &TYPESCRIPT_VOCAB);
            let type_aliases_by_span = collect_param_type_aliases(&tree, file, src, &TYPESCRIPT_TYPE_ALIASES);
            for decl in &mut decl_index.defs {
                if let Some(vis) = visibility_by_span.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                if let Some(aliases) = type_aliases_by_span.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
            }
            // ECMAScript `#name` private fields/methods are syntactically marked.
            for decl in &mut decl_index.defs {
                if decl.name.starts_with('#') {
                    decl.visibility = Visibility::Private;
                }
            }
            // Per-class `bases`: `class Echo extends WebSocketHandler implements Mixin { ... }`
            // becomes `["WebSocketHandler", "Mixin"]`. The TS grammar groups extends +
            // implements under a `class_heritage` child of the class.
            let bases_by_span = collect_typescript_class_bases(&tree, file, src);
            for decl in &mut decl_index.defs {
                // Bases only make sense on type-defining declarations.
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
            apply_javascript_getter_property_sources(&mut decl_index, &tree, src, file);
        }
        // Recognised TypeScript lifecycle transitions — same call
        // names as JavaScript since TS shares the JS runtime surface.
        const TYPESCRIPT_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "destroy",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "abort",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "unsubscribe",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "release",
                transition: "unlocked",
                arg_index: 0,
            },
        ];
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, TYPESCRIPT_LIFECYCLE_TRANSITIONS);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Combine ES-module imports, CommonJS `require(...)` calls, and the
/// TypeScript-only `import x = require("y")` legacy form. Delegates to
/// the JS helpers so the two adapters cannot drift on import semantics.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = js_ts_imports(file, tree, src);
    // Dedup against `import_alias`: the JS helper sees an anonymous `require("y")`
    // and would emit `alias=None` for the same module the TS-specific pass below
    // emits with `alias=Some("x")`.
    let mut require_calls = js_ts_require_calls(file, tree, src);
    let alias_call_spans = ts_import_alias_call_spans(tree);
    require_calls.retain(|spec| !span_inside_any(spec.span, &alias_call_spans));
    imports.extend(require_calls);
    // `import x = require("y")` — TS legacy form. tree-sitter-typescript wraps it
    // in `import_alias` (not `import_statement`), so the JS helper never sees it.
    imports.extend(parse_ts_import_alias(file, tree, src));
    imports
}

/// Return the byte spans of every `call_expression` that lives
/// inside an `import_alias` node. Used to dedup the JS helper's
/// anonymous emission against the TS-specific aliased emission.
fn ts_import_alias_call_spans(tree: &Tree) -> Vec<(u32, u32)> {
    let mut alias_call_spans = Vec::new();
    for alias_node in collect_kinds(tree, &["import_alias"]) {
        let mut stack = vec![alias_node];
        while let Some(current) = stack.pop() {
            if current.kind() == "call_expression" {
                let start = current.start_byte() as u32;
                let end = current.end_byte() as u32;
                alias_call_spans.push((start, end));
            }
            // Descend even past `call_expression` — nested forms are rare but possible.
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    alias_call_spans
}

/// True when `span` is byte-contained within any of the given ranges.
/// Used to suppress duplicate require-call imports that already have an
/// `import_alias` entry above them.
fn span_inside_any(span: bonsai_common::Span, ranges: &[(u32, u32)]) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| span.start >= u64::from(start) && span.end <= u64::from(end))
}

/// Parse TypeScript-only `import x = require("y")` statements. The
/// grammar wraps these in `import_alias` nodes whose `name` field
/// holds `x` and whose `value` field is a call to `require` with a
/// single string argument. Emits a single Module-scope ImportSpec
/// with `alias = Some("x")` so resolve sees `x` as an alias for
/// the `y` module.
fn parse_ts_import_alias(file: FileId, tree: &Tree, src: &[u8]) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for alias_node in collect_kinds(tree, &["import_alias"]) {
        let local_alias = alias_node
            .child_by_field_name("name")
            .map(|name_node| node_text(&name_node, src).to_string());
        // Prefer the documented `value` field; fall back to the first `call_expression`
        // named child to tolerate grammar revisions that expose the require call differently.
        let value_node = alias_node.child_by_field_name("value").or_else(|| {
            let mut cursor = alias_node.walk();
            // Bind explicitly so the cursor outlives the iterator return.
            let found = alias_node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "call_expression");
            found
        });
        let Some(value_node) = value_node else { continue };
        // The value is typically `require("...")`; pull the module path from the first string.
        let module = first_named_child_of_kind(&value_node, "string")
            .and_then(|string_node| first_named_child_of_kind(&string_node, "string_fragment"))
            .map(|fragment| node_text(&fragment, src).to_string())
            .unwrap_or_else(|| {
                // Fallback: walk for any `string_fragment` descendant. Rare, but covers
                // grammars that nest the literal under different node kinds.
                let mut stack = vec![value_node];
                while let Some(current) = stack.pop() {
                    if current.kind() == "string_fragment" {
                        return node_text(&current, src).to_string();
                    }
                    let mut cursor = current.walk();
                    for child in current.named_children(&mut cursor) {
                        stack.push(child);
                    }
                }
                String::new()
            });
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &alias_node),
            module,
            alias: local_alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Whether a declaration kind can carry a base list (`extends` / `implements`).
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk TS class / interface / abstract-class declarations and
/// collect bare base type names. Grammar shape:
///
///   `class Echo extends WebSocketHandler implements Mixin { ... }` →
///     (class_declaration name: (type_identifier)
///        (class_heritage
///           (extends_clause value: (identifier))
///           (implements_clause (type_identifier))))
///
/// `interface_declaration` uses `extends_type_clause` (multiple
/// type identifiers under one wrapper) instead of `class_heritage`.
fn collect_typescript_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &[
        "class_declaration",
        "abstract_class_declaration",
        "class",
        "interface_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for class_child in class_node.named_children(&mut class_cursor) {
            match class_child.kind() {
                // Class wrapper containing both `extends_clause` and `implements_clause`.
                "class_heritage" => {
                    collect_ts_heritage_names(class_child, src, &mut bases);
                }
                // `interface_declaration` and direct `extends_clause` children.
                "extends_type_clause" | "extends_clause" => {
                    collect_ts_heritage_names(class_child, src, &mut bases);
                }
                _ => {}
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Walk a TS heritage wrapper (class_heritage / extends_clause /
/// implements_clause / extends_type_clause) and pick out every
/// identifier-like base name. Generics → leftmost name.
fn collect_ts_heritage_names(node: Node<'_>, src: &[u8], collected_bases: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            // Wrapper kinds — descend; the actual identifier is one or more levels down.
            "extends_clause" | "implements_clause" | "extends_type_clause" | "class_heritage" => {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
            "identifier" | "type_identifier" => {
                if let Some(name) = canonical_ts_base_name(node_text(&current, src)) {
                    if !collected_bases.iter().any(|b| b == &name) {
                        collected_bases.push(name);
                    }
                }
            }
            "generic_type" => {
                // `Foo<T>` — keep `Foo` and skip `type_arguments` entirely so we
                // don't accidentally collect `T` as a base.
                if let Some(name_child) = current.child_by_field_name("name") {
                    if let Some(name) = canonical_ts_base_name(node_text(&name_child, src)) {
                        if !collected_bases.iter().any(|b| b == &name) {
                            collected_bases.push(name);
                        }
                    }
                } else {
                    // Fallback for grammars without the `name` field: take the
                    // first identifier-like child and stop.
                    let mut cursor = current.walk();
                    for child in current.named_children(&mut cursor) {
                        if matches!(child.kind(), "identifier" | "type_identifier") {
                            if let Some(name) = canonical_ts_base_name(node_text(&child, src)) {
                                if !collected_bases.iter().any(|b| b == &name) {
                                    collected_bases.push(name);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            "nested_type_identifier" | "nested_identifier" => {
                // `Foo.Bar` — `canonical_ts_base_name` keeps only the right-most segment.
                if let Some(name) = canonical_ts_base_name(node_text(&current, src)) {
                    if !collected_bases.iter().any(|b| b == &name) {
                        collected_bases.push(name);
                    }
                }
            }
            _ => {
                // Unknown wrapper — keep descending; we'd rather over-walk than miss a base.
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}

/// Reduce a heritage type expression to a bare class/interface name:
/// strips generics (`Foo<T>` -> `Foo`) and nested-type prefixes
/// (`mod.Foo` -> `Foo`). Returns `None` if nothing usable remains.
fn canonical_ts_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Drop generic argument list before any path split — `mod.Foo<T>` should yield `Foo`.
    let without_generics = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let bare = without_generics
        .rsplit('.')
        .next()
        .unwrap_or(without_generics)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Split a workspace-relative TS/JS path into module-identity segments.
/// The trailing source extension is stripped so `src/utils/log.ts` becomes
/// `["src", "utils", "log"]`. Skips path roots and parent (`..`) components.
fn js_module_segments(path: &std::path::Path) -> Vec<String> {
    let mut segments: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if let Some(last_segment) = segments.last_mut() {
        // Strip exactly one source extension; `.tsx` is checked before `.ts`.
        for extension in [".tsx", ".ts", ".jsx", ".js", ".mjs", ".cjs"] {
            if last_segment.ends_with(extension) {
                *last_segment = last_segment.trim_end_matches(extension).to_string();
                break;
            }
        }
    }
    segments.retain(|segment| !segment.is_empty());
    segments
}
