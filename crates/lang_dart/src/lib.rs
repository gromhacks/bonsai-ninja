//! Dart language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasBinding, Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("dart");
const PACK_NAME: &str = "dart";

// Dart (tree-sitter-dart UserNobody14) handler. Function bodies live in
// a sibling `function_body` of the signature (kit's body fallback finds
// it via the parent chain). Class methods wrap the signature in a
// `method_signature` — we index only the inner signature to avoid
// double-counting. Calls in Dart use the unique split-grammar pattern
// `identifier selector(args)`; the walker has a Dart-specific branch
// that synthesizes a Call event from the previous-sibling identifier.
const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &[
        "function_signature",
        "getter_signature",
        "setter_signature",
        "constructor_signature",
        "factory_constructor_signature",
    ],
    class_kinds: &[
        "class_definition",
        "mixin_declaration",
        "extension_declaration",
        "enum_declaration",
    ],
    method_kinds: &["method_signature"],
    method_context_kinds: &["class_definition", "mixin_declaration", "extension_declaration"],
    constructor_method_kinds: &["constructor_signature", "factory_constructor_signature"],
    constructor_names: &[],
    if_kinds: &["if_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &[],
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    loop_kinds: &[],
    call_kinds: &[],
    assignment_kinds: &["assignment_expression", "initialized_variable_definition"],
    return_kinds: &["return_statement"],
    throw_kinds: &["throw_expression"],
    lambda_kinds: &["function_expression", "lambda_expression"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    yield_kinds: &["yield_statement"],
    await_kinds: &["await_expression"],
    defer_kinds: &[],
    using_kinds: &[],
    method_receiver_param_index: None,
    implicit_receiver_names: &["this", "super"],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct DartAdapter;

impl DartAdapter {
    /// Construct a stateless Dart adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for DartAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Dart"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["dart"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        // Dart privacy is name-based: `_`-prefixed identifiers are
        // library-private (Visibility::Module).
        for decl in &mut decl_index.defs {
            if decl.name.starts_with('_') {
                decl.visibility = Visibility::Module;
            }
        }
        // Per-decl `type_aliases` from typed parameters
        // (`String name`, `HttpClient client`). Brings Dart in
        // lockstep with Java/Kotlin/Scala/TS/C#/Swift/Rust/Python so
        // `attribute: [HttpClient, getUrl]`-style rules can resolve
        // `client.getUrl(...)` semantically per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let source_bytes = snapshot.text.as_bytes();
            let aliases_by_span = collect_dart_method_type_aliases(&tree, file, source_bytes);
            for decl in &mut decl_index.defs {
                if let Some(aliases) = aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
                {
                    decl.type_aliases = aliases.clone();
                }
            }
            // Per-class `bases`: `class Echo extends WebSocketHandler with M implements I`
            // → ["WebSocketHandler", "M", "I"]. Dart wraps the parent
            // class under `superclass:` (which can also embed a
            // `mixins` sibling carrying `with` clauses) and lists
            // `interfaces:` separately.
            let bases_by_span = collect_dart_class_bases(&tree, file, source_bytes);
            for decl in &mut decl_index.defs {
                if !is_class_like(decl.kind) {
                    continue;
                }
                // Match by exact span first; fall back to name to handle
                // cases where the decl span differs from the class node.
                if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
            }
        }
        // Recognised Dart lifecycle transitions — `close` for streams /
        // sinks / files, `cancel` for stream subscriptions and timers,
        // `dispose` for `ChangeNotifier`/`AnimationController`-style
        // resources whose freed state is observable.
        const DART_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
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
            bonsai_lang_api::LifecycleTransition {
                call_match: "dispose",
                transition: "freed",
                arg_index: 0,
            },
        ];
        for decl in &mut decl_index.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, DART_LIFECYCLE_TRANSITIONS);
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

/// Extract Dart `import` directives into the canonical `ImportSpec` shape
/// used by the matcher index.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Dart's `import 'pkg:foo/bar.dart' as x show A, B;` parses as
    //   import_or_export
    //     library_import
    //       import_specification
    //         configurable_uri > uri > string_literal "'pkg:...'"
    //         identifier "x"               <- alias (optional)
    for import_node in collect_kinds(tree, &["import_or_export"]) {
        let Some(import_spec) = first_named_child_of_kind(&import_node, "library_import")
            .and_then(|library_import| first_named_child_of_kind(&library_import, "import_specification"))
        else {
            continue;
        };
        let Some(uri_node) = first_named_child_of_kind(&import_spec, "configurable_uri")
            .and_then(|configurable_uri| first_named_child_of_kind(&configurable_uri, "uri"))
            .and_then(|uri| first_named_child_of_kind(&uri, "string_literal"))
        else {
            continue;
        };
        // Dart import URIs come in three flavours:
        //   1. `package:foo/foo.dart` — pub package; canonical name is `foo`.
        //   2. `dart:io` — core library; canonical name is `dart:io`.
        //   3. `relative.dart` — local file; pass through unchanged.
        // Strip the `package:` prefix so the matcher's import-index
        // sees the package name (`foo/foo.dart` → first-segment
        // `foo`) instead of being shadowed by the `package:` scheme.
        // Without this strip, `pkg::import_matches_package(needle="foo",
        // module="package:foo/foo.dart")` is false (no prefix match
        // against the leading `package:` literal).
        let raw_uri = node_text(&uri_node, src).trim_matches(|ch: char| matches!(ch, '\'' | '"'));
        let module = raw_uri.strip_prefix("package:").unwrap_or(raw_uri).to_string();
        // The optional `as x` alias appears as the first identifier
        // child of the import specification.
        let mut spec_cursor = import_spec.walk();
        let alias = import_spec
            .named_children(&mut spec_cursor)
            .find(|child| child.kind() == "identifier")
            .map(|alias_node| node_text(&alias_node, src).to_string());
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module,
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

/// Walk every Dart function/method body once and record the
/// parameter type-alias bindings. Tree-sitter-dart names function
/// declarations as `function_signature` / `getter_signature` /
/// `setter_signature` / `method_signature` and class constructors
/// as `constructor_signature`; each carries a `formal_parameter_list`
/// with `formal_parameter` / `normal_formal_parameter` /
/// `simple_formal_parameter` children.
fn collect_dart_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut aliases_per_signature = Vec::new();
    for signature_node in collect_kinds(
        tree,
        &[
            "function_signature",
            "getter_signature",
            "setter_signature",
            "method_signature",
            "constructor_signature",
            "factory_constructor_signature",
        ],
    ) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut signature_cursor = signature_node.walk();
        for child in signature_node.named_children(&mut signature_cursor) {
            if child.kind() == "formal_parameter_list" {
                collect_dart_parameter_aliases(child, src, &mut aliases);
            }
        }
        dedup_dart_type_aliases(&mut aliases);
        if !aliases.is_empty() {
            aliases_per_signature.push((span_of(file, &signature_node), aliases));
        }
    }
    aliases_per_signature
}

/// Recurse through a Dart `formal_parameter_list` and emit a type-alias
/// binding for each typed parameter we can identify.
fn collect_dart_parameter_aliases(
    parameter_list_node: Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    let mut cursor = parameter_list_node.walk();
    for child in parameter_list_node.named_children(&mut cursor) {
        match child.kind() {
            "formal_parameter"
            | "normal_formal_parameter"
            | "simple_formal_parameter"
            | "default_formal_parameter"
            | "default_named_parameter" => {
                dart_typed_parameter_alias(child, src, aliases);
            }
            // Recurse for grouped parameter lists (`{a, b}`, `[a, b]`).
            _ => collect_dart_parameter_aliases(child, src, aliases),
        }
    }
}

/// Pull the `(binding, declared type)` pair out of a single Dart formal
/// parameter node. Best-effort: many parameter shapes lack a `type`
/// field, in which case we scan unnamed children.
fn dart_typed_parameter_alias(parameter_node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    // tree-sitter-dart's `formal_parameter` exposes the binding
    // identifier under the `name` field but the type is an
    // unnamed `type_identifier` / `type` child preceding the
    // identifier. `simple_formal_parameter` may not expose `name`
    // as a field at all — fall back to scanning named children
    // for an identifier-like leaf.
    let binding_name = if let Some(name_node) = parameter_node.child_by_field_name("name") {
        node_text(&name_node, src).trim().to_string()
    } else {
        let mut last_identifier: Option<Node<'_>> = None;
        let mut param_cursor = parameter_node.walk();
        for child in parameter_node.named_children(&mut param_cursor) {
            if child.kind() == "identifier" {
                last_identifier = Some(child);
            }
        }
        match last_identifier {
            Some(identifier_node) => node_text(&identifier_node, src).trim().to_string(),
            None => return,
        }
    };
    if binding_name.is_empty() {
        return;
    }
    // Preferred path: parameter exposes `type:` field directly.
    if let Some(type_node) = parameter_node.child_by_field_name("type") {
        if let Some(canonical) = canonical_dart_type_name(node_text(&type_node, src)) {
            push_dart_type_alias(aliases, &binding_name, &canonical);
        }
        return;
    }
    // Fallback path: type is an unnamed child (`type_identifier`,
    // `type`, `function_type`, `type_name`). Pick the first match.
    let mut param_cursor = parameter_node.walk();
    for child in parameter_node.named_children(&mut param_cursor) {
        if matches!(
            child.kind(),
            "type_identifier" | "type" | "function_type" | "type_name"
        ) {
            if let Some(canonical) = canonical_dart_type_name(node_text(&child, src)) {
                push_dart_type_alias(aliases, &binding_name, &canonical);
                return;
            }
        }
    }
}

/// Strip generics / nullable markers / function-type tail down to
/// the leftmost type identifier. `List<String>` → `List`,
/// `String?` → `String`, `Future<HttpClient>` → `Future`.
fn canonical_dart_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('?').trim();
    // Drop generics: keep everything up to the first `<`.
    let without_generics = trimmed.split('<').next().unwrap_or(trimmed).trim();
    // Drop module prefixes: `prefix.Type` → `Type`.
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

/// Append a `(name, type_name)` alias unless either side is empty or
/// they collapse to the same identifier (which would be a no-op alias).
fn push_dart_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    aliases.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

/// Drop duplicate `(name, type_name)` pairs in place, preserving order.
fn dedup_dart_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}

/// `true` when `kind` is a Dart class-shaped declaration eligible for
/// `bases:` enrichment (extends / implements / mixins).
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Dart class / mixin / extension definitions and collect bare
/// base type names. Grammar shape (verified):
///
///   `class Echo extends WebSocketHandler with M1 implements I1`
///     → (class_definition name: (identifier)
///          superclass: (superclass (type_identifier)
///                                  (mixins (type_identifier)))
///          interfaces: (interfaces (type_identifier)))
///
/// The `superclass:` field wraps the `extends` parent and any
/// `with` mixins. `interfaces:` carries `implements` types.
/// Generic / qualified bases collapse to the bare tail.
fn collect_dart_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_per_class = Vec::new();
    let class_kinds = &["class_definition", "mixin_declaration", "extension_declaration"];
    for class_node in collect_kinds(tree, class_kinds) {
        // Prefer the named `name:` field; older grammars expose only an
        // unnamed `identifier` child.
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "identifier"))
        else {
            continue;
        };
        let class_name = node_text(&name_node, src).trim();
        if class_name.is_empty() {
            continue;
        }
        let mut bases: Vec<String> = Vec::new();
        // `superclass:` carries `extends` plus any embedded `with` mixins.
        if let Some(superclass_node) = class_node.child_by_field_name("superclass") {
            collect_dart_base_names(superclass_node, src, &mut bases);
        }
        // `interfaces:` carries `implements` types.
        if let Some(interfaces_node) = class_node.child_by_field_name("interfaces") {
            collect_dart_base_names(interfaces_node, src, &mut bases);
        }
        if !bases.is_empty() {
            bases_per_class.push((span_of(file, &class_node), class_name.to_string(), bases));
        }
    }
    bases_per_class
}

/// Walk a Dart parent-clause wrapper (`superclass`, `interfaces`,
/// `mixins`) and pick out every type identifier. Skip
/// `type_arguments` so generic params (e.g. `<String, int>`) don't
/// leak into the bases list.
fn collect_dart_base_names(parent_clause: Node<'_>, src: &[u8], bases: &mut Vec<String>) {
    let mut stack = vec![parent_clause];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "type_arguments" => {
                // Skip generics — these are type params of the base,
                // not bases of their own.
                continue;
            }
            "type_identifier" => {
                if let Some(name) = canonical_dart_type_name(node_text(&node, src)) {
                    // De-dup: a class can list the same name twice via
                    // mixins + implements clauses.
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}
