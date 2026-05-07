//! Go language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, DeclIndex, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasBinding, Visibility,
};
use tree_sitter::Node;
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("go");
const PACK_NAME: &str = "go";
// `composite_literal` is included so struct-literal initialisers
// surface as call sites (constructor-like). `go_statement` is NOT
// added: tree-sitter-go nests the actual `call_expression` as the
// statement's named child, so the standard recursion already picks
// up `workerFn(x)`. `send_statement` is handled via
// `pseudo_call_event` (lowered to a `send(channel, value)` call so
// the value's taint surfaces) — adding it as a generic call_kind
// would mis-extract the channel as the callee.
const GO_CALL_KINDS: &[&str] = &["composite_literal"];

/// Go lifecycle transitions: stdlib `Close` / `Unlock` / `Cancel` /
/// `Stop` and the cgo `C.free` bridge.
const GO_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
    bonsai_lang_api::LifecycleTransition {
        call_match: "Close",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Unlock",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "RUnlock",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Cancel",
        transition: "cancelled",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Stop",
        transition: "cancelled",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "C.free",
        transition: "freed",
        arg_index: 0,
    },
];

const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &["function_declaration", "method_declaration"],
    call_kinds: GO_CALL_KINDS,
    method_receiver_param_index: Some(0),
    ..bonsai_lang_api::kit::GENERIC_HANDLER
};

/// Tree-sitter adapter for the Go programming language.
#[derive(Debug, Default, Copy, Clone)]
pub struct GoAdapter;

impl GoAdapter {
    /// Construct a fresh adapter; the type carries no state.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for GoAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Go"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["go"]
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
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Go module_path = the file's `package <name>;` declaration.
        // All files in the same package share the segment so
        // unexported (lowercase-first) names cross-link only within
        // the package. Falls back to file-stem when the package
        // declaration isn't present.
        let parsed = parse_with(PACK_NAME, file, ctx);
        let package_segment = parsed.as_ref().and_then(|(snapshot, tree)| {
            extract_go_package(tree.root_node(), snapshot.text.as_bytes()).map(|name| vec![name])
        });
        if let Some(segments) = package_segment {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            // No `package` clause (parse error or fragment) — fall back
            // to file-stem so cross-file lookups still match by name.
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        // Go's exported/unexported convention is fully name-based:
        // uppercase first letter = exported (Public); everything else
        // is package-private (Visibility::Module).
        for decl in &mut idx.defs {
            if let Some(first_char) = decl.name.chars().next() {
                if !first_char.is_ascii_uppercase() {
                    decl.visibility = Visibility::Module;
                }
            }
        }
        // Per-decl `type_aliases` from typed parameters and method
        // receivers. Go signatures always carry an explicit type on
        // every binding, so this is the most reliable surface for
        // semantic-identity narrowing across all the supported
        // languages. Brings Go in lockstep with Java/Kotlin/Scala/
        // TS/C#/Swift/Rust/Python/Dart per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parsed {
            let src = snapshot.text.as_bytes();
            let aliases_by_span = collect_go_method_type_aliases(&tree, file, src);
            let method_receivers_by_span = collect_go_method_receiver_types(&tree, file, src);
            let bases_by_span = collect_go_class_bases(&tree, file, src);
            let class_symbols: Vec<(String, SymbolId)> = idx
                .defs
                .iter()
                .filter(|decl| matches!(decl.kind, bonsai_lang_api::DeclKind::Class))
                .map(|decl| (decl.name.clone(), decl.symbol))
                .collect();
            for decl in &mut idx.defs {
                if let Some(aliases) = aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
                {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(receiver_type) = method_receivers_by_span
                    .iter()
                    .find_map(|(span, ty)| (*span == decl.span).then_some(ty))
                {
                    if let Some((_, class_symbol)) = class_symbols
                        .iter()
                        .find(|(class_name, _)| class_name == receiver_type)
                    {
                        decl.parent = Some(*class_symbol);
                    }
                }
                if let Some(bases) = bases_by_span
                    .iter()
                    .find_map(|(span, bases)| (*span == decl.span).then_some(bases))
                {
                    decl.bases = bases.clone();
                }
            }
        }
        // Append `FlowEvent::Lifecycle` for recognised Go
        // resource transitions (`f.Close()`, `mu.Unlock()`,
        // `cancel()`, `C.free`). Receiver-style calls land with
        // `name = "Close"` and `args[0] = "f"`, so arg_index 0
        // points at the receiver text.
        for decl in &mut idx.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, GO_LIFECYCLE_TRANSITIONS);
        }
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Parse `import` declarations into `ImportSpec` records.
///
/// Surfaces both the imported module path and the local binding name
/// so the resolver and taint engine can match qualified identifiers
/// like `fmt.Println` against the right module.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Two shapes:
    //   1. Single: `import "path"` or `import alias "path"` —
    //      a direct `import_spec` child.
    //   2. Grouped: `import ( "a"; "b" )` — `import_spec` children
    //      nested inside `import_spec_list`. Walking each
    //      `import_declaration`'s descendants (rather than re-scanning
    //      the whole tree per declaration) keeps this O(N).
    for declaration in collect_kinds(tree, &["import_declaration"]) {
        let specs = collect_kinds_under(&declaration, &["import_spec"]);
        for spec in specs {
            let Some(path_node) = spec.child_by_field_name("path") else {
                continue;
            };
            // Prefer the unquoted string content; fall back to manually
            // stripping `"` / `` ` `` if the grammar didn't expose it.
            let module = first_named_child_of_kind(&path_node, "interpreted_string_literal_content")
                .map(|content| node_text(&content, src).to_string())
                .unwrap_or_else(|| {
                    node_text(&path_node, src)
                        .trim_matches(|ch: char| matches!(ch, '"' | '`'))
                        .to_string()
                });
            if module.is_empty() {
                continue;
            }
            // `import f "fmt"` / `import . "x"` / `import _ "x"`
            let explicit_alias = spec
                .child_by_field_name("name")
                .map(|name_node| node_text(&name_node, src).to_string());
            // `.` makes the module a wildcard import (members enter the
            // current scope unprefixed).
            let is_wildcard = explicit_alias.as_deref() == Some(".");
            // Go binds an unaliased import's local name to the path
            // tail: `import "io/fs"` → `fs`, `import "fmt"` → `fmt`.
            // Surface that binding as an explicit `alias` so taint's
            // qualified-alias gate sees a Go alias map for
            // `fmt.Println` instead of falling through to bare-tail
            // resolution. `_` / `.` aliases bind no local name, so
            // we skip them. Coupled with the self-binding and
            // path-style detectors in `bonsai_resolve` and
            // `bonsai_taint::inter::resolve_call_candidates`.
            let alias = if explicit_alias.is_some() {
                let alias_text = explicit_alias.as_deref();
                // `_` (blank) and `.` (wildcard) bind no local name.
                if matches!(alias_text, Some("_" | ".")) {
                    None
                } else {
                    explicit_alias
                }
            } else {
                // Unaliased: synthesize the Go-implicit binding from
                // the path tail.
                module
                    .rsplit('/')
                    .next()
                    .filter(|path_tail| !path_tail.is_empty())
                    .map(str::to_string)
            };
            imports.push(ImportSpec {
                span: span_of(file, &spec),
                module,
                alias,
                is_wildcard,
                original_name: None,
                scope: ImportScope::Module,
            });
        }
    }
    imports
}

/// Walk the subtree rooted at `root` and return every named descendant
/// whose kind is in `kinds`. Local helper because `collect_kinds`
/// walks the entire tree from the root, which would re-scan every
/// `import_declaration` for every declaration.
fn collect_kinds_under<'tree>(
    root: &tree_sitter::Node<'tree>,
    kinds: &[&str],
) -> Vec<tree_sitter::Node<'tree>> {
    let mut matches = Vec::new();
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if kinds.contains(&child.kind()) {
                matches.push(child);
            }
            stack.push(child);
        }
    }
    matches
}

/// Walk every Go function/method declaration once and record
/// parameter type-alias bindings. Go is the easiest case: every
/// formal parameter has an explicit type and the grammar names them
/// uniformly as `parameter_declaration` nodes inside
/// `parameter_list`.
fn collect_go_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut aliases_by_fn = Vec::new();
    for fn_node in collect_kinds(tree, &["function_declaration", "method_declaration"]) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        // `method_declaration` has a `receiver` (parameter_list with
        // one entry); both function and method have `parameters`.
        if let Some(receiver) = fn_node.child_by_field_name("receiver") {
            collect_go_parameter_aliases(receiver, src, &mut aliases);
        }
        if let Some(params) = fn_node.child_by_field_name("parameters") {
            collect_go_parameter_aliases(params, src, &mut aliases);
        }
        collect_go_local_type_aliases(fn_node, src, &mut aliases);
        dedup_go_type_aliases(&mut aliases);
        if !aliases.is_empty() {
            aliases_by_fn.push((span_of(file, &fn_node), aliases));
        }
    }
    aliases_by_fn
}

fn collect_go_method_receiver_types(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for method in collect_kinds(tree, &["method_declaration"]) {
        let Some(receiver) = method.child_by_field_name("receiver") else {
            continue;
        };
        let Some(receiver_type) = first_go_parameter_type(receiver, src) else {
            continue;
        };
        out.push((span_of(file, &method), receiver_type));
    }
    out
}

fn first_go_parameter_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameter_declaration"
            && child.kind() != "variadic_parameter_declaration"
        {
            continue;
        }
        let Some(type_node) = child.child_by_field_name("type") else {
            continue;
        };
        if let Some(type_name) = canonical_go_type_name(node_text(&type_node, src)) {
            return Some(type_name);
        }
    }
    None
}

fn collect_go_class_bases(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, Vec<String>)> {
    let mut out = Vec::new();
    for type_spec in collect_kinds(tree, &["type_spec"]) {
        let Some(type_node) = type_spec.child_by_field_name("type") else {
            continue;
        };
        if !matches!(type_node.kind(), "struct_type" | "interface_type") {
            continue;
        }
        let mut bases = Vec::new();
        collect_go_embedded_type_names(type_node, src, &mut bases);
        if !bases.is_empty() {
            out.push((span_of(file, &type_spec), bases));
        }
    }
    out
}

fn collect_go_embedded_type_names(node: Node<'_>, src: &[u8], bases: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "field_declaration" {
            let named_field = current.child_by_field_name("name").is_some();
            if !named_field {
                if let Some(type_node) = current.child_by_field_name("type") {
                    if let Some(base) = canonical_go_type_name(node_text(&type_node, src)) {
                        push_unique_string(bases, base);
                    }
                } else if let Some(base) = first_type_identifier_text(current, src) {
                    push_unique_string(bases, base);
                }
            }
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn collect_go_local_type_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    for var_spec in collect_kinds_under(&node, &["var_spec"]) {
        let names = go_var_spec_names(var_spec, src);
        if names.is_empty() {
            continue;
        }
        let declared_type = var_spec
            .child_by_field_name("type")
            .and_then(|type_node| canonical_go_type_name(node_text(&type_node, src)));
        let concrete_type = var_spec
            .child_by_field_name("value")
            .and_then(|value_node| first_go_composite_literal_type(value_node, src));
        for name in names {
            if let Some(ty) = declared_type.as_deref() {
                push_go_type_alias(aliases, &name, ty);
            }
            if let Some(ty) = concrete_type.as_deref() {
                push_go_type_alias(aliases, &name, ty);
            }
        }
    }
}

fn go_var_spec_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let type_start = node
        .child_by_field_name("type")
        .map(|type_node| type_node.start_byte())
        .unwrap_or(usize::MAX);
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= type_start {
            continue;
        }
        if child.kind() == "identifier" {
            let name = node_text(&child, src).trim();
            if !name.is_empty() {
                push_unique_string(&mut names, name.to_string());
            }
        }
    }
    names
}

fn first_go_composite_literal_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "composite_literal" {
            if let Some(type_node) = current.child_by_field_name("type") {
                if let Some(type_name) = canonical_go_type_name(node_text(&type_node, src)) {
                    return Some(type_name);
                }
            }
        }
        let mut cursor = current.walk();
        let children: Vec<_> = current.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

fn first_type_identifier_text(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "type_identifier" | "qualified_type") {
            if let Some(type_name) = canonical_go_type_name(node_text(&current, src)) {
                return Some(type_name);
            }
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    let value = value.trim();
    if value.is_empty() || values.iter().any(|existing| existing == value) {
        return;
    }
    values.push(value.to_string());
}

/// Visit a `parameter_list` node and forward each parameter
/// declaration to `go_parameter_decl_aliases`.
fn collect_go_parameter_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        // Variadic parameters (`...T`) follow the same shape as a
        // normal parameter declaration.
        if child.kind() == "parameter_declaration" || child.kind() == "variadic_parameter_declaration" {
            go_parameter_decl_aliases(child, src, aliases);
        }
    }
}

/// Bind every identifier in a single `parameter_declaration` to its
/// canonical type name.
fn go_parameter_decl_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    // Go grammar: `parameter_declaration` has a `name:` field
    // (sometimes a list of identifiers `a, b, c Type`) and a `type:`
    // field. Pointer / qualified / generic types still resolve to
    // the bare type name through `canonical_go_type_name`.
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(canonical) = canonical_go_type_name(node_text(&type_node, src)) else {
        return;
    };
    // A single `parameter_declaration` may bind multiple identifiers
    // sharing one type (`a, b string`). Iterate every identifier
    // child rather than just `child_by_field_name("name")`.
    let mut cursor = node.walk();
    let mut bound_any = false;
    for child in node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            let name = node_text(&child, src).trim().to_string();
            if !name.is_empty() {
                push_go_type_alias(aliases, &name, &canonical);
                bound_any = true;
            }
        }
    }
    if !bound_any {
        // Fallback for grammar shapes that don't expose identifiers
        // as direct named children — try the explicit `name` field.
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(&name_node, src).trim().to_string();
            if !name.is_empty() {
                push_go_type_alias(aliases, &name, &canonical);
            }
        }
    }
}

/// Strip pointer / qualified / generic wrappers down to the
/// rightmost bare type identifier. `*http.Request` →
/// `Request`, `[]string` → `string`, `map[string]int` → `int`,
/// `Foo[T]` → `Foo`.
fn canonical_go_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('*').trim_start_matches('&').trim();
    // Strip slice / array / map prefixes if present; keep the
    // value type for the binding.
    let after_brackets = if let Some(rest) = trimmed.strip_prefix("[]") {
        rest.trim()
    } else if let Some(rest) = trimmed.strip_prefix("map[") {
        // `map[K]V` → V (most relevant for taint propagation).
        rest.split_once(']')
            .map_or(rest, |(_, value_type)| value_type)
            .trim()
    } else if trimmed.starts_with('[') {
        // Fixed-size array `[N]T` — strip up to the closing bracket.
        trimmed
            .split_once(']')
            .map_or(trimmed, |(_, value_type)| value_type)
            .trim()
    } else {
        trimmed
    };
    // Drop any generic instantiation suffix (`Foo[T]` → `Foo`).
    let without_generic = after_brackets.split('[').next().unwrap_or(after_brackets).trim();
    // Drop the package qualifier (`http.Request` → `Request`).
    let bare = without_generic
        .rsplit('.')
        .next()
        .unwrap_or(without_generic)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Append a type-alias binding, skipping no-op entries (empty names
/// or self-bindings where `name == type_name`).
fn push_go_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    aliases.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

/// Drop duplicate `(name, type_name)` pairs in place while preserving
/// insertion order.
fn dedup_go_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}

/// Find the `package <name>` declaration at the top of a Go file
/// and return the package name. Files without a package declaration
/// (rare; would be a parse error in real Go) return None.
fn extract_go_package(root: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        let mut sub = child.walk();
        for subchild in child.children(&mut sub) {
            if subchild.kind() == "package_identifier" || subchild.kind() == "identifier" {
                return Some(node_text(&subchild, src).to_string());
            }
        }
    }
    None
}
