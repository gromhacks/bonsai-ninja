//! C++ language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, collect_param_type_aliases, first_named_child_of_kind, language_from_pack, node_text,
        parse_with, span_of, with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, DeclKind, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasVocabulary, Visibility,
};

/// C++ parameter shape: `parameter_declaration` carries `type` and
/// `declarator` fields (the declarator may be a pointer / array /
/// reference wrapper around the binding identifier). The kit
/// helper drops back to `child_by_field_name("declarator")` when
/// `name` isn't present, then walks down to the inner identifier.
// `parameter_declaration` covers the function's formal parameters;
// `declaration` covers local stack-allocated bindings inside the
// body (`Box obj;`, `Logger log = ...;`). Both shapes carry a
// `type` field and a `declarator` field, so the kit's generic
// param-alias extractor pulls a `name : Type` binding from either.
const CPP_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition"],
    param_kinds: &["parameter_declaration", "declaration"],
    name_field: "declarator",
    type_field: "type",
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("cpp");
const PACK_NAME: &str = "cpp";
const CPP_CALL_KINDS: &[&str] = &["new_expression"];

/// C++ lifecycle transitions. `release` covers `unique_ptr.release()`.
/// `delete` / `delete[]` aren't `Call` events so they're not modelled here.
const CPP_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
    bonsai_lang_api::LifecycleTransition {
        call_match: "free",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "fclose",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "close",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "closedir",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "release",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "reset",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "std::move",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "move",
        transition: "moved",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "pthread_mutex_unlock",
        transition: "unlocked",
        arg_index: 0,
    },
];

const HANDLER: GrammarHandler = GrammarHandler {
    call_kinds: CPP_CALL_KINDS,
    // `this` for instance methods; C++ has no `super` keyword, but
    // `Base::method()` is a qualified call that the resolver
    // already narrows by qualified-name matching, so the explicit
    // implicit-receiver list stays at `this`.
    ..with_fn_kinds_and_implicit_receivers(&["function_definition"], &["this"], &[])
};

/// Zero-sized adapter handle; all state lives in the shared parser pack.
#[derive(Debug, Default, Copy, Clone)]
pub struct CppAdapter;

impl CppAdapter {
    /// Construct a fresh adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for CppAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "C++"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["cpp", "cc", "cxx", "hpp", "hh", "hxx"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Macros: same story as C — tree-sitter-cpp parses
        // `STR_CPY(...)` / `LOG(...)` / `assert(...)` as ordinary
        // call expressions and the engine narrows them by name.
        // `#define` expansion is not performed.
        LanguageCapabilities {
            macros: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Populate qualified_name + module_path + visibility per the
        // semantic-identity contract
        // (`docs/contributing/design-patterns.mdx::Semantic Resolution Always`).
        // Two TU-private surfaces in C++:
        //   - `static` storage class on a free function (C-inherited).
        //   - Definition inside an anonymous namespace.
        // Both must surface as `Visibility::Private` so the resolver
        // refuses cross-TU linking by name.
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        let private_function_names = collect_tu_private_function_names(file, ctx);
        for decl in &mut decl_index.defs {
            if private_function_names.contains(&decl.name) {
                decl.visibility = Visibility::Private;
            }
        }
        // Per-class `bases`: `class C : public Base, private Other {…}`
        // → ["Base", "Other"]. C++ exposes them as a single
        // `base_class_clause` whose access_specifier+type_identifier
        // pairs alternate. Per-decl `type_aliases` from typed
        // parameters bring C++ in lockstep with the rest per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let bases_by_span = collect_cpp_class_bases(&tree, file, src);
            let alias_map = collect_param_type_aliases(&tree, file, src, &CPP_TYPE_ALIASES);
            for decl in &mut decl_index.defs {
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                // Bases only attach to class-shaped decls; skip
                // free functions, methods, vars, etc.
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
        // Append `FlowEvent::Lifecycle` for recognised C++
        // resource transitions. Built on the C base set since
        // `free` / `fclose` / `close` carry over; `delete` is the
        // C++-specific addition.
        for decl in &mut decl_index.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, CPP_LIFECYCLE_TRANSITIONS);
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

/// Collect every C++ function name that's TU-private:
///
/// - Function definitions with a `static` storage class specifier.
/// - Function definitions whose body lives inside an anonymous
///   `namespace { ... }` block (no namespace identifier).
fn collect_tu_private_function_names(
    file: FileId,
    ctx: &AdapterContext<'_>,
) -> std::collections::HashSet<String> {
    let mut private_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let _ = file;
    // Bail conservatively on any I/O / parser failure.
    let Ok(snapshot) = ctx.vfs.snapshot(file) else {
        return private_names;
    };
    let Ok(language) = language_from_pack(PACK_NAME) else {
        return private_names;
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&language).is_err() {
        return private_names;
    }
    let Some(tree) = parser.parse(snapshot.text.as_bytes(), None) else {
        return private_names;
    };
    let src = snapshot.text.as_bytes();
    let root = tree.root_node();
    walk_for_tu_private(root, src, false, &mut private_names);
    private_names
}

/// Recursive walker tracking whether we're currently inside an
/// anonymous namespace; when we are, every nested function definition
/// counts as TU-private even without a `static` specifier.
fn walk_for_tu_private(
    node: Node<'_>,
    src: &[u8],
    inside_anonymous_ns: bool,
    private_names: &mut std::collections::HashSet<String>,
) {
    if node.kind() == "function_definition"
        && (inside_anonymous_ns || function_has_static_specifier(&node, src))
    {
        if let Some(name) = function_name(&node, src) {
            private_names.insert(name);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // An anonymous namespace child flips the flag for the
        // subtree; inner namespaces inherit privacy.
        let entering_anonymous =
            inside_anonymous_ns || (child.kind() == "namespace_definition" && !namespace_is_named(&child));
        walk_for_tu_private(child, src, entering_anonymous, private_names);
    }
}

/// True when a `namespace_definition` has any identifier — a missing
/// name means the namespace is anonymous (TU-local).
fn namespace_is_named(node: &Node<'_>) -> bool {
    if node.child_by_field_name("name").is_some() {
        return true;
    }
    let mut cursor = node.walk();
    let has_identifier = node
        .children(&mut cursor)
        .any(|child| child.kind() == "namespace_identifier" || child.kind() == "identifier");
    has_identifier
}

/// True when `node` (a `function_definition`) carries a `static`
/// storage-class specifier as a direct child.
fn function_has_static_specifier(node: &Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "storage_class_specifier" && node_text(&child, src) == "static" {
            return true;
        }
    }
    false
}

/// Resolve the bare function name from a `function_definition`'s
/// declarator chain. Falls through pointer / reference declarators.
fn function_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    extract_function_identifier(&declarator, src)
}

/// Recursively unwrap a declarator subtree until a leaf identifier
/// surfaces. Includes destructor / operator names so e.g. `~Foo` or
/// `operator==` still produce a name.
fn extract_function_identifier(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if matches!(
        node.kind(),
        "identifier" | "field_identifier" | "destructor_name" | "operator_name"
    ) {
        return Some(node_text(node, src).to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = extract_function_identifier(&child, src) {
            return Some(found);
        }
    }
    None
}

/// True for decl kinds that may carry a base list — only those need
/// `bases` populated.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk C++ class / struct specifiers and collect bare base type
/// names. Grammar shape (verified):
///
///   `class Echo : public Base, private Other { … };` →
///     (class_specifier name: (type_identifier)
///        (base_class_clause (access_specifier) (type_identifier)
///                           (access_specifier) (type_identifier))
///        body: (field_declaration_list))
///
/// Within `base_class_clause`, parents are listed as
/// `type_identifier` / `qualified_identifier` / `template_type`
/// nodes (alternating with `access_specifier` keywords). Generic /
/// qualified bases collapse to the bare tail.
fn collect_cpp_class_bases(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_specifier", "struct_specifier", "union_specifier"];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for class_child in class_node.named_children(&mut class_cursor) {
            // Bases live exclusively under the `base_class_clause`
            // child; everything else (the body, attributes, etc.) is
            // skipped.
            if class_child.kind() != "base_class_clause" {
                continue;
            }
            let mut clause_cursor = class_child.walk();
            for clause_child in class_child.named_children(&mut clause_cursor) {
                match clause_child.kind() {
                    "type_identifier"
                    | "qualified_identifier"
                    | "template_type"
                    | "scoped_type_identifier" => {
                        if let Some(name) = canonical_cpp_base_name(node_text(&clause_child, src)) {
                            // Dedup so `class C : public Base, public Base` collapses.
                            if !bases.iter().any(|existing| existing == &name) {
                                bases.push(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Reduce a base-class type expression to its bare tail identifier:
/// strip template arguments and namespace qualifiers so
/// `ns::Base<T>` → `Base`.
fn canonical_cpp_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let without_template = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let bare = without_template
        .rsplit("::")
        .next()
        .unwrap_or(without_template)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Translate `#include` directives and `using` declarations into
/// `ImportSpec`s. The two flavours produce indistinguishable
/// downstream lookups; namespace `using` ending in `::*` is recorded
/// as a wildcard import.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // C-style preproc_include + C++ `using namespace X;` / `using X::Y;`.
    for include_node in collect_kinds(tree, &["preproc_include"]) {
        let Some(path_node) = include_node.child_by_field_name("path") else {
            continue;
        };
        let module = match path_node.kind() {
            "system_lib_string" => node_text(&path_node, src)
                .trim_matches(|c: char| matches!(c, '<' | '>'))
                .to_string(),
            "string_literal" => first_named_child_of_kind(&path_node, "string_content")
                .map(|content_node| node_text(&content_node, src).to_string())
                .unwrap_or_else(|| node_text(&path_node, src).trim_matches('"').to_string()),
            _ => node_text(&path_node, src).to_string(),
        };
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &include_node),
            module,
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    for using_node in collect_kinds(tree, &["using_declaration"]) {
        // Tree-sitter-cpp doesn't break the path into fields, so we
        // recover it textually by stripping the syntactic prefix and
        // trailing semicolon.
        let module = node_text(&using_node, src)
            .trim_start_matches("using ")
            .trim_start_matches("namespace ")
            .trim_end_matches(';')
            .trim()
            .to_string();
        if module.is_empty() {
            continue;
        }
        let is_wildcard = module.ends_with("::*");
        imports.push(ImportSpec {
            span: span_of(file, &using_node),
            module: module.trim_end_matches("::*").to_string(),
            alias: None,
            is_wildcard,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    // C++ `namespace h = util;` — explicit namespace alias. The
    // `name` field is the local alias (`h`); the `aliased` /
    // `value` field is the original namespace identifier (`util`).
    // Bind `h` as a `Namespace` target so `h::helper(...)` resolves
    // to `util::helper(...)`.
    for alias_node in collect_kinds(tree, &["namespace_alias_definition"]) {
        let alias_name_node = alias_node.child_by_field_name("name").or_else(|| {
            let mut cursor = alias_node.walk();
            let mut found = None;
            for child in alias_node.named_children(&mut cursor) {
                if matches!(child.kind(), "identifier" | "namespace_identifier") {
                    found = Some(child);
                    break;
                }
            }
            found
        });
        let module_name_node = alias_node
            .child_by_field_name("aliased")
            .or_else(|| alias_node.child_by_field_name("value"))
            .or_else(|| {
                let mut cursor = alias_node.walk();
                let mut seen_first = false;
                let mut found = None;
                for child in alias_node.named_children(&mut cursor) {
                    if matches!(
                        child.kind(),
                        "identifier" | "qualified_identifier" | "namespace_identifier"
                    ) {
                        if seen_first {
                            found = Some(child);
                            break;
                        }
                        seen_first = true;
                    }
                }
                found
            });
        let (Some(alias_name_node), Some(module_name_node)) = (alias_name_node, module_name_node)
        else {
            continue;
        };
        let alias_name = node_text(&alias_name_node, src).trim().to_string();
        let module = node_text(&module_name_node, src).trim().to_string();
        if alias_name.is_empty() || module.is_empty() || alias_name == module {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &alias_node),
            module,
            alias: Some(alias_name),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}
