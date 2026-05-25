//! C++ language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, collect_param_type_aliases, first_named_child_of_kind, language_from_pack, node_text,
        parse_with, span_of, with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, DeclIndex, DeclKind, FieldWrite, GrammarHandler, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasVocabulary, Visibility,
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
            // C++ constructors are class-named; the kind-based
            // `DeclKind::Constructor` lookup is authoritative.
            super_receiver_tokens: bonsai_lang_api::NO_SUPER_RECEIVER_TOKENS,
            implicit_receiver_tokens: &["this"],
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
            // Phase-6 return-type extraction: `T foo() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, &tree, src, &HANDLER);
            let bases_by_span = collect_cpp_class_bases(&tree, file, src);
            let access_by_span = collect_cpp_member_visibility(&tree, file, src);
            let alias_map = collect_param_type_aliases(&tree, file, src, &CPP_TYPE_ALIASES);
            let initializer_specs = collect_cpp_initializer_field_specs(&tree, file, src);
            for decl in &mut decl_index.defs {
                if let Some(visibility) = access_by_span.get(&decl.span).copied() {
                    decl.visibility = visibility;
                }
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                // Repair catch-param bindings: the kit's generic
                // extractor picks the first identifier descendant of
                // the catch clause, which on C++ `catch (const T& e)`
                // is the type identifier rather than the binding.
                fix_cpp_catch_params(&mut decl.flow_events, &tree, src);
                // Bases only attach to class-shaped decls; skip
                // free functions, methods, vars, etc.
                if let Some(specs) = initializer_specs
                    .iter()
                    .find_map(|(span, specs)| (*span == decl.span).then_some(specs))
                {
                    for spec in specs {
                        let source_param_indices = decl
                            .params
                            .iter()
                            .enumerate()
                            .filter_map(|(idx, param)| {
                                cpp_value_mentions_param(&spec.value, param).then_some(idx)
                            })
                            .collect::<Vec<_>>();
                        if source_param_indices.is_empty() {
                            continue;
                        }
                        decl.receiver_field_writes.push(FieldWrite {
                            span: spec.span,
                            target: format!("this.{}", spec.field),
                            source_param_indices,
                        });
                    }
                    decl.receiver_field_writes
                        .sort_by_key(|write| (write.span.start, write.target.clone()));
                    decl.receiver_field_writes.dedup_by(|a, b| {
                        a.span == b.span
                            && a.target == b.target
                            && a.source_param_indices == b.source_param_indices
                    });
                }
                if !is_class_like(decl.kind) {
                    continue;
                }
                if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
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

#[derive(Clone, Debug)]
struct CppInitializerFieldSpec {
    span: Span,
    field: String,
    value: String,
}

fn collect_cpp_initializer_field_specs(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<CppInitializerFieldSpec>)> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_definition"]) {
        let Some(initializers) = first_named_child_of_kind(&fn_node, "field_initializer_list") else {
            continue;
        };
        let mut specs = Vec::new();
        let mut cursor = initializers.walk();
        for init in initializers.named_children(&mut cursor) {
            if init.kind() != "field_initializer" {
                continue;
            }
            let Some(field_node) = first_named_child_of_kind(&init, "field_identifier") else {
                continue;
            };
            let Some(value_node) = first_named_child_of_kind(&init, "argument_list") else {
                continue;
            };
            let field = node_text(&field_node, src).trim().to_string();
            let value = node_text(&value_node, src)
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim()
                .to_string();
            if field.is_empty() || value.is_empty() {
                continue;
            }
            specs.push(CppInitializerFieldSpec {
                span: span_of(file, &init),
                field,
                value,
            });
        }
        if !specs.is_empty() {
            out.push((span_of(file, &fn_node), specs));
        }
    }
    out
}

fn cpp_value_mentions_param(value: &str, param: &str) -> bool {
    let mut token = String::new();
    for ch in value.chars().chain(std::iter::once(' ')) {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }
        if token == param {
            return true;
        }
        token.clear();
    }
    false
}

fn collect_cpp_member_visibility(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut out = std::collections::HashMap::new();
    for class_node in collect_kinds(tree, &["class_specifier", "struct_specifier"]) {
        let default_visibility = if class_node.kind() == "struct_specifier" {
            Visibility::Public
        } else {
            Visibility::Private
        };
        let mut current_visibility = default_visibility;
        if let Some(body) = class_node.child_by_field_name("body") {
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                if child.kind() == "access_specifier" {
                    current_visibility = cpp_access_visibility(node_text(&child, src), default_visibility);
                    continue;
                }
                if child.kind() == "function_definition" {
                    out.insert(span_of(file, &child), current_visibility);
                }
            }
        }
    }
    out
}

fn cpp_access_visibility(raw: &str, default_visibility: Visibility) -> Visibility {
    match raw.trim().trim_end_matches(':') {
        "public" => Visibility::Public,
        "protected" => Visibility::Protected,
        "private" => Visibility::Private,
        _ => default_visibility,
    }
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
fn collect_cpp_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_specifier", "struct_specifier", "union_specifier"];
    for class_node in collect_kinds(tree, class_kinds) {
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "type_identifier"))
            .or_else(|| first_named_child_of_kind(&class_node, "identifier"))
        else {
            continue;
        };
        let class_name = node_text(&name_node, src).trim();
        if class_name.is_empty() {
            continue;
        }
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
            bases_by_class.push((span_of(file, &class_node), class_name.to_string(), bases));
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
        // recover it textually. Two distinct shapes share this node
        // kind:
        //
        //   * `using namespace X::Y;` — wildcard import; brings every
        //     name in `X::Y` into scope, no single local binding.
        //   * `using X::Y::Z;`        — single-symbol import; binds
        //     `Z` locally to `X::Y::Z`.
        //
        // The leading `using namespace` keyword is the discriminator;
        // detect it BEFORE trimming so the wildcard form isn't
        // misclassified as a single-symbol import that would alias
        // `Y` (the second-to-last segment) by accident.
        let raw = node_text(&using_node, src);
        let raw_trimmed = raw.trim_start();
        let is_wildcard_namespace = raw_trimmed.starts_with("using namespace ");
        let module_path = raw_trimmed
            .trim_start_matches("using ")
            .trim_start_matches("namespace ")
            .trim_end_matches(';')
            .trim()
            .trim_end_matches("::*")
            .to_string();
        if module_path.is_empty() {
            continue;
        }
        // Tail-segment binding only applies to the single-symbol form.
        let alias = (!is_wildcard_namespace)
            .then(|| module_path.rsplit("::").next().unwrap_or(""))
            .filter(|tail| !tail.is_empty())
            .map(str::to_string);
        imports.push(ImportSpec {
            span: span_of(file, &using_node),
            module: module_path,
            alias,
            is_wildcard: is_wildcard_namespace,
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
        let (Some(alias_name_node), Some(module_name_node)) = (alias_name_node, module_name_node) else {
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

/// Repair `catch_param` on C++ `Try` events. The kit's generic
/// extractor returns the first identifier descendant of the catch
/// clause, which on `catch (const std::exception& e)` is the type
/// identifier rather than the binding. We re-extract the binding
/// from the parse tree via the standard `parameter_declaration` →
/// `declarator` → identifier chain.
fn fix_cpp_catch_params(events: &mut [bonsai_lang_api::FlowEvent], tree: &Tree, src: &[u8]) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if let Some(name) = cpp_catch_param_binding(node, src) {
                        *catch_param = Some(name);
                    }
                }
                fix_cpp_catch_params(body, tree, src);
                fix_cpp_catch_params(catch_events, tree, src);
                fix_cpp_catch_params(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                fix_cpp_catch_params(then_events, tree, src);
                fix_cpp_catch_params(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                fix_cpp_catch_params(body, tree, src);
            }
            _ => {}
        }
    }
}

fn cpp_catch_param_binding(try_node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut tcur = try_node.walk();
    for child in try_node.named_children(&mut tcur) {
        if child.kind() != "catch_clause" {
            continue;
        }
        // catch_clause > parameter_list > parameter_declaration > declarator > identifier.
        let mut ccur = child.walk();
        for sub in child.named_children(&mut ccur) {
            let target = if sub.kind() == "parameter_list" {
                let mut pcur = sub.walk();
                let mut found: Option<Node<'_>> = None;
                for c in sub.named_children(&mut pcur) {
                    if c.kind() == "parameter_declaration" {
                        found = Some(c);
                        break;
                    }
                }
                found
            } else if sub.kind() == "parameter_declaration" {
                Some(sub)
            } else {
                None
            };
            let Some(pdecl) = target else { continue };
            // The `declarator` field of `parameter_declaration` is the
            // binding. For `const T& e`, the declarator is a
            // reference_declarator → identifier. For bare `T e`, the
            // declarator is an identifier.
            let decl = pdecl.child_by_field_name("declarator");
            if let Some(decl) = decl {
                if let Some(ident) = first_identifier_descendant_cpp(decl) {
                    return Some(node_text(&ident, src).trim().to_string());
                }
            }
            // Fallback: trailing identifier among the named children.
            let mut pcur = pdecl.walk();
            let mut last_ident: Option<Node<'_>> = None;
            for n in pdecl.named_children(&mut pcur) {
                if let Some(found) = first_identifier_descendant_cpp(n) {
                    last_ident = Some(found);
                }
            }
            if let Some(n) = last_ident {
                return Some(node_text(&n, src).trim().to_string());
            }
        }
    }
    None
}

fn first_identifier_descendant_cpp<'a>(node: Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "identifier" || node.kind() == "field_identifier" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_identifier_descendant_cpp(child) {
            return Some(found);
        }
    }
    None
}
