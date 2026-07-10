//! C language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        c_family_preproc_imports, collect_kinds, collect_param_type_aliases, first_named_child_of_kind,
        language_from_pack, node_text, parse_with, span_of,
    },
    with_fn_kinds, AdapterContext, AdapterError, DeclIndex, GrammarHandler, ImportIndex, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasVocabulary, Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("c");
const PACK_NAME: &str = "c";
const HANDLER: GrammarHandler = GrammarHandler {
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    ..with_fn_kinds(&["function_definition"])
};

/// C function parameters: every binding is `Type declarator`. The
/// kit's `param_alias_from_node` consults `child_by_field_name("type")`
/// for the type, falls back to `child_by_field_name("declarator")`
/// for the binding identifier (`leaf_identifier_text` walks the
/// pointer/array declarator chain to find the inner identifier),
/// and accepts lowercase primitive types (`int`, `char`, `void`,
/// `unsigned`) per the cross-language `canonical_short_type_name`.
const C_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition"],
    param_kinds: &["parameter_declaration"],
    name_field: "declarator",
    type_field: "type",
};

/// Zero-sized adapter handle; all state lives in the shared parser pack.
#[derive(Debug, Default, Copy, Clone)]
pub struct CAdapter;

impl CAdapter {
    /// Construct a fresh adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for CAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "C"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["c", "h"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Macros: tree-sitter-c parses `STR_CPY(dest, src)` and
        // `LOG(fmt, ...)` as ordinary `call_expression` nodes, so the
        // call-graph layer narrows their callee resolution by name.
        // `#define` expansion is intentionally not performed (would
        // require a real preprocessor pass), so macros that expand to
        // multi-statement bodies still degrade to `OverApproximate`.
        // The `Partial` claim covers the call-shape recognition that
        // already works.
        LanguageCapabilities {
            macros: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: bonsai_lang_api::NO_SUPER_RECEIVER_TOKENS,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Populate qualified_name + module_path + visibility from C
        // syntax. C has no language-level module boundary, so the
        // file stem is the closest semantic anchor — that's what
        // distinguishes two `static void error(...)` decls in
        // unrelated translation units. See
        // `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        let static_function_names = collect_static_function_names(file, ctx);
        for decl in &mut decl_index.defs {
            // `static` storage class scopes the symbol to this TU.
            if static_function_names.contains(&decl.name) {
                decl.visibility = Visibility::Private;
            }
        }
        // Per-decl `type_aliases` from typed parameters. C is fully
        // typed — every parameter declares both a type and a
        // declarator that resolves to the binding identifier. The
        // kit helper handles the declarator-walking that strips
        // pointer / array wrappers down to the inner name. Brings
        // the C adapter in lockstep with the rest per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let valid_function_names = collect_function_definition_names_with_body(file, &tree, src);
            decl_index.defs.retain(|decl| {
                if !matches!(
                    decl.kind,
                    bonsai_lang_api::DeclKind::Function
                        | bonsai_lang_api::DeclKind::Method
                        | bonsai_lang_api::DeclKind::Constructor
                ) {
                    return true;
                }
                !is_c_reserved_decl_name(&decl.name)
                    && valid_function_names
                        .get(&decl.span)
                        .is_some_and(|name| name == &decl.name)
            });
            // Phase-6 return-type extraction: `T foo() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            // C's `function_definition` uses the `type` field for return type.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, &tree, src, &HANDLER);
            bonsai_lang_api::kit::inject_c_family_function_pointer_aliases(&mut decl_index, &tree, src, file);
            let alias_map = collect_param_type_aliases(&tree, file, src, &C_TYPE_ALIASES);
            for decl in &mut decl_index.defs {
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
            }
        }
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            let has_variadic_param = decl
                .params
                .iter()
                .any(|param| param == bonsai_lang_api::kit::SYNTHETIC_VARARGS_PARAM);
            bonsai_lang_api::kit::normalize_c_variadic_builtin_flow(
                &mut decl.flow_events,
                has_variadic_param,
            );
            inject_c_lifecycle_events(&mut decl.flow_events);
        }
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Tree-sitter can recover from macro-heavy C headers by stretching a
/// declaration sequence into a bogus `function_definition`. Keep only
/// nodes with an actual compound-statement body; C declarations and
/// function-pointer API tables are not callable definitions.
fn collect_function_definition_names_with_body(
    file: FileId,
    tree: &Tree,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, String> {
    collect_kinds(tree, &["function_definition"])
        .into_iter()
        .filter(function_definition_has_body)
        .filter_map(|node| function_name(&node, src).map(|name| (span_of(file, &node), name)))
        .collect()
}

fn function_definition_has_body(node: &Node<'_>) -> bool {
    node.child_by_field_name("body")
        .is_some_and(|body| body.kind() == "compound_statement")
        || first_named_child_of_kind(node, "compound_statement").is_some()
}

fn is_c_reserved_decl_name(name: &str) -> bool {
    matches!(
        name,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
    )
}

/// Walk the C tree and collect every function name whose definition
/// has a `static` storage class. C `static` is translation-unit-private
/// — file-scoped, not module-scoped — so the resolver's
/// `Visibility::Private` filter is the right fit when paired with the
/// adapter's `module_path` of `[file_stem]`.
fn collect_static_function_names(
    file: FileId,
    ctx: &AdapterContext<'_>,
) -> std::collections::HashSet<String> {
    let mut static_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Bail conservatively on any I/O / language failure — better to
    // leave names public than to hallucinate visibility.
    let Ok(snapshot) = ctx.vfs.snapshot(file) else {
        return static_names;
    };
    let Ok(language) = language_from_pack(PACK_NAME) else {
        return static_names;
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&language).is_err() {
        return static_names;
    }
    let Some(tree) = parser.parse(snapshot.text.as_bytes(), None) else {
        return static_names;
    };
    let src = snapshot.text.as_bytes();
    for fn_node in collect_kinds(&tree, &["function_definition"]) {
        if !function_has_static_specifier(&fn_node, src) {
            continue;
        }
        if let Some(name) = function_name(&fn_node, src) {
            static_names.insert(name);
        }
    }
    static_names
}

/// True when `node` (a `function_definition`) carries a `static`
/// storage-class specifier as a direct child.
fn function_has_static_specifier(node: &Node<'_>, src: &[u8]) -> bool {
    // tree-sitter-c emits a `storage_class_specifier` child whose
    // text reads "static" when the function is marked static. The
    // specifier appears either as a direct child of
    // `function_definition` or nested inside `declaration_specifiers`.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "storage_class_specifier" && node_text(&child, src) == "static" {
            return true;
        }
    }
    false
}

/// Resolve the bare function name out of a `function_definition` node
/// by descending into its `declarator` field.
fn function_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    // `function_definition` -> declarator -> ... -> identifier.
    // tree-sitter-c usually puts the bare identifier under the
    // `function_declarator` -> `identifier` chain.
    let declarator = node.child_by_field_name("declarator")?;
    extract_function_identifier(&declarator, src)
}

/// Recursively unwrap a declarator subtree until a bare `identifier`
/// surfaces; returns `None` only on completely anonymous declarators.
fn extract_function_identifier(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(node, src).to_string());
    }
    // function_declarator wraps the identifier; pointer_declarator and
    // similar nest inside.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = extract_function_identifier(&child, src) {
            return Some(found);
        }
    }
    None
}

fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    c_family_preproc_imports(tree, src, file)
}

/// C lifecycle transitions for `inject_lifecycle_events`.
const C_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
    bonsai_lang_api::LifecycleTransition {
        call_match: "free",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "cfree",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "fclose",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "pclose",
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
        call_match: "fcloseall",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "pthread_mutex_unlock",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "pthread_rwlock_unlock",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "pthread_spin_unlock",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "munmap",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "shmdt",
        transition: "freed",
        arg_index: 0,
    },
];

fn inject_c_lifecycle_events(events: &mut Vec<bonsai_lang_api::FlowEvent>) {
    bonsai_lang_api::inject_lifecycle_events(events, C_LIFECYCLE_TRANSITIONS);
}
