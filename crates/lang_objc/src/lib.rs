//! Objective-C language adapter.
//!
//! `.m` files can also legitimately be MATLAB source; the CLI's file
//! detection assigns `.m` to Objective-C by default (same convention
//! `tree-sitter-language-pack` uses). If a project mixes the two, the
//! user can scope `--include` / `--exclude` to disambiguate.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, DeclIndex, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasBinding,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("objc");
const PACK_NAME: &str = "objc";

// Objective-C handler. Mixes C-style functions with Objective-C
// methods. `*_method_declaration` covers `@interface` headers (no body)
// and `method_definition` covers `@implementation` bodies. ObjC's
// `@try/@catch/@finally` parses as `try_statement`. `@synchronized`
// and `@autoreleasepool` are scope-bracketed regions modeled as
// `using` (resource-managed scope) since `body` then runs under the
// managed lock / pool.
const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &[
        "function_definition",
        "method_definition",
        "class_method_declaration",
        "instance_method_declaration",
    ],
    class_kinds: &[
        "class_interface",
        "class_implementation",
        "category_interface",
        "category_implementation",
        "protocol_declaration",
    ],
    method_kinds: &["method_definition"],
    method_context_kinds: &["class_implementation", "category_implementation"],
    constructor_method_kinds: &[],
    constructor_names: &["init"],
    if_kinds: &["if_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &["for_in_statement"],
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    loop_kinds: &[],
    call_kinds: &["call_expression", "message_expression"],
    assignment_kinds: &["assignment_expression", "init_declarator"],
    return_kinds: &["return_statement"],
    throw_kinds: &["throw_statement"],
    lambda_kinds: &["block_literal_expression"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &["synchronized_statement", "autoreleasepool_statement"],
    method_receiver_param_index: None,
    implicit_receiver_names: &["self", "super"],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
};

/// Zero-sized adapter handle; all state lives in the shared parser pack.
#[derive(Debug, Default, Copy, Clone)]
pub struct ObjCAdapter;

impl ObjCAdapter {
    /// Construct a fresh adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ObjCAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Objective-C"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.h` is ambiguous with C / C++; we claim `.m` (Objective-C
        // implementation) and `.mm` (Objective-C++). Users wanting
        // headers scoped to Objective-C can include `.h` via CLI
        // include/exclude patterns.
        &["m", "mm"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Macros: tree-sitter-objc parses `NSAssert(...)` / `NS_INLINE`
        // / `IB_DESIGNABLE` etc. as ordinary call expressions or
        // declarators, so name-resolution narrows them. Genuine
        // multi-statement `#define` expansion isn't performed.
        LanguageCapabilities {
            macros: bonsai_lang_api::CapabilityLevel::Partial,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        // Objective-C convention: methods/selectors prefixed with `_`
        // are private (Apple naming convention). Mark them
        // Visibility::Private so the resolver refuses cross-class
        // calls to internal helpers.
        for decl in &mut decl_index.defs {
            if decl.name.starts_with('_') {
                decl.visibility = bonsai_lang_api::Visibility::Private;
            }
        }
        // Per-decl `type_aliases` from typed parameters
        // (`(NSString *)name`, `(HTTPRequest *)req`). Objective-C
        // method signatures and C-style function parameters both
        // carry an explicit type — extract them so
        // `attribute: [NSURL, absoluteString]`-style rules can
        // resolve `req.absoluteString` semantically per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let aliases_by_span = collect_objc_method_type_aliases(&tree, file, src);
            for decl in &mut decl_index.defs {
                if let Some(aliases) = aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
                {
                    decl.type_aliases = aliases.clone();
                }
            }
        }
        // Recognised Objective-C lifecycle transitions. Manual
        // retain/release (`release`, `autorelease`), explicit
        // `dealloc`, Core Foundation (`CFRelease`), C `free`,
        // resource `close`, and async `cancel` patterns. All map
        // to the canonical lattice states.
        const OBJC_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "release",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "dealloc",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "CFRelease",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "free",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "autorelease",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
        ];
        for decl in &mut decl_index.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, OBJC_LIFECYCLE_TRANSITIONS);
        }
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Translate `#import` / `#include` directives into `ImportSpec`s.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Both `#import` and `#include` parse as `preproc_include` with a
    // `path` field — either `system_lib_string` (`<X.h>`) or
    // `string_literal > string_content` (`"X.h"`). tree-sitter-objc
    // doesn't distinguish import vs include in the kind name; both are
    // semantically equivalent for cross-module symbol lookup.
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
    imports
}

/// Walk every Objective-C method / function declaration once and
/// record parameter type-alias bindings. The grammar names
/// instance/class methods as `*_method_declaration` and
/// `method_definition`; their `parameters` field holds
/// `keyword_argument` (Objective-C style `name:(Type)param`) or
/// `parameter_list` of C-style `(Type) name` declarations. C
/// `function_definition` is also included so plain C helpers in
/// `.m` files participate in receiver narrowing.
fn collect_objc_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut aliases_by_fn = Vec::new();
    for fn_node in collect_kinds(
        tree,
        &[
            "function_definition",
            "method_definition",
            "class_method_declaration",
            "instance_method_declaration",
        ],
    ) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        // C-style parameters live under a nested
        // `function_declarator` whose `parameters` field is the
        // `parameter_list`. Walk the declarator chain so pointer-
        // /array-decorated function shapes still surface the list.
        if let Some(params_list) = find_objc_parameter_list(fn_node) {
            collect_objc_c_parameter_aliases(params_list, src, &mut aliases);
        }
        // ObjC selector parameters appear as `keyword_argument`
        // children of the method declaration node.
        let mut cursor = fn_node.walk();
        for child in fn_node.named_children(&mut cursor) {
            if child.kind() == "keyword_argument" {
                objc_keyword_argument_alias(child, src, &mut aliases);
            }
        }
        dedup_objc_type_aliases(&mut aliases);
        if !aliases.is_empty() {
            aliases_by_fn.push((span_of(file, &fn_node), aliases));
        }
    }
    aliases_by_fn
}

/// Walk the `function_declarator` chain to find the
/// `parameter_list` underneath. Handles pointer / array / nested
/// declarator wrappers without enumerating every grammar shape.
fn find_objc_parameter_list<'a>(node: Node<'a>) -> Option<Node<'a>> {
    if let Some(direct) = node.child_by_field_name("parameters") {
        return Some(direct);
    }
    if let Some(declarator) = node.child_by_field_name("declarator") {
        return find_objc_parameter_list(declarator);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameter_list" {
            return Some(child);
        }
        if let Some(found) = find_objc_parameter_list(child) {
            return Some(found);
        }
    }
    None
}

/// Walk a `parameter_list` node and emit one alias per
/// `parameter_declaration` child.
fn collect_objc_c_parameter_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            objc_parameter_decl_alias(child, src, aliases);
        }
    }
}

/// Pull the `(type) name` pair out of one `parameter_declaration` and
/// push it as a binding. Skips silently when either half is missing
/// or fails canonicalization.
fn objc_parameter_decl_alias(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(canonical_type) = canonical_objc_type_name(node_text(&type_node, src)) else {
        return;
    };
    // ObjC's parameter declarator may be a pointer / array / direct
    // identifier. Walk the declarator chain to find the bare
    // identifier name.
    if let Some(declarator_node) = node.child_by_field_name("declarator") {
        if let Some(name) = objc_declarator_identifier(declarator_node, src) {
            push_objc_type_alias(aliases, &name, &canonical_type);
        }
    }
}

/// Recursively descend a declarator subtree until a leaf identifier
/// surfaces. Pointer / array wrappers are unwrapped via the
/// `declarator` field; anonymous declarators yield `None`.
fn objc_declarator_identifier(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(&node, src).trim().to_string());
    }
    // Fast path: most declarator wrappers expose an inner declarator
    // via a named field.
    if let Some(inner) = node.child_by_field_name("declarator") {
        return objc_declarator_identifier(inner, src);
    }
    // Fallback: walk every named child by index — this catches
    // grammar shapes that don't name the inner declarator field.
    let count = node.named_child_count();
    for i in 0..count {
        let idx = u32::try_from(i).ok()?;
        if let Some(child) = node.named_child(idx) {
            if let Some(found) = objc_declarator_identifier(child, src) {
                return Some(found);
            }
        }
    }
    None
}

/// Extract the `(type) name` pair from one keyword-argument selector
/// segment of an Objective-C method declaration.
fn objc_keyword_argument_alias(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    // `application:openURL:` keyword argument shapes:
    //   keyword_argument
    //     selector_name (the `openURL` keyword)
    //     ( type ) name
    let mut type_text: Option<String> = None;
    let mut name_text: Option<String> = None;
    let count = node.named_child_count();
    for i in 0..count {
        let Some(idx) = u32::try_from(i).ok() else {
            continue;
        };
        let Some(child) = node.named_child(idx) else {
            continue;
        };
        match child.kind() {
            "type_descriptor" | "type" | "primitive_type" => {
                type_text = Some(node_text(&child, src).to_string());
            }
            "identifier" => {
                name_text = Some(node_text(&child, src).trim().to_string());
            }
            _ => {}
        }
    }
    // Both halves must be present — a missing type or name leaves the
    // selector ambiguous, so we drop the binding rather than guess.
    let Some(raw_type) = type_text else {
        return;
    };
    let Some(name) = name_text else {
        return;
    };
    if let Some(canonical_type) = canonical_objc_type_name(&raw_type) {
        push_objc_type_alias(aliases, &name, &canonical_type);
    }
}

/// Strip pointer / qualifier / generic suffix down to the bare
/// type identifier. `NSString *` → `NSString`, `id<NSCopying>` →
/// `id`, `__autoreleasing NSURL *` → `NSURL`,
/// `NSArray<NSString *> *` → `NSArray`.
fn canonical_objc_type_name(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_end_matches(|c: char| c == '*' || c.is_whitespace())
        .trim();
    // Strip Objective-C ARC qualifiers / `nullable` / `nonnull`
    // attribute prefixes; `__autoreleasing NSURL` → `NSURL`.
    let mut head = trimmed;
    for prefix in [
        "__autoreleasing",
        "__strong",
        "__weak",
        "__unsafe_unretained",
        "nullable",
        "nonnull",
        "_Nullable",
        "_Nonnull",
        "const",
    ] {
        if let Some(rest) = head.trim_start().strip_prefix(prefix) {
            head = rest.trim_start();
        }
    }
    let without_generics = head.split('<').next().unwrap_or(head).trim();
    // Pointer star may appear in front for block / function
    // pointer types — strip leading `*`.
    let bare = without_generics
        .trim_start_matches('*')
        .trim()
        .rsplit(' ')
        .next()
        .unwrap_or(without_generics)
        .trim_end_matches('*')
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Append a `name -> type_name` alias if both halves are non-empty
/// and distinct. The `name == type_name` check filters trivial
/// `Foo Foo` cases that would clutter the index without aiding
/// resolution.
fn push_objc_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    aliases.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

/// Drop duplicate `(name, type_name)` pairs while preserving order so
/// the first observed binding wins.
fn dedup_objc_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}
