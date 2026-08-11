//! Rust language adapter.

use bonsai_common::FileId;
use bonsai_lang_api::{
    collect_param_type_aliases, decl_index_from_tree_with_handler,
    kit::{
        collect_kinds, language_from_pack, node_text, parse_with, pattern_binding_sites_from_arms, span_of,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, CallKind, CallTargetExtraction, CapabilityLevel,
    DeclIndex, DeclKind, FieldWrite, FlowEvent, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, PatternBindingSite, TypeAliasVocabulary, Visibility,
    NO_CONSTRUCTOR_METHOD_NAMES,
};

const RUST_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_item"],
    // `let_declaration` captures typed locals (`let c: Foo = make();`)
    // so cast / factory-typed receivers resolve `receiver_type_in` — it
    // exposes the same `pattern` (name) + `type` fields as a parameter.
    param_kinds: &["parameter", "let_declaration"],
    name_field: "pattern",
    type_field: "type",
};
use tree_sitter::{Language, Node, Tree};

fn rust_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "for_expression")
        .then(|| {
            Some((
                node.child_by_field_name("pattern")?,
                node.child_by_field_name("value")?,
            ))
        })
        .flatten()
}

fn rust_pattern_bindings(node: Node<'_>) -> Vec<PatternBindingSite<'_>> {
    let mut sites = if node.kind() == "match_expression" {
        pattern_binding_sites_from_arms(node, &["value"], &["match_arm"], &["pattern"], &[])
    } else {
        Vec::new()
    };

    if matches!(node.kind(), "if_expression" | "while_expression") {
        let Some(condition) = node.child_by_field_name("condition") else {
            return sites;
        };
        let mut stack = vec![condition];
        while let Some(current) = stack.pop() {
            if current.kind() == "let_condition" {
                if let (Some(pattern), Some(source)) = (
                    current.child_by_field_name("pattern"),
                    current.child_by_field_name("value"),
                ) {
                    sites.push(PatternBindingSite {
                        span_node: current,
                        pattern,
                        source,
                    });
                }
                continue;
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
    } else if matches!(node.kind(), "if_let_expression" | "while_let_expression") {
        if let (Some(pattern), Some(source)) = (
            node.child_by_field_name("pattern"),
            node.child_by_field_name("value"),
        ) {
            sites.push(PatternBindingSite {
                span_node: node,
                pattern,
                source,
            });
        }
    }
    sites
}

pub const LANG_ID: LanguageId = LanguageId::new("rust");
const PACK_NAME: &str = "rust";

fn rust_indirect_place_operand(node: Node<'_>) -> Option<Node<'_>> {
    let operator = match node.kind() {
        "unary_expression" => "*",
        "reference_expression" => "&",
        _ => return None,
    };
    let mut cursor = node.walk();
    if !node.children(&mut cursor).any(|child| child.kind() == operator) {
        return None;
    }
    node.child_by_field_name("value").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).last()
    })
}

/// Rust call targets are exact grammar `function`/`macro` nodes. Scoped paths
/// are namespace/type syntax, not value receivers; preserving the complete
/// node text lets the later Rust resolution pass classify them without shared
/// language or provider heuristics.
fn rust_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    let target = match node.kind() {
        "call_expression" => node.child_by_field_name("function")?,
        "macro_invocation" => node.child_by_field_name("macro")?,
        _ => return None,
    };
    let mut full_text = node_text(&target, src).trim().to_string();
    if node.kind() == "macro_invocation" && !full_text.ends_with('!') {
        full_text.push('!');
    }
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &[
        "boolean_literal",
        "integer_literal",
        "float_literal",
        "true",
        "false",
    ],
    string_literal_kinds: &["string_literal", "raw_string_literal", "char_literal"],
    comment_kinds: &["line_comment", "block_comment"],
    doc_comment_prefixes: &["///", "//!", "/**"],
    decorator_kinds: &["attribute_item"],
    parameter_container_kinds: &["parameters"],
    parameter_kinds: &["parameter", "self_parameter", "variadic_parameter"],
    parameter_annotation_kinds: &["attribute_item"],
    parameter_annotation_name_extractor: None,
    variadic_parameter_kinds: &["variadic_parameter"],
    self_parameter_kinds: &["self_parameter"],
    binding_identifier_kinds: &["identifier", "self"],
    pattern_binding_extractor: Some(rust_pattern_bindings),
    non_binding_pattern_field_names: &["type", "path", "constructor", "field"],
    identifier_kinds: &["identifier", "self"],
    aggregate_pattern_kinds: &["tuple_pattern", "struct_pattern", "slice_pattern"],
    named_aggregate_kinds: &["struct_expression"],
    positional_aggregate_kinds: &["tuple_expression", "array_expression"],
    aggregate_pair_kinds: &["field_initializer"],
    aggregate_key_field_names: &["field"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["field_identifier", "identifier"],
    shorthand_field_kinds: &["shorthand_field_initializer", "shorthand_field_identifier"],
    spread_kinds: &["base_field_initializer"],
    spread_value_field_names: &["value"],
    aggregate_syntax_only_kinds: &["type_identifier"],
    transparent_call_wrapper_kinds: &[
        "field_expression",
        "scoped_identifier",
        "parenthesized_expression",
        "try_expression",
        "await_expression",
    ],
    single_expression_group_kinds: &["expression_list"],
    assignment_target_wrapper_kinds: &["let_declaration"],
    binding_declaration_keyword_spellings: &["let", "const"],
    nested_type_ownership: true,
    fn_kinds: &["function_item"],
    class_kinds: &["struct_item", "enum_item", "trait_item", "union_item"],
    class_decl_kinds: &[
        ("struct_item", DeclKind::Struct),
        ("union_item", DeclKind::Struct),
        ("enum_item", DeclKind::Enum),
        ("trait_item", DeclKind::Trait),
    ],
    method_kinds: &[],
    method_context_kinds: &["impl_item", "trait_item"],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: NO_CONSTRUCTOR_METHOD_NAMES,
    // `if_expression` is the canonical conditional. `match_expression`
    // joins it so each arm's pattern bindings (e.g. `Some(v) => sink(v)`)
    // are emitted as Assigns scoped to the arm body. Without this the
    // bound name `v` is invisible to the taint engine and full-match
    // arm flows are lost (audit task #132). `if_let_expression` is the
    // sugar form covered by the same binding extraction path.
    if_kinds: &["if_expression", "match_expression", "if_let_expression"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["block", "expression_statement"],
    branch_arm_kinds: &["block", "match_arm"],
    for_kinds: &[],
    foreach_kinds: &["for_expression"],
    foreach_binding_extractor: Some(rust_foreach_binding),
    while_kinds: &["while_expression"],
    do_kinds: &[],
    // Rust's unconditional `loop { }` has no condition or init/update —
    // map to `LoopKind::Loop` rather than misclassifying as DoWhile.
    loop_kinds: &["loop_expression"],
    call_kinds: &["call_expression", "macro_invocation"],
    call_callee_field_names: &["function", "macro"],
    call_target_extractor: Some(rust_call_target),
    call_argument_field_names: &["arguments", "token_tree"],
    call_argument_container_kinds: &["arguments", "token_tree"],
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: Some(rust_argument_passing_mode),
    call_ref_kinds: &["call_expression", "macro_invocation"],
    member_expression_kinds: &["field_expression", "scoped_identifier"],
    subscript_expression_kinds: &["subscript_expression", "index_expression"],
    member_base_field_names: &["value", "scope"],
    member_name_field_names: &["field", "name"],
    subscript_base_field_names: &["value"],
    subscript_index_field_names: &["index"],
    call_name_suffix_tokens: &["!"],
    assignment_kinds: &[
        "assignment_expression",
        "compound_assignment_expr",
        "let_declaration",
    ],
    compound_assignment_kinds: &["compound_assignment_expr"],
    type_only_declaration_kinds: &["let_declaration"],
    return_kinds: &["return_expression"],
    throw_kinds: &[],
    lambda_kinds: &["closure_expression"],
    // Rust's postfix `?` is a `try_expression`, while the unstable
    // `try { ... }` construct is a distinct `try_block`. Only the latter owns
    // a structured body and therefore lowers to the shared Try event.
    try_kinds: &["try_block"],
    catch_kinds: &[],
    finally_kinds: &[],
    break_kinds: &["break_expression"],
    continue_kinds: &["continue_expression"],
    control_label_field_names: &["label"],
    yield_kinds: &["yield_expression"],
    yield_value_field_names: &["value"],
    await_kinds: &["await_expression"],
    defer_kinds: &[],
    using_kinds: &[],
    try_body_field_names: &["body"],
    special_forms: &[],
    method_receiver_param_index: Some(0),
    indirect_place_operand_extractor: Some(rust_indirect_place_operand),
    receiver_presence_extractor: Some(rust_function_has_receiver),
    implicit_receiver_names: &["self"],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: true,
    void_return_type_names: &[],
    ..bonsai_lang_api::EMPTY_HANDLER
};

/// Rust associated functions share `function_item` syntax with methods, but
/// only an exact `self_parameter` child establishes a receiver binding.
fn rust_function_has_receiver(node: Node<'_>, _src: &[u8]) -> bool {
    node.child_by_field_name("parameters")
        .map(|parameters| {
            let mut cursor = parameters.walk();
            let has_self = parameters
                .named_children(&mut cursor)
                .any(|parameter| parameter.kind() == "self_parameter");
            has_self
        })
        .unwrap_or(false)
}

fn rust_argument_passing_mode(_argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
    if value.kind() == "reference_expression" {
        ArgumentPassingMode::WriteBack
    } else {
        ArgumentPassingMode::Value
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct RustAdapter;

impl RustAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for RustAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Rust"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["rs"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            modules: CapabilityLevel::Partial,
            generics: CapabilityLevel::Partial,
            macros: CapabilityLevel::Partial,
            dynamic_dispatch: CapabilityLevel::Partial,
            exceptions: CapabilityLevel::Unsupported,
            // Rust's async blocks and postfix `.await` are grammar-owned
            // constructs. Runtime scheduling APIs are deliberately not
            // classified here; package/API semantics belong in rule data.
            async_await: CapabilityLevel::Exact,
            coroutines: CapabilityLevel::Unsupported,
            reflection: CapabilityLevel::Unsupported,
            ffi: CapabilityLevel::Partial,
            pattern_matching: CapabilityLevel::Exact,
            receiver_types: CapabilityLevel::Partial,
            field_places_complete: false,
            module_export_aliases: &[],
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax {
                rooted_prefixes: &["crate::", "self::"],
                repeatable_rooted_prefixes: &["super::"],
            },
            // Rust has no constructor keyword or reserved factory name.
            // Associated functions are classified from their `-> Self`
            // return plus `Self { ... }` / `Self(...)` AST shape below.
            constructor_method_names: NO_CONSTRUCTOR_METHOD_NAMES,
            bare_call_constructor_syntax: false,
            // `super` is a module-path segment in Rust, never a supertype
            // receiver. Trait/base dispatch is expressed through type paths.
            super_receiver_tokens: &[],
            // `self` is an explicit `self_parameter` grammar node and is
            // carried by receiver_param_index rather than synthesized.
            implicit_receiver_tokens: &[],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax::none(),
            same_directory_unqualified_calls: false,
            build_target_linkage: false,
            // Rust forbids ordinary same-scope overloads. Multiple callable
            // declarations with the same semantic owner and typed signature
            // are statically admissible alternatives (most commonly
            // mutually exclusive configuration items, or trait surfaces).
            // The resolver retains every such body as narrowed evidence.
            callable_declaration_family: bonsai_lang_api::CallableDeclarationFamily::SameSignature,
            quoted_callable_literals: false,
            callable_reference_syntax: bonsai_lang_api::CallableReferenceSyntax::none(),
            call_text_prefilter: bonsai_lang_api::CallTextPrefilter::Disabled,
            module_resolution_extensions: &[],
            workspace_manifest_context_extensions: &[],
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let Some((snapshot, raw_tree)) = parse_with(PACK_NAME, file, ctx) else {
            return DeclIndex {
                file,
                ..DeclIndex::default()
            };
        };
        let raw_src = snapshot.text.as_bytes();
        let compiler_view = rust_item_macro_compiler_view(raw_src, &raw_tree);
        let src = compiler_view
            .as_ref()
            .map_or(raw_src, |(source, _)| source.as_slice());
        let tree = compiler_view.as_ref().map_or(raw_tree.as_ref(), |(_, tree)| tree);
        let mut idx = decl_index_from_tree_with_handler(file, src, tree, &HANDLER);
        // Phase-6 return-type extraction: `fn f() -> T {}` populates
        // `Decl.return_type` for `apply_assign_call_result_types`.
        bonsai_lang_api::populate_decl_return_types(&mut idx, tree, src, &HANDLER);
        let arm_spans = collect_rust_match_arm_spans(tree, src, file);
        let struct_literal_field_assigns = collect_rust_struct_literal_field_assigns(tree, file, src);
        let scoped_call_spans = collect_rust_scoped_call_spans(tree, file);
        let self_constructor_call_spans = collect_rust_self_constructor_call_spans(tree, file, src);
        let exported_import_aliases = collect_rust_exported_import_aliases(tree, file, src);
        for decl in &mut idx.defs {
            enrich_rust_struct_literal_field_assigns(&mut decl.flow_events, &struct_literal_field_assigns);
            bonsai_lang_api::kit::split_match_arms_in_branch_events(&mut decl.flow_events, &arm_spans);
            classify_rust_scoped_calls(&mut decl.flow_events, &scoped_call_spans);
            classify_rust_self_constructor_calls(&mut decl.flow_events, &self_constructor_call_spans);
            enrich_rust_format_macro_operands(&mut decl.flow_events);
            enrich_rust_tail_return_sources(&mut decl.flow_events, &decl.params);
            enrich_rust_constructor_field_writes(decl);
        }
        append_rust_exported_import_decls(&mut idx, exported_import_aliases);
        // Rust module_path: relative file path under workspace root,
        // dropping `src/` and `lib.rs`/`mod.rs`/`<name>.rs` to produce
        // a `crate::mod::sub`-shaped path. Falls back to file-stem.
        let segments = ctx
            .workspace_relative_path(file)
            .map(|path| rust_module_segments(&path))
            .unwrap_or_default();
        if !segments.is_empty() {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        // Rust visibility from `pub`, `pub(crate)`, `pub(super)`,
        // `pub(in path)`. Absence = private (file/mod-scoped).
        {
            let visibility_by_span = collect_rust_visibility(tree.root_node(), file, src);
            let alias_map = collect_param_type_aliases(tree, file, src, &RUST_TYPE_ALIASES);
            let tuple_struct_bases = collect_rust_tuple_struct_bases(tree, file, src);
            let struct_field_aliases = collect_rust_struct_field_aliases(tree, src);
            let impl_method_parents = collect_rust_impl_method_parents(tree, file, src);
            let impl_method_parent_symbols = impl_method_parents
                .iter()
                .filter_map(|(span, type_name)| {
                    idx.defs
                        .iter()
                        .find(|candidate| {
                            candidate.name == *type_name
                                && matches!(
                                    candidate.kind,
                                    bonsai_lang_api::DeclKind::Class
                                        | bonsai_lang_api::DeclKind::Struct
                                        | bonsai_lang_api::DeclKind::Trait
                                        | bonsai_lang_api::DeclKind::Interface
                                        | bonsai_lang_api::DeclKind::Enum
                                )
                        })
                        .map(|parent| (*span, parent.symbol))
                })
                .collect::<Vec<_>>();
            for decl in &mut idx.defs {
                if let Some(vis) = visibility_by_span.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(bases) = tuple_struct_bases.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
                if decl.parent.is_none() {
                    if let Some(parent_symbol) = impl_method_parent_symbols
                        .iter()
                        .find_map(|(span, parent_symbol)| (*span == decl.span).then_some(*parent_symbol))
                    {
                        decl.parent = Some(parent_symbol);
                    }
                }
            }
            apply_rust_struct_field_aliases(&mut idx, &struct_field_aliases);
            enrich_rust_self_tuple_constructor_returns(&mut idx);
            classify_rust_declared_constructor_calls(&mut idx);
        }
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Propagate adapter-classified constructor result types onto local
        // receivers so later method dispatch consumes the same semantic fact.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        let Some((snapshot, raw_tree)) = parse_with(PACK_NAME, file, ctx) else {
            return ImportIndex {
                file,
                ..ImportIndex::default()
            };
        };
        let raw_src = snapshot.text.as_bytes();
        let compiler_view = rust_item_macro_compiler_view(raw_src, &raw_tree);
        let src = compiler_view
            .as_ref()
            .map_or(raw_src, |(source, _)| source.as_slice());
        let tree = compiler_view.as_ref().map_or(raw_tree.as_ref(), |(_, tree)| tree);
        ImportIndex {
            file,
            imports: parse_imports(tree, src, file),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustExportedImportAlias {
    span: bonsai_common::Span,
    name: String,
    target: String,
    visibility: Visibility,
}

/// Lower visible Rust `use` bindings as declaration-level namespace facades.
///
/// A path such as `crate::runtime::task::Id` can name a type physically
/// declared in `runtime/task/id.rs` through `pub(crate) use self::id::Id` in
/// `runtime/task/mod.rs`. The import declaration is the compiler fact that
/// connects those identities; filename casing or identifier spelling is not.
fn collect_rust_exported_import_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<RustExportedImportAlias> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, &["use_declaration"]) {
        let visibility = rust_node_visibility(&node, src);
        if matches!(visibility, Visibility::Private) {
            continue;
        }
        let Some(argument) = node.child_by_field_name("argument") else {
            continue;
        };
        let span = span_of(file, &node);
        let mut imports = Vec::new();
        append_rust_use_argument(argument, &[], span, src, true, &mut imports);
        for import in imports.into_iter().filter(|import| !import.is_wildcard) {
            let (name, target) = if let Some(member) = import.original_name.as_deref() {
                let name = import.alias.as_deref().unwrap_or(member).trim();
                let target = if import.module.trim().is_empty() {
                    member.to_string()
                } else {
                    format!("{}::{member}", import.module.trim())
                };
                (name.to_string(), target)
            } else {
                let Some(name) = import
                    .alias
                    .clone()
                    .or_else(|| bonsai_lang_api::module_local_binding(&import.module))
                else {
                    continue;
                };
                (name, import.module)
            };
            if name.is_empty() || target.trim().is_empty() {
                continue;
            }
            out.push(RustExportedImportAlias {
                span,
                name,
                target,
                visibility,
            });
        }
    }
    out.sort_by(|a, b| {
        (a.span.start, a.span.end, a.name.as_str(), a.target.as_str()).cmp(&(
            b.span.start,
            b.span.end,
            b.name.as_str(),
            b.target.as_str(),
        ))
    });
    out.dedup();
    out
}

fn append_rust_exported_import_decls(idx: &mut DeclIndex, aliases: Vec<RustExportedImportAlias>) {
    let mut next_symbol = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .map_or(0, |symbol| symbol.saturating_add(1));
    for alias in aliases {
        idx.defs.push(bonsai_lang_api::Decl {
            symbol: bonsai_common::SymbolId::new(next_symbol),
            kind: DeclKind::Import,
            name: alias.name,
            qualified_name: None,
            module_path: bonsai_lang_api::ModulePath::default(),
            span: alias.span,
            name_span: alias.span,
            visibility: alias.visibility,
            parent: None,
            body_span: None,
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases: Vec::new(),
            bases: vec![alias.target],
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            receiver_field_initializers: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
        next_symbol = next_symbol.saturating_add(1);
    }
}

/// Build a same-offset compiler view for declarative macros whose argument is
/// itself valid Rust item syntax.
///
/// Tree-sitter intentionally represents a macro argument as an opaque
/// `token_tree`; it cannot see an `impl` wrapped by configuration helpers such
/// as `wrapper! { impl Type { ... } }`. Rust permits macros in item position,
/// and production crates use that facility extensively. When—and only when—
/// the token-tree interior parses cleanly as Rust items, erase the invocation
/// wrapper while retaining every byte offset and parse again. Nested wrappers
/// are exposed to a strict fixed point: each accepted pass removes at least
/// one finite macro wrapper, so there is no semantic or numeric iteration cap.
/// Expression macros remain untouched.
fn rust_item_macro_compiler_view(src: &[u8], raw_tree: &Tree) -> Option<(Vec<u8>, Tree)> {
    let language = language_from_pack(PACK_NAME).ok()?;
    let mut source = src.to_vec();
    let mut transformed_tree = None;

    loop {
        let tree = transformed_tree.as_ref().unwrap_or(raw_tree);
        let ranges = rust_item_macro_wrapper_ranges(tree, &source, &language);
        if ranges.is_empty() {
            return transformed_tree.map(|tree| (source, tree));
        }
        for (wrapper_start, body_start, body_end, wrapper_end) in ranges {
            erase_rust_macro_wrapper(&mut source[wrapper_start..body_start]);
            erase_rust_macro_wrapper(&mut source[body_end..wrapper_end]);
        }
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).ok()?;
        transformed_tree = parser.parse(&source, None);
    }
}

fn rust_item_macro_wrapper_ranges(
    tree: &Tree,
    src: &[u8],
    language: &Language,
) -> Vec<(usize, usize, usize, usize)> {
    let mut ranges = Vec::new();
    for invocation in collect_kinds(tree, &["macro_invocation"]) {
        let Some(parent) = invocation.parent() else {
            continue;
        };
        if !matches!(parent.kind(), "source_file" | "declaration_list") {
            continue;
        }
        let Some(body) = first_named_child_of_kind_local(invocation, "token_tree") else {
            continue;
        };
        let wrapper_start = invocation.start_byte();
        let wrapper_end = invocation.end_byte();
        let body_start = body.start_byte().saturating_add(1);
        let body_end = body.end_byte().saturating_sub(1);
        if wrapper_start >= body_start
            || body_start > body_end
            || body_end >= wrapper_end
            || !rust_macro_body_is_item_syntax(&src[body_start..body_end], language)
        {
            continue;
        }
        ranges.push((wrapper_start, body_start, body_end, wrapper_end));
    }
    ranges.sort_unstable();
    ranges
}

fn rust_macro_body_is_item_syntax(src: &[u8], language: &Language) -> bool {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(language).is_err() {
        return false;
    }
    let Some(tree) = parser.parse(src, None) else {
        return false;
    };
    let root = tree.root_node();
    if root.has_error() {
        return false;
    }
    let mut cursor = root.walk();
    let has_item = root.named_children(&mut cursor).any(|node| {
        matches!(
            node.kind(),
            "const_item"
                | "enum_item"
                | "extern_crate_declaration"
                | "foreign_mod_item"
                | "function_item"
                | "impl_item"
                | "macro_definition"
                | "macro_invocation"
                | "mod_item"
                | "static_item"
                | "struct_item"
                | "trait_item"
                | "type_item"
                | "union_item"
                | "use_declaration"
        )
    });
    has_item
}

fn erase_rust_macro_wrapper(bytes: &mut [u8]) {
    for byte in bytes {
        if !matches!(*byte, b'\n' | b'\r') {
            *byte = b' ';
        }
    }
}

/// Classify tuple-struct construction through Rust's `Self(...)` type
/// syntax.  The generic extractor sees the function position as an
/// identifier, but the Rust AST makes this a type construction rather
/// than an arbitrary function call.  Keeping the decision on exact AST
/// spans preserves projected argument state through newtype wrappers
/// without teaching the dataflow engine any factory or API names.
fn collect_rust_self_constructor_call_spans(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashSet<bonsai_common::Span> {
    collect_kinds(tree, &["call_expression"])
        .into_iter()
        .filter_map(|call| {
            let function = call.child_by_field_name("function")?;
            (function.kind() == "identifier" && node_text(&function, src).trim() == "Self")
                .then(|| span_of(file, &function))
        })
        .collect()
}

/// Call-target spans whose Tree-sitter syntax is a Rust path rather than an
/// instance receiver expression.
///
/// `module::function()` and `Type::associated()` share the same Rust grammar
/// shape. Neither supplies a runtime receiver argument; name resolution later
/// decides whether the path owns a free function, associated method, or
/// constructor. Keeping this distinction in the adapter prevents shared
/// resolution from treating a namespace/type path like `value.method()`.
fn collect_rust_scoped_call_spans(
    tree: &Tree,
    file: FileId,
) -> std::collections::HashSet<bonsai_common::Span> {
    collect_kinds(tree, &["call_expression"])
        .into_iter()
        .filter_map(|call| {
            let function = call.child_by_field_name("function")?;
            rust_call_target_is_scoped_path(function).then(|| span_of(file, &function))
        })
        .collect()
}

fn rust_call_target_is_scoped_path(node: Node<'_>) -> bool {
    if node.kind() == "scoped_identifier" {
        return true;
    }
    if node.kind() != "generic_function" {
        return false;
    }
    node.child_by_field_name("function")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.named_child(0))
        .is_some_and(rust_call_target_is_scoped_path)
}

fn classify_rust_scoped_calls(
    events: &mut [FlowEvent],
    scoped_call_spans: &std::collections::HashSet<bonsai_common::Span>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                receiver,
                receiver_types,
                call_kind,
                ..
            } if scoped_call_spans.contains(span) => {
                *receiver = None;
                receiver_types.clear();
                *call_kind = CallKind::Function;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                classify_rust_scoped_calls(then_events, scoped_call_spans);
                classify_rust_scoped_calls(else_events, scoped_call_spans);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                classify_rust_scoped_calls(body, scoped_call_spans);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                classify_rust_scoped_calls(body, scoped_call_spans);
                classify_rust_scoped_calls(catch_events, scoped_call_spans);
                classify_rust_scoped_calls(finally_events, scoped_call_spans);
            }
            _ => {}
        }
    }
}

fn classify_rust_self_constructor_calls(
    events: &mut [FlowEvent],
    constructor_spans: &std::collections::HashSet<bonsai_common::Span>,
) {
    for event in events {
        match event {
            FlowEvent::Call { span, call_kind, .. } if constructor_spans.contains(span) => {
                *call_kind = CallKind::Constructor;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                classify_rust_self_constructor_calls(then_events, constructor_spans);
                classify_rust_self_constructor_calls(else_events, constructor_spans);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                classify_rust_self_constructor_calls(body, constructor_spans);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                classify_rust_self_constructor_calls(body, constructor_spans);
                classify_rust_self_constructor_calls(catch_events, constructor_spans);
                classify_rust_self_constructor_calls(finally_events, constructor_spans);
            }
            _ => {}
        }
    }
}

fn enrich_rust_format_macro_operands(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    for capture in rust_format_named_captures(&arg.value_text) {
                        if !arg.source_names.iter().any(|existing| existing == &capture) {
                            arg.source_names.push(capture);
                        }
                    }
                }
            }
            FlowEvent::Assign {
                source_names,
                source_call_args,
                ..
            } => {
                for arg in source_call_args {
                    for capture in rust_format_named_captures(arg) {
                        if !source_names.iter().any(|existing| existing == &capture) {
                            source_names.push(capture);
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_format_macro_operands(then_events);
                enrich_rust_format_macro_operands(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_format_macro_operands(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_format_macro_operands(body);
                enrich_rust_format_macro_operands(catch_events);
                enrich_rust_format_macro_operands(finally_events);
            }
            _ => {}
        }
    }
}

fn enrich_rust_tail_return_sources(events: &mut [FlowEvent], params: &[String]) {
    for event in events {
        match event {
            FlowEvent::Return {
                value_name,
                value_flow,
                ..
            } => {
                if value_name.is_none() {
                    *value_name = value_flow
                        .place
                        .as_ref()
                        .filter(|place| {
                            rust_self_field_place(place) || params.iter().any(|param| param == *place)
                        })
                        .cloned()
                        // A Rust reference expression (`&self.data.cmd`) is
                        // not itself a storage place. Its CST-lowered scalar
                        // operands still carry the exact referent, so select
                        // that adapter-owned field projection instead of
                        // teaching shared place lowering about Rust's `&`.
                        .or_else(|| {
                            value_flow
                                .source_names
                                .iter()
                                .find(|source| rust_self_field_place(source))
                                .cloned()
                        })
                        .or_else(|| rust_single_param_aggregate_source(value_flow, params));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_tail_return_sources(then_events, params);
                enrich_rust_tail_return_sources(else_events, params);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_tail_return_sources(body, params);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_tail_return_sources(body, params);
                enrich_rust_tail_return_sources(catch_events, params);
                enrich_rust_tail_return_sources(finally_events, params);
            }
            _ => {}
        }
    }
}

fn rust_single_param_aggregate_source(
    flow: &bonsai_lang_api::ExpressionFlow,
    params: &[String],
) -> Option<String> {
    let mut sources: Vec<String> = flow
        .aggregate_fields
        .iter()
        .filter_map(|field| field.value.place.clone())
        .filter(|source| params.iter().any(|param| param == source))
        .collect();
    for item in &flow.tuple_items {
        if let Some(source) = item
            .place
            .as_ref()
            .filter(|source| params.iter().any(|param| param == *source))
        {
            sources.push(source.clone());
        }
    }
    sources.sort();
    sources.dedup();
    (sources.len() == 1).then(|| sources.remove(0))
}

fn enrich_rust_constructor_field_writes(decl: &mut bonsai_lang_api::Decl) {
    if decl.params.is_empty()
        || decl
            .return_type
            .as_deref()
            .is_none_or(|return_type| return_type.trim() != "Self")
    {
        return;
    }
    let mut constructs_self = false;
    let mut writes = Vec::new();
    for event in &decl.flow_events {
        let FlowEvent::Return { span, value_flow, .. } = event else {
            continue;
        };
        if value_flow.call_sites.iter().any(|call_span| {
            rust_call_at_span(&decl.flow_events, *call_span).is_some_and(|(name, _)| name.trim() == "Self")
        }) || !value_flow.tuple_items.is_empty()
        {
            constructs_self = true;
        }
        if !value_flow.aggregate_fields.is_empty() {
            constructs_self = true;
        }
        for field in &value_flow.aggregate_fields {
            let Some(value) = field.value.place.as_ref() else {
                continue;
            };
            let Some(source_idx) = decl.params.iter().position(|param| param == value) else {
                continue;
            };
            writes.push(FieldWrite {
                span: *span,
                target: format!("self.{}", field.name),
                source_param_indices: vec![source_idx],
            });
        }
    }
    if !constructs_self {
        return;
    }
    decl.kind = bonsai_lang_api::DeclKind::Constructor;
    decl.receiver_field_writes.extend(writes);
    decl.receiver_field_writes
        .sort_by_key(|write| (write.span.start, write.target.clone()));
    decl.receiver_field_writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
}

#[derive(Clone, Debug)]
struct RustConstructorFieldSource {
    target_suffix: String,
    source_param_index: usize,
}

fn enrich_rust_self_tuple_constructor_returns(idx: &mut DeclIndex) {
    let class_name_by_symbol = idx
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Class
                    | bonsai_lang_api::DeclKind::Struct
                    | bonsai_lang_api::DeclKind::Trait
                    | bonsai_lang_api::DeclKind::Interface
                    | bonsai_lang_api::DeclKind::Enum
            )
        })
        .map(|decl| (decl.symbol, decl.name.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let mut constructor_fields: std::collections::HashMap<(String, String), Vec<RustConstructorFieldSource>> =
        std::collections::HashMap::new();
    for decl in &idx.defs {
        let Some(parent) = decl.parent.and_then(|symbol| class_name_by_symbol.get(&symbol)) else {
            continue;
        };
        for write in &decl.receiver_field_writes {
            let Some(target_suffix) = write.target.trim().strip_prefix("self.") else {
                continue;
            };
            if target_suffix.is_empty() {
                continue;
            }
            for source_param_index in &write.source_param_indices {
                constructor_fields
                    .entry((parent.clone(), decl.name.clone()))
                    .or_default()
                    .push(RustConstructorFieldSource {
                        target_suffix: target_suffix.to_string(),
                        source_param_index: *source_param_index,
                    });
            }
        }
    }
    if constructor_fields.is_empty() {
        return;
    }

    for decl in &mut idx.defs {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        let returns_self = decl.return_type.as_deref().is_some_and(|ty| ty.trim() == "Self");
        let mut writes = Vec::new();
        collect_rust_self_tuple_constructor_return_writes(
            &decl.flow_events,
            &decl.params,
            returns_self,
            &constructor_fields,
            &mut writes,
        );
        if writes.is_empty() {
            continue;
        }
        decl.receiver_field_writes.extend(writes);
        decl.receiver_field_writes
            .sort_by_key(|write| (write.span.start, write.target.clone()));
        decl.receiver_field_writes.dedup_by(|a, b| {
            a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
        });
        decl.kind = bonsai_lang_api::DeclKind::Constructor;
    }
}

/// Classify scoped Rust calls from constructor declarations already
/// proven by the adapter. This deliberately uses the declaration graph
/// instead of a conventional factory-name list: `Type::assemble(...)`
/// and `Type::new(...)` have identical semantics when both return a
/// `Self { ... }` or `Self(...)` construction.
fn classify_rust_declared_constructor_calls(idx: &mut DeclIndex) {
    let owner_name_by_symbol = idx
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Class
                    | bonsai_lang_api::DeclKind::Struct
                    | bonsai_lang_api::DeclKind::Trait
                    | bonsai_lang_api::DeclKind::Interface
                    | bonsai_lang_api::DeclKind::Enum
            )
        })
        .map(|decl| (decl.symbol, decl.name.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let mut constructors: std::collections::HashMap<String, std::collections::HashSet<String>> =
        std::collections::HashMap::new();
    for decl in idx
        .defs
        .iter()
        .filter(|decl| decl.kind == bonsai_lang_api::DeclKind::Constructor)
    {
        let Some(owner) = decl.parent.and_then(|parent| owner_name_by_symbol.get(&parent)) else {
            continue;
        };
        constructors
            .entry(owner.clone())
            .or_default()
            .insert(decl.name.clone());
    }
    if constructors.is_empty() {
        return;
    }

    for decl in &mut idx.defs {
        classify_rust_constructor_calls_in_events(&mut decl.flow_events, &constructors);
    }
}

fn classify_rust_constructor_calls_in_events(
    events: &mut [FlowEvent],
    constructors: &std::collections::HashMap<String, std::collections::HashSet<String>>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver_types,
                call_kind,
                ..
            } => {
                let Some((owner, method)) = name.rsplit_once("::") else {
                    continue;
                };
                let Some(owner) = rust_type_tail(owner) else {
                    continue;
                };
                if constructors
                    .get(owner.as_str())
                    .is_some_and(|methods| methods.contains(method))
                {
                    *call_kind = CallKind::Constructor;
                    if !receiver_types.iter().any(|existing| existing == &owner) {
                        receiver_types.insert(0, owner);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                classify_rust_constructor_calls_in_events(then_events, constructors);
                classify_rust_constructor_calls_in_events(else_events, constructors);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                classify_rust_constructor_calls_in_events(body, constructors);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                classify_rust_constructor_calls_in_events(body, constructors);
                classify_rust_constructor_calls_in_events(catch_events, constructors);
                classify_rust_constructor_calls_in_events(finally_events, constructors);
            }
            _ => {}
        }
    }
}

fn collect_rust_self_tuple_constructor_return_writes(
    events: &[FlowEvent],
    params: &[String],
    returns_self: bool,
    constructor_fields: &std::collections::HashMap<(String, String), Vec<RustConstructorFieldSource>>,
    out: &mut Vec<FieldWrite>,
) {
    for event in events {
        match event {
            FlowEvent::Return { span, value_flow, .. } => {
                if !returns_self {
                    continue;
                }
                let Some((_, args)) = value_flow
                    .call_sites
                    .iter()
                    .find_map(|call_span| rust_call_at_span(events, *call_span))
                    .filter(|(name, _)| name.trim() == "Self")
                else {
                    continue;
                };
                for (tuple_idx, arg) in args.iter().enumerate() {
                    if let Some((callee, ctor_args)) = rust_call_inside_span(events, arg.span) {
                        let Some((owner, ctor)) = callee.rsplit_once("::") else {
                            continue;
                        };
                        let Some(owner) = rust_type_tail(owner) else {
                            continue;
                        };
                        if let Some(fields) = constructor_fields.get(&(owner, ctor.to_string())) {
                            for field in fields {
                                let Some(source_arg) = ctor_args.get(field.source_param_index) else {
                                    continue;
                                };
                                let Some(source_param_index) =
                                    rust_param_index_for_call_arg(source_arg, params)
                                else {
                                    continue;
                                };
                                out.push(FieldWrite {
                                    span: *span,
                                    target: format!("self.{tuple_idx}.{}", field.target_suffix),
                                    source_param_indices: vec![source_param_index],
                                });
                            }
                        }
                    } else if let Some(source_param_index) = rust_param_index_for_call_arg(arg, params) {
                        out.push(FieldWrite {
                            span: *span,
                            target: format!("self.{tuple_idx}"),
                            source_param_indices: vec![source_param_index],
                        });
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_rust_self_tuple_constructor_return_writes(
                    then_events,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
                collect_rust_self_tuple_constructor_return_writes(
                    else_events,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_rust_self_tuple_constructor_return_writes(
                    body,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_rust_self_tuple_constructor_return_writes(
                    body,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
                collect_rust_self_tuple_constructor_return_writes(
                    catch_events,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
                collect_rust_self_tuple_constructor_return_writes(
                    finally_events,
                    params,
                    returns_self,
                    constructor_fields,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn rust_param_index_for_call_arg(arg: &bonsai_lang_api::CallArg, params: &[String]) -> Option<usize> {
    arg.place
        .as_deref()
        .or_else(|| (arg.source_names.len() == 1).then(|| arg.source_names[0].as_str()))
        .and_then(|source| params.iter().position(|param| param == source))
}

fn rust_call_at_span(
    events: &[FlowEvent],
    wanted: bonsai_common::Span,
) -> Option<(&str, &[bonsai_lang_api::CallArg])> {
    let mut contained = None;
    for event in events {
        match event {
            FlowEvent::Call { span, name, args, .. } if *span == wanted => return Some((name, args)),
            FlowEvent::Call { span, name, args, .. }
                if span.file == wanted.file && span.start == wanted.start && span.end <= wanted.end =>
            {
                // The callee token of the outer expression begins at the
                // expression's start; nested argument calls begin later.
                return Some((name, args));
            }
            FlowEvent::Call { span, name, args, .. }
                if span.file == wanted.file && wanted.start <= span.start && span.end <= wanted.end =>
            {
                // ExpressionFlow records the parsed call-expression span,
                // while the generic call fact uses the grammar's callee span.
                // They denote the same AST site. Exact/start-aligned matches
                // above identify the outer call; this widest-contained choice
                // is only a recovery path for grammar span variations.
                let width = span.end.saturating_sub(span.start);
                if contained
                    .as_ref()
                    .is_none_or(|(best_width, _, _)| width > *best_width)
                {
                    contained = Some((width, name.as_str(), args.as_slice()));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(call) =
                    rust_call_at_span(then_events, wanted).or_else(|| rust_call_at_span(else_events, wanted))
                {
                    return Some(call);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(call) = rust_call_at_span(body, wanted) {
                    return Some(call);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(call) = rust_call_at_span(body, wanted)
                    .or_else(|| rust_call_at_span(catch_events, wanted))
                    .or_else(|| rust_call_at_span(finally_events, wanted))
                {
                    return Some(call);
                }
            }
            _ => {}
        }
    }
    contained.map(|(_, name, args)| (name, args))
}

fn rust_call_inside_span(
    events: &[FlowEvent],
    container: bonsai_common::Span,
) -> Option<(&str, &[bonsai_lang_api::CallArg])> {
    for event in events {
        let event_span = event.span();
        if let FlowEvent::Call { name, args, span, .. } = event {
            if span.file == container.file && container.start <= span.start && span.end <= container.end {
                return Some((name, args));
            }
        }
        if event_span.file != container.file
            || event_span.end < container.start
            || container.end < event_span.start
        {
            continue;
        }
        let nested = match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => rust_call_inside_span(then_events, container)
                .or_else(|| rust_call_inside_span(else_events, container)),
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rust_call_inside_span(body, container)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => rust_call_inside_span(body, container)
                .or_else(|| rust_call_inside_span(catch_events, container))
                .or_else(|| rust_call_inside_span(finally_events, container)),
            _ => None,
        };
        if nested.is_some() {
            return nested;
        }
    }
    None
}

fn collect_rust_struct_literal_field_assigns(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<FlowEvent>> {
    let mut out = std::collections::HashMap::new();
    for node in collect_kinds(tree, &["let_declaration", "assignment_expression"]) {
        let Some(target_node) = node
            .child_by_field_name("pattern")
            .or_else(|| node.child_by_field_name("left"))
            .or_else(|| node.child_by_field_name("target"))
        else {
            continue;
        };
        let target = node_text(&target_node, src).trim();
        if !rust_bare_identifier(target) {
            continue;
        }
        let Some(value_node) = node
            .child_by_field_name("value")
            .or_else(|| node.child_by_field_name("right"))
        else {
            continue;
        };
        let target_type = node
            .child_by_field_name("type")
            .and_then(|ty| rust_type_tail(node_text(&ty, src)));
        let struct_nodes = rust_struct_literal_nodes_for_assignment(value_node, target_type.as_deref(), src);
        if struct_nodes.is_empty() {
            continue;
        }
        let mut events = Vec::new();
        for struct_node in struct_nodes {
            collect_rust_struct_literal_field_events(target, struct_node, file, src, &mut events);
        }
        if !events.is_empty() {
            events.sort_by_key(event_span_start);
            events.dedup_by(|a, b| flow_event_assign_key(a) == flow_event_assign_key(b));
            out.insert(span_of(file, &node), events);
        }
    }
    out
}

fn enrich_rust_struct_literal_field_assigns(
    events: &mut Vec<FlowEvent>,
    field_assigns: &std::collections::HashMap<bonsai_common::Span, Vec<FlowEvent>>,
) {
    let mut enriched = Vec::with_capacity(events.len());
    for mut event in std::mem::take(events) {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_struct_literal_field_assigns(then_events, field_assigns);
                enrich_rust_struct_literal_field_assigns(else_events, field_assigns);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_struct_literal_field_assigns(body, field_assigns);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_struct_literal_field_assigns(body, field_assigns);
                enrich_rust_struct_literal_field_assigns(catch_events, field_assigns);
                enrich_rust_struct_literal_field_assigns(finally_events, field_assigns);
            }
            _ => {}
        }
        let extra = match &event {
            FlowEvent::Assign { span, .. } => field_assigns.get(span).cloned(),
            _ => None,
        };
        enriched.push(event);
        if let Some(extra) = extra {
            enriched.extend(extra);
        }
    }
    *events = enriched;
}

fn rust_struct_literal_nodes_for_assignment<'tree>(
    value_node: Node<'tree>,
    target_type: Option<&str>,
    src: &[u8],
) -> Vec<Node<'tree>> {
    if value_node.kind() == "struct_expression" {
        return vec![value_node];
    }
    let Some(target_type) = target_type else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack = vec![value_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "struct_expression"
            && rust_struct_expression_name(node, src).as_deref() == Some(target_type)
        {
            out.push(node);
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn collect_rust_struct_literal_field_events(
    target: &str,
    struct_node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<FlowEvent>,
) {
    let Some(body) = first_named_child_of_kind_local(struct_node, "field_initializer_list") else {
        return;
    };
    let mut cursor = body.walk();
    for field_node in body.named_children(&mut cursor) {
        match field_node.kind() {
            "field_initializer" => {
                let Some(field) = field_node.child_by_field_name("field") else {
                    continue;
                };
                let Some(value) = field_node.child_by_field_name("value") else {
                    continue;
                };
                let field_name = node_text(&field, src).trim();
                if !rust_bare_identifier(field_name) {
                    continue;
                }
                let value_text = node_text(&value, src).trim();
                let source_names = rust_value_source_names(value_text);
                if source_names.is_empty() {
                    continue;
                }
                out.push(FlowEvent::Assign {
                    span: span_of(file, &field_node),
                    target: format!("{target}.{field_name}"),
                    source_name: rust_bare_identifier(value_text).then(|| value_text.to_string()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names,
                    declares_new_binding: false,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                });
            }
            "shorthand_field_initializer" => {
                let value_text = node_text(&field_node, src).trim();
                if !rust_bare_identifier(value_text) {
                    continue;
                }
                out.push(FlowEvent::Assign {
                    span: span_of(file, &field_node),
                    target: format!("{target}.{value_text}"),
                    source_name: Some(value_text.to_string()),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: vec![value_text.to_string()],
                    declares_new_binding: false,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                });
            }
            _ => {}
        }
    }
}

fn rust_struct_expression_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("type"))
        .or_else(|| first_named_child_of_kind_local(node, "type_identifier"))?;
    rust_type_tail(node_text(&name, src))
}

fn rust_type_tail(text: &str) -> Option<String> {
    let tail = text
        .trim()
        .trim_matches('&')
        .trim()
        .rsplit("::")
        .next()
        .unwrap_or(text)
        .trim();
    (rust_bare_identifier(tail)).then(|| tail.to_string())
}

fn rust_value_source_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in rust_identifier_chains_outside_strings(text) {
        push_rust_source_token(&mut out, &token);
    }
    out.sort();
    out.dedup();
    out
}

fn rust_identifier_chains_outside_strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    let mut in_string: Option<char> = None;
    let mut escape = false;
    while let Some(ch) = chars.next() {
        if let Some(quote) = in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                push_rust_identifier_chain(&mut out, &mut current);
                in_string = Some(ch);
            }
            ':' if chars.peek() == Some(&':') => {
                current.push_str("::");
                let _ = chars.next();
            }
            '.' => current.push('.'),
            '_' | 'a'..='z' | 'A'..='Z' | '0'..='9' => current.push(ch),
            _ => push_rust_identifier_chain(&mut out, &mut current),
        }
    }
    push_rust_identifier_chain(&mut out, &mut current);
    out
}

fn push_rust_identifier_chain(out: &mut Vec<String>, current: &mut String) {
    let token = current.trim_matches('.').trim_matches(':').trim();
    if !token.is_empty()
        && token
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        out.push(token.to_string());
    }
    current.clear();
}

fn push_rust_source_token(out: &mut Vec<String>, token: &str) {
    let token = token.trim_end_matches('!');
    if token.is_empty() {
        return;
    }
    out.push(token.to_string());
    for sep in [".", "::"] {
        if token.contains(sep) {
            let parts = token.split(sep).collect::<Vec<_>>();
            for split in 1..parts.len() {
                let prefix = parts[..split].join(sep);
                if !prefix.is_empty() {
                    out.push(prefix);
                }
            }
        }
    }
}

fn first_named_child_of_kind_local<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let found = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == kind);
    found
}

fn event_span_start(event: &FlowEvent) -> u64 {
    match event {
        FlowEvent::Assign { span, .. }
        | FlowEvent::AggregateAssign { span, .. }
        | FlowEvent::Call { span, .. }
        | FlowEvent::Return { span, .. }
        | FlowEvent::Throw { span, .. }
        | FlowEvent::Branch { span, .. }
        | FlowEvent::Loop { span, .. }
        | FlowEvent::Break { span, .. }
        | FlowEvent::Continue { span, .. }
        | FlowEvent::Yield { span, .. }
        | FlowEvent::Await { span, .. }
        | FlowEvent::Defer { span, .. }
        | FlowEvent::Using { span, .. }
        | FlowEvent::Try { span, .. }
        | FlowEvent::Lifecycle { span, .. } => span.start,
    }
}

fn flow_event_assign_key(event: &FlowEvent) -> Option<(bonsai_common::Span, String)> {
    match event {
        FlowEvent::Assign { span, target, .. } => Some((*span, target.clone())),
        _ => None,
    }
}

fn rust_self_field_place(expr: &str) -> bool {
    let Some(rest) = expr.strip_prefix("self.") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .chars()
            .all(|ch| ch == '.' || ch == '_' || ch.is_ascii_alphanumeric())
}

fn rust_bare_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn rust_format_named_captures(text: &str) -> Vec<String> {
    let trimmed = text.trim_start();
    let Some(after_macro) = trimmed
        .strip_prefix("format!")
        .or_else(|| trimmed.strip_prefix("format_args!"))
    else {
        return Vec::new();
    };
    let Some(open) = after_macro.find('(') else {
        return Vec::new();
    };
    let args = &after_macro[open + 1..];
    let Some((literal, _)) = first_rust_string_literal(args) else {
        return Vec::new();
    };
    rust_format_named_captures_from_literal(literal)
}

fn first_rust_string_literal(text: &str) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'"' {
            let start = idx + 1;
            idx += 1;
            let mut escaped = false;
            while idx < bytes.len() {
                let byte = bytes[idx];
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    return Some((&text[start..idx], idx + 1));
                }
                idx += 1;
            }
            return None;
        }
        idx += 1;
    }
    None
}

fn rust_format_named_captures_from_literal(literal: &str) -> Vec<String> {
    let bytes = literal.as_bytes();
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] != b'{' {
            idx += 1;
            continue;
        }
        if bytes.get(idx + 1) == Some(&b'{') {
            idx += 2;
            continue;
        }
        let start = idx + 1;
        if start >= bytes.len() || !is_rust_ident_start(bytes[start]) {
            idx += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() && is_rust_ident_continue(bytes[end]) {
            end += 1;
        }
        let name = &literal[start..end];
        if !out.iter().any(|existing| existing == name) {
            out.push(name.to_string());
        }
        idx = end;
    }
    out
}

fn is_rust_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_rust_ident_continue(byte: u8) -> bool {
    is_rust_ident_start(byte) || byte.is_ascii_digit()
}

/// Per-arm body spans for every `match_expression` in the file.
/// Mirrors the Scala/Swift collectors; passed to the kit's
/// `split_match_arms_in_branch_events` to peel the kit-emitted flat
/// Branch into per-arm forks.
fn collect_rust_match_arm_spans(tree: &Tree, _src: &[u8], file: FileId) -> Vec<Vec<bonsai_common::Span>> {
    let mut out: Vec<Vec<bonsai_common::Span>> = Vec::new();
    for match_node in collect_kinds(tree, &["match_expression"]) {
        let mut arm_body_spans: Vec<bonsai_common::Span> = Vec::new();
        let body = match_node
            .child_by_field_name("body")
            .or_else(|| match_node.child_by_field_name("block"));
        let Some(body) = body else { continue };
        let mut bcur = body.walk();
        for arm in body.named_children(&mut bcur) {
            if !matches!(
                arm.kind(),
                "match_arm" | "match_block_arm" | "match_expression_arm"
            ) {
                continue;
            }
            // The arm's body is in the `value` field (or the last
            // named child for grammars without a labeled value field).
            let arm_body = arm
                .child_by_field_name("value")
                .or_else(|| arm.child_by_field_name("body"));
            if let Some(body_node) = arm_body {
                arm_body_spans.push(span_of(file, &body_node));
            }
        }
        if !arm_body_spans.is_empty() {
            out.push(arm_body_spans);
        }
    }
    out
}

/// Walk the Rust tree and map function/struct/enum/trait/impl spans
/// to their syntactic Visibility:
///
/// - `pub` → Public
/// - `pub(crate)` → Crate
/// - `pub(super)` / `pub(in path)` → Module (treated as parent-scoped)
/// - no `pub` modifier → Private (mod-private; with empty
///   module_path treated as file-private by the resolver)
fn collect_rust_visibility(
    root: Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Visibility> {
    let mut out = std::collections::HashMap::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let is_decl = matches!(
            kind,
            "function_item"
                | "struct_item"
                | "enum_item"
                | "trait_item"
                | "impl_item"
                | "mod_item"
                | "type_item"
        );
        if is_decl {
            out.insert(span_of(file, &node), rust_node_visibility(&node, src));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn rust_node_visibility(node: &Node<'_>, src: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "visibility_modifier" {
            continue;
        }
        let text = node_text(&child, src);
        if text == "pub" {
            return Visibility::Public;
        }
        if text.starts_with("pub(crate") {
            return Visibility::Crate;
        }
        if text.starts_with("pub(super") || text.starts_with("pub(in") {
            return Visibility::Module;
        }
        // `pub(self)` is private to the current module — same as no
        // modifier in practice.
        return Visibility::Private;
    }
    Visibility::Private
}

fn collect_rust_tuple_struct_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, &["struct_item"]) {
        let name = node
            .child_by_field_name("name")
            .map(|n| node_text(&n, src).to_string())
            .unwrap_or_default();
        let Some(fields) = node.child_by_field_name("body") else {
            continue;
        };
        if fields.kind() != "ordered_field_declaration_list" {
            continue;
        }
        let mut bases = Vec::new();
        let mut cursor = fields.walk();
        for field_type in fields.children_by_field_name("type", &mut cursor) {
            let Some(base) = rust_nominal_tuple_field_type(field_type, src) else {
                continue;
            };
            if !bases.iter().any(|existing| existing == &base) {
                bases.push(base);
            }
        }
        if !bases.is_empty() {
            out.push((span_of(file, &node), name, bases));
        }
    }
    out
}

fn collect_rust_struct_field_aliases(
    tree: &Tree,
    src: &[u8],
) -> Vec<(String, Vec<bonsai_lang_api::TypeAliasBinding>)> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, &["struct_item"]) {
        let name = node
            .child_by_field_name("name")
            .map(|n| node_text(&n, src).to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let Some(fields) = node.child_by_field_name("body") else {
            continue;
        };
        let mut aliases = Vec::new();
        match fields.kind() {
            "field_declaration_list" => {
                let mut cursor = fields.walk();
                for field in fields
                    .named_children(&mut cursor)
                    .filter(|field| field.kind() == "field_declaration")
                {
                    let Some(field_name) = field.child_by_field_name("name") else {
                        continue;
                    };
                    let Some(field_type) = field.child_by_field_name("type") else {
                        continue;
                    };
                    let field_name = node_text(&field_name, src).trim();
                    let type_name = rust_declared_field_type_name(field_type, src);
                    if field_name.is_empty() || type_name.is_empty() {
                        continue;
                    }
                    aliases.push(bonsai_lang_api::TypeAliasBinding {
                        name: format!("self.{field_name}"),
                        type_name,
                    });
                }
            }
            "ordered_field_declaration_list" => {
                let mut cursor = fields.walk();
                for (idx, field_type) in fields.children_by_field_name("type", &mut cursor).enumerate() {
                    let type_name = rust_declared_field_type_name(field_type, src);
                    if type_name.is_empty() {
                        continue;
                    }
                    aliases.push(bonsai_lang_api::TypeAliasBinding {
                        name: format!("self.{idx}"),
                        type_name,
                    });
                }
            }
            _ => continue,
        }
        if !aliases.is_empty() {
            out.push((name, aliases));
        }
    }
    out
}

/// Preserve an adapter-classified Rust type path for receiver dispatch.
///
/// A bare tail is insufficient for Rust because a field commonly names a
/// sibling module type (`scheduler::Handle`) while the enclosing module also
/// declares a different `Handle`. Tree-sitter has already classified the
/// exact type node here, so retaining its path is syntax lowering rather than
/// a shared-engine name guess. Generic constructors keep their outer type,
/// matching the existing field-type contract; reference/pointer wrappers are
/// transparent for method dispatch.
fn rust_declared_field_type_name(mut node: Node<'_>, src: &[u8]) -> String {
    while matches!(node.kind(), "reference_type" | "pointer_type") {
        let Some(inner) = node.child_by_field_name("type") else {
            break;
        };
        node = inner;
    }
    if node.kind() == "generic_type" {
        if let Some(outer) = node.child_by_field_name("type") {
            node = outer;
        }
    }
    if node.kind() == "scoped_type_identifier" {
        return bonsai_common::normalize_qualified_name(node_text(&node, src));
    }
    bonsai_lang_api::kit::canonical_simple_type_name(node_text(&node, src))
}

fn rust_nominal_tuple_field_type(mut node: Node<'_>, src: &[u8]) -> Option<String> {
    while matches!(node.kind(), "reference_type" | "pointer_type") {
        node = node.child_by_field_name("type")?;
    }
    if node.kind() == "generic_type" {
        node = node.child_by_field_name("type")?;
    }
    matches!(node.kind(), "type_identifier" | "scoped_type_identifier")
        .then(|| bonsai_common::normalize_qualified_name(node_text(&node, src)))
        .filter(|type_name| !type_name.is_empty())
}

fn apply_rust_struct_field_aliases(
    idx: &mut DeclIndex,
    struct_field_aliases: &[(String, Vec<bonsai_lang_api::TypeAliasBinding>)],
) {
    if struct_field_aliases.is_empty() {
        return;
    }
    let aliases_by_class = struct_field_aliases
        .iter()
        .map(|(name, aliases)| (name.as_str(), aliases))
        .collect::<std::collections::HashMap<_, _>>();
    let class_name_by_symbol = idx
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Class
                    | bonsai_lang_api::DeclKind::Struct
                    | bonsai_lang_api::DeclKind::Trait
                    | bonsai_lang_api::DeclKind::Interface
                    | bonsai_lang_api::DeclKind::Enum
            )
        })
        .map(|decl| (decl.symbol, decl.name.clone()))
        .collect::<std::collections::HashMap<_, _>>();

    for decl in &mut idx.defs {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        let Some(parent) = decl.parent else { continue };
        let Some(class_name) = class_name_by_symbol.get(&parent) else {
            continue;
        };
        let Some(aliases) = aliases_by_class.get(class_name.as_str()) else {
            continue;
        };
        for alias in *aliases {
            if !decl.type_aliases.contains(alias) {
                decl.type_aliases.push((*alias).clone());
            }
        }
    }
}

fn collect_rust_impl_method_parents(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String)> {
    let functions = collect_kinds(tree, &["function_item"]);
    let mut out = Vec::new();
    for impl_node in collect_kinds(tree, &["impl_item"]) {
        let Some(type_name) = rust_impl_self_type(node_text(&impl_node, src)) else {
            continue;
        };
        let impl_span = span_of(file, &impl_node);
        for function in &functions {
            let fn_span = span_of(file, function);
            if fn_span.start >= impl_span.start && fn_span.end <= impl_span.end {
                out.push((fn_span, type_name.clone()));
            }
        }
    }
    out
}

fn rust_impl_self_type(text: &str) -> Option<String> {
    let header = text.split('{').next()?.trim();
    let rest = header.strip_prefix("impl")?.trim();
    let self_type = if let Some((_, rhs)) = rest.rsplit_once(" for ") {
        rhs.trim()
    } else {
        let mut rest = rest;
        if rest.starts_with('<') {
            if let Some(end) = matching_angle_close(rest) {
                rest = rest[end + 1..].trim();
            }
        }
        rest
    };
    let candidate = self_type
        .split(|ch: char| !(ch == '_' || ch == ':' || ch.is_ascii_alphanumeric()))
        .find(|part| !part.is_empty())?;
    candidate
        .rsplit("::")
        .next()
        .filter(|tail| {
            tail.chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
        })
        .map(str::to_string)
}

fn matching_angle_close(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '<' => depth = depth.saturating_add(1),
            '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, &["mod_item"]) {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let module = node_text(&name_node, src).trim();
        if module.is_empty() {
            continue;
        }
        out.push(ImportSpec {
            span: span_of(file, &node),
            module: module.to_string(),
            alias: Some(module.to_string()),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    for node in collect_kinds(tree, &["use_declaration"]) {
        let Some(argument) = node.child_by_field_name("argument") else {
            continue;
        };
        append_rust_use_argument(argument, &[], span_of(file, &node), src, true, &mut out);
    }
    out
}

fn append_rust_use_argument(
    argument: Node<'_>,
    prefix: &[String],
    span: bonsai_common::Span,
    src: &[u8],
    top_level: bool,
    out: &mut Vec<ImportSpec>,
) {
    match argument.kind() {
        "scoped_use_list" => {
            let mut nested_prefix = prefix.to_vec();
            if let Some(path) = argument.child_by_field_name("path") {
                nested_prefix.extend(rust_path_segments(path, src));
            }
            if let Some(list) = argument.child_by_field_name("list") {
                append_rust_use_argument(list, &nested_prefix, span, src, false, out);
            }
        }
        "use_list" => {
            let mut cursor = argument.walk();
            for child in argument.named_children(&mut cursor) {
                append_rust_use_argument(child, prefix, span, src, false, out);
            }
        }
        "use_as_clause" => {
            let (Some(path), Some(alias_node)) = (
                argument.child_by_field_name("path"),
                argument.child_by_field_name("alias"),
            ) else {
                return;
            };
            let mut segments = prefix.to_vec();
            segments.extend(rust_path_segments(path, src));
            let Some(original) = segments.pop() else {
                return;
            };
            let alias = node_text(&alias_node, src).trim();
            if alias.is_empty() {
                return;
            }
            if original == "self" {
                out.push(ImportSpec {
                    span,
                    module: segments.join("::"),
                    alias: Some(alias.to_string()),
                    is_wildcard: false,
                    original_name: None,
                    scope: ImportScope::Module,
                });
            } else {
                out.push(ImportSpec {
                    span,
                    module: segments.join("::"),
                    alias: Some(alias.to_string()),
                    is_wildcard: false,
                    original_name: Some(original),
                    scope: ImportScope::Module,
                });
            }
        }
        "use_wildcard" => {
            let mut module = prefix.to_vec();
            if let Some(path) = argument.named_child(0) {
                module.extend(rust_path_segments(path, src));
            }
            if !module.is_empty() {
                out.push(ImportSpec {
                    span,
                    module: module.join("::"),
                    alias: None,
                    is_wildcard: true,
                    original_name: None,
                    scope: ImportScope::Module,
                });
            }
        }
        "self" if !top_level => {
            let Some(local) = prefix.last() else {
                return;
            };
            out.push(ImportSpec {
                span,
                module: prefix.join("::"),
                alias: Some(local.clone()),
                is_wildcard: false,
                original_name: None,
                scope: ImportScope::Module,
            });
        }
        _ => {
            let mut segments = prefix.to_vec();
            segments.extend(rust_path_segments(argument, src));
            if segments.is_empty() {
                return;
            }
            if top_level {
                let module = segments.join("::");
                out.push(ImportSpec {
                    span,
                    module,
                    alias: None,
                    is_wildcard: false,
                    original_name: None,
                    scope: ImportScope::Module,
                });
                return;
            }

            let Some(original) = segments.pop() else {
                return;
            };
            out.push(ImportSpec {
                span,
                module: segments.join("::"),
                alias: None,
                is_wildcard: false,
                original_name: Some(original),
                scope: ImportScope::Module,
            });
        }
    }
}

fn rust_path_segments(path: Node<'_>, src: &[u8]) -> Vec<String> {
    if path.kind() == "scoped_identifier" {
        let mut segments = path
            .child_by_field_name("path")
            .map(|node| rust_path_segments(node, src))
            .unwrap_or_default();
        if let Some(name) = path.child_by_field_name("name") {
            let name = node_text(&name, src).trim();
            if !name.is_empty() {
                segments.push(name.to_string());
            }
        }
        return segments;
    }
    if matches!(
        path.kind(),
        "identifier" | "metavariable" | "crate" | "self" | "super"
    ) {
        let segment = node_text(&path, src).trim();
        if !segment.is_empty() {
            return vec![segment.to_string()];
        }
    }
    Vec::new()
}

fn rust_module_segments(path: &std::path::Path) -> Vec<String> {
    let mut segs: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    // Drop the trailing `<name>.rs` and any `src/` or `lib.rs`/`mod.rs`
    // sentinels so two files in the same crate share the same prefix.
    if let Some(last) = segs.last_mut() {
        let stem = {
            let path = std::path::Path::new(last);
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                .then(|| path.file_stem().map(|stem| stem.to_string_lossy().into_owned()))
                .flatten()
        };
        if let Some(stem) = stem {
            *last = stem;
        }
    }
    if matches!(segs.last().map(String::as_str), Some("lib" | "mod" | "main")) {
        segs.pop();
    }
    segs.retain(|s| s != "src" && !s.is_empty());
    segs
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
