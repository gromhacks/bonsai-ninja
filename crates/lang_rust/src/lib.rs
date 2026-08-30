//! Rust language adapter.

use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_param_type_aliases, decl_index_from_tree_with_handler,
    kit::{
        call_arg_from_node_with_handler, collect_kinds, language_from_pack, node_text, parse_with,
        pattern_binding_sites_from_arms, span_of,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, CallArg, CallKind, CallTargetExtraction,
    CapabilityLevel, DeclIndex, DeclKind, FieldWrite, FlowEvent, GrammarHandler, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, PatternBindingSite, StaticScalarValue,
    TypeAliasBinding, TypeAliasVocabulary, Visibility, NO_CONSTRUCTOR_METHOD_NAMES,
};

const RUST_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_item"],
    // Parameters always carry a compiler-owned declared type. Rust locals
    // are collected separately below because an untyped `let` can contain
    // type syntax inside its initializer (`factory::<T>()`); recursively
    // searching that initializer would incorrectly declare the binding as
    // `T`.
    param_kinds: &["parameter"],
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
    let mut target = match node.kind() {
        "call_expression" => node.child_by_field_name("function")?,
        "macro_invocation" => node.child_by_field_name("macro")?,
        _ => return None,
    };
    // A Rust turbofish is an instantiation of the same callable, not part of
    // its symbol identity (`warp::query::<T>` calls `warp::query`). Keep the
    // exact grammar-selected base target while type arguments remain in the
    // surrounding CST/compiler object for consumers that need them.
    while target.kind() == "generic_function" {
        target = target.child_by_field_name("function")?;
    }
    let mut full_text = node_text(&target, src).trim().to_string();
    if node.kind() == "macro_invocation" && !full_text.ends_with('!') {
        full_text.push('!');
    }
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: target,
        full_text,
    })
}

fn rust_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "boolean_literal" | "true" | "false" => match node_text(&node, src).trim() {
            "true" => Some(StaticScalarValue::Boolean(true)),
            "false" => Some(StaticScalarValue::Boolean(false)),
            _ => None,
        },
        "string_literal" | "raw_string_literal" | "char_literal" => {
            rust_static_string(node_text(&node, src).trim()).map(StaticScalarValue::String)
        }
        _ => None,
    }
}

fn rust_static_string(literal: &str) -> Option<String> {
    let literal = literal.strip_prefix('b').unwrap_or(literal);
    if let Some(raw) = literal.strip_prefix('r') {
        let hash_count = raw.bytes().take_while(|byte| *byte == b'#').count();
        let raw = raw.get(hash_count..)?;
        let body = raw.strip_prefix('"')?;
        let suffix = format!("\"{}", "#".repeat(hash_count));
        return body.strip_suffix(&suffix).map(ToString::to_string);
    }
    let (quote, body) = if let Some(body) = literal.strip_prefix('"') {
        ('"', body.strip_suffix('"')?)
    } else if let Some(body) = literal.strip_prefix('\'') {
        ('\'', body.strip_suffix('\'')?)
    } else {
        return None;
    };
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            '"' if quote == '"' => out.push('"'),
            '\'' if quote == '\'' => out.push('\''),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            'x' => {
                let hi = chars.next()?.to_digit(16)?;
                let lo = chars.next()?.to_digit(16)?;
                out.push(char::from_u32((hi << 4) | lo)?);
            }
            'u' => {
                if chars.next()? != '{' {
                    return None;
                }
                let mut digits = String::new();
                loop {
                    match chars.next()? {
                        '}' => break,
                        '_' => {}
                        digit if digit.is_ascii_hexdigit() && digits.len() < 6 => digits.push(digit),
                        _ => return None,
                    }
                }
                out.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
            }
            '\n' => {
                while chars.peek().is_some_and(|next| next.is_whitespace()) {
                    chars.next();
                }
            }
            _ => return None,
        }
    }
    Some(out)
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
    // Rust extractor parameters bind the identifiers inside the parsed
    // pattern (`Query(value): Query<T>`). The tuple-struct constructor is
    // type syntax, not the parameter identity seen by dataflow or rules.
    destructured_parameter_kinds: &[
        "tuple_struct_pattern",
        "tuple_pattern",
        "struct_pattern",
        "slice_pattern",
        "reference_pattern",
        // A bare `_` formal is an anonymous grammar token selected through
        // the parameter's `pattern` field. It occupies a source slot but
        // introduces no addressable compiler binding.
        "_",
    ],
    pattern_binding_extractor: Some(rust_pattern_bindings),
    non_binding_pattern_field_names: &["type", "path", "field"],
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
    single_expression_group_kinds: &[],
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
    // arm flows are lost (audit task #132). Rust `if let` is an
    // `if_expression` whose condition contains a
    // `let_condition`; the grammar has no separate `if_let_expression` node.
    if_kinds: &["if_expression", "match_expression"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    condition_not_operator_kinds: &[],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["block", "expression_statement"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &[],
    branch_arm_kinds: &["block", "match_arm"],
    exclusive_branch_arm_kinds: &["match_arm"],
    fallthrough_branch_arm_kinds: &[],
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
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["arguments", "token_tree"],
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: Some(rust_argument_passing_mode),
    call_ref_kinds: &["call_expression", "macro_invocation"],
    member_expression_kinds: &["field_expression", "scoped_identifier"],
    subscript_expression_kinds: &["index_expression"],
    member_base_field_names: &["value"],
    member_name_field_names: &["field", "name"],
    subscript_base_field_names: &["value"],
    subscript_index_field_names: &[],
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
    exclusive_catch_arm_kinds: &[],
    finally_kinds: &[],
    break_kinds: &["break_expression"],
    continue_kinds: &["continue_expression"],
    control_label_field_names: &[],
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

/// Rust CST kinds consumed by adapter-owned normalization after/beside the
/// shared handler. Keeping this explicit makes grammar upgrades fail in
/// conformance instead of silently disabling compiler facts.
const ADDITIONAL_GRAMMAR_NODE_KINDS: &[(&str, &str)] = &[
    ("pattern-bindings", "for_expression"),
    ("pattern-bindings", "match_expression"),
    ("pattern-bindings", "match_arm"),
    ("pattern-bindings", "if_expression"),
    ("pattern-bindings", "while_expression"),
    ("pattern-bindings", "let_condition"),
    ("indirect-place", "unary_expression"),
    ("indirect-place", "reference_expression"),
    ("indirect-place-operator", "*"),
    ("indirect-place-operator", "&"),
    ("call-target", "call_expression"),
    ("call-target", "macro_invocation"),
    ("call-target", "generic_function"),
    ("receiver-parameter", "self_parameter"),
    ("exported-use", "use_declaration"),
    ("macro-item-view", "source_file"),
    ("macro-item-view", "declaration_list"),
    ("macro-item-view", "token_tree"),
    ("macro-item-view", "const_item"),
    ("macro-item-view", "enum_item"),
    ("macro-item-view", "extern_crate_declaration"),
    ("macro-item-view", "foreign_mod_item"),
    ("macro-item-view", "function_item"),
    ("macro-item-view", "impl_item"),
    ("macro-item-view", "macro_definition"),
    ("macro-item-view", "macro_invocation"),
    ("macro-item-view", "mod_item"),
    ("macro-item-view", "static_item"),
    ("macro-item-view", "struct_item"),
    ("macro-item-view", "trait_item"),
    ("macro-item-view", "type_item"),
    ("macro-item-view", "union_item"),
    ("macro-item-view", "use_declaration"),
    ("self-constructor", "identifier"),
    ("scoped-call", "scoped_identifier"),
    ("struct-literal", "let_declaration"),
    ("struct-literal", "assignment_expression"),
    ("struct-literal", "struct_expression"),
    ("struct-literal", "field_initializer_list"),
    ("struct-literal", "field_initializer"),
    ("struct-literal", "shorthand_field_initializer"),
    ("cast-local-type", "type_cast_expression"),
    ("destructured-parameter", "parameter"),
    ("visibility", "visibility_modifier"),
    ("tuple-struct-fields", "ordered_field_declaration_list"),
    ("struct-fields", "field_declaration_list"),
    ("struct-fields", "field_declaration"),
    ("field-type", "reference_type"),
    ("field-type", "pointer_type"),
    ("field-type", "generic_type"),
    ("field-type", "type_identifier"),
    ("field-type", "scoped_type_identifier"),
    ("imports", "scoped_use_list"),
    ("imports", "use_list"),
    ("imports", "use_as_clause"),
    ("imports", "use_wildcard"),
    ("imports", "self"),
    ("imports", "metavariable"),
    ("imports", "crate"),
    ("imports", "super"),
];

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
            unqualified_imports_search_current_directory: false,
            workspace_manifest_context_extensions: &[],
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        ADDITIONAL_GRAMMAR_NODE_KINDS
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
        let format_macros = collect_rust_format_macros(tree, file, src);
        mark_rust_format_macro_values_as_syntax_propagated(&mut idx, &format_macros);
        // Phase-6 return-type extraction: `fn f() -> T {}` populates
        // `Decl.return_type` for `apply_assign_call_result_types`.
        bonsai_lang_api::populate_decl_return_types(&mut idx, tree, src, &HANDLER);
        let struct_literal_field_assigns = collect_rust_struct_literal_field_assigns(tree, file, src);
        let chained_method_assignment_receivers =
            collect_rust_chained_method_assignment_receivers(tree, file, src);
        let scoped_call_spans = collect_rust_scoped_call_spans(tree, file);
        let self_constructor_call_spans = collect_rust_self_constructor_call_spans(tree, file, src);
        let exported_import_aliases = collect_rust_exported_import_aliases(tree, file, src);
        let format_nested_calls = collect_rust_format_nested_calls(tree, file, src);
        for decl in &mut idx.defs {
            let owner_span = decl.span;
            enrich_rust_struct_literal_field_assigns(&mut decl.flow_events, &struct_literal_field_assigns);
            enrich_rust_chained_method_assignment_receivers(
                &mut decl.flow_events,
                &chained_method_assignment_receivers,
            );
            classify_rust_scoped_calls(&mut decl.flow_events, &scoped_call_spans);
            classify_rust_self_constructor_calls(&mut decl.flow_events, &self_constructor_call_spans);
            enrich_rust_format_macro_operands(&mut decl.flow_events, &format_macros, owner_span);
            enrich_rust_format_nested_call_events(&mut decl.flow_events, &format_nested_calls);
            enrich_rust_tail_return_sources(&mut decl.flow_events, &decl.params);
            enrich_rust_constructor_field_writes(decl);
        }
        enrich_rust_format_nested_call_value_facts(&mut idx, &format_nested_calls);
        idx.finite_literal_selections = idx
            .defs
            .iter()
            .filter_map(|decl| {
                bonsai_lang_api::kit::complete_finite_literal_return_span(&decl.flow_events).map(
                    |selection_span| bonsai_lang_api::FiniteLiteralSelectionFact {
                        selection_span,
                        assignment_span: None,
                        target: None,
                        call_span: None,
                        argument_index: None,
                    },
                )
            })
            .collect();
        bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut idx.finite_literal_selections);
        append_rust_exported_import_decls(&mut idx, exported_import_aliases);
        // Rust module_path: relative file path under workspace root,
        // dropping `src/` and `lib.rs`/`mod.rs`/`<name>.rs` to produce
        // a `crate::mod::sub`-shaped path. Falls back to file-stem.
        let semantic_path = ctx
            .workspace_relative_path(file)
            .or_else(|| ctx.vfs.path(file).ok().map(|path| (*path).clone()));
        let segments = semantic_path
            .as_deref()
            .map(rust_module_segments)
            .unwrap_or_default();
        if let Some(path) = semantic_path.as_deref() {
            let crate_root = rust_crate_root_segments(path);
            for decl in &mut idx.defs {
                normalize_rust_rooted_calls(&mut decl.flow_events, &segments, crate_root.as_deref());
            }
        }
        // Rust visibility from `pub`, `pub(crate)`, `pub(super)`,
        // `pub(in path)`. Absence = private (file/mod-scoped).
        {
            let visibility_by_span = collect_rust_visibility(tree.root_node(), file, src);
            let mut alias_map = collect_param_type_aliases(tree, file, src, &RUST_TYPE_ALIASES);
            for (span, bindings) in collect_rust_explicit_local_type_aliases(tree, file, src) {
                let aliases = alias_map.entry(span).or_default();
                for binding in bindings {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            for (span, bindings) in collect_rust_cast_local_type_aliases(tree, file, src) {
                let aliases = alias_map.entry(span).or_default();
                for binding in bindings {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            for (span, bindings) in collect_rust_param_type_identities(tree, file, src) {
                let aliases = alias_map.entry(span).or_default();
                for binding in bindings {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            // The shared short-type collector intentionally handles many
            // grammars. Rust reference syntax can otherwise leave a modifier
            // fragment such as `mut Client` beside the exact nominal
            // identities emitted above. That fragment is not a Rust type
            // path and must never participate in receiver/provider identity.
            // Keep only grammar-valid nominal paths; the Rust-specific type
            // walk already preserves `Client` and every qualified import.
            for aliases in alias_map.values_mut() {
                aliases.retain(|alias| rust_nominal_type_alias(&alias.type_name));
            }
            let tuple_struct_bases = collect_rust_tuple_struct_bases(tree, file, src);
            let impl_trait_bases = collect_rust_impl_trait_bases(tree, src);
            let trait_impl_method_spans = collect_rust_trait_impl_method_spans(tree, file);
            let struct_field_aliases = collect_rust_struct_field_aliases(tree, src);
            let imports = parse_imports(tree, src, file);
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
                // Rust forbids an explicit `pub` modifier on trait-impl
                // methods: their callable visibility is supplied by the
                // implemented trait. Preserve that compiler fact so a typed
                // call from another module can resolve to the exact declared
                // implementation instead of treating its syntactically bare
                // method as module-private.
                if trait_impl_method_spans.contains(&decl.span) {
                    decl.visibility = Visibility::Public;
                }
                if let Some(aliases) = alias_map.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
                if let Some(bases) = tuple_struct_bases.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
                for (_, trait_name) in impl_trait_bases
                    .iter()
                    .filter(|(type_name, _)| type_name == &decl.name)
                {
                    if !decl.bases.iter().any(|base| base == trait_name) {
                        decl.bases.push(trait_name.clone());
                    }
                }
                if decl.parent.is_none() {
                    if let Some(parent_symbol) = impl_method_parent_symbols
                        .iter()
                        .find_map(|(span, parent_symbol)| (*span == decl.span).then_some(*parent_symbol))
                    {
                        decl.parent = Some(parent_symbol);
                    }
                }
                // Every Rust `self` parameter has the exact type named by
                // its enclosing `impl Type` syntax, even when the type
                // declaration lives in another module/file. Retain that
                // compiler fact independently from the file-local parent
                // symbol: global resolution can then combine it with this
                // file's `use` bindings to resolve `self.method()` across
                // split impl blocks without a bare-name fallback.
                if let Some(owner_type) = impl_method_parents
                    .iter()
                    .find_map(|(span, owner_type)| (*span == decl.span).then_some(owner_type))
                {
                    if let Some(receiver_name) = decl
                        .receiver_param_index
                        .and_then(|index| decl.params.get(index))
                        .filter(|name| !name.is_empty())
                    {
                        let receiver_is_typed =
                            decl.type_aliases.iter().any(|alias| alias.name == *receiver_name);
                        if !receiver_is_typed {
                            decl.type_aliases.push(TypeAliasBinding {
                                name: receiver_name.clone(),
                                type_name: owner_type.clone(),
                            });
                        }
                    }
                }
            }
            apply_rust_struct_field_aliases(&mut idx, &struct_field_aliases);
            qualify_rust_declared_type_aliases(&mut idx, &imports);
            enrich_rust_self_tuple_constructor_returns(&mut idx);
            classify_rust_declared_constructor_calls(&mut idx);
        }
        // Parent symbols come from `impl Type` syntax and must be installed
        // before qualified member identities are derived. Applying module
        // identity first leaves methods as `module.method` instead of
        // `module.Type.method`, weakening navigation and split-impl linkage.
        if !segments.is_empty() {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        normalize_rust_assigned_match_arm_exits(&mut idx, tree, file, src);
        normalize_rust_match_unwrap_assignments(&mut idx, tree, file, src);
        populate_rust_const_static_values(&mut idx, tree, file, src);
        bonsai_lang_api::kit::populate_call_argument_static_values(
            &mut idx,
            tree,
            file,
            src,
            &HANDLER,
            rust_static_scalar,
        );
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Propagate adapter-classified constructor result types onto local
        // receivers so later method dispatch consumes the same semantic fact.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        // Parameter-pattern aliases are attached after generic lowering. Rejoin
        // those exact compiler types to receiver calls once all adapter-owned
        // aliases are present; otherwise `Wrapper(value): Wrapper<dyn Trait>`
        // retains the declaration fact but leaves `value.method()` untyped.
        bonsai_lang_api::apply_call_receiver_types(&mut idx);
        apply_rust_iife_receiver_types(&mut idx, tree, file, src);
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
        let mut imports = parse_imports(tree, src, file);
        if let Some(path) = ctx
            .workspace_relative_path(file)
            .or_else(|| ctx.vfs.path(file).ok().map(|path| (*path).clone()))
        {
            let current_module = rust_module_segments(&path);
            let crate_root = rust_crate_root_segments(&path);
            for import in &mut imports {
                import.module =
                    normalize_rust_rooted_path(&import.module, &current_module, crate_root.as_deref());
            }
        }
        ImportIndex { file, imports }
    }
}

/// A Rust match arm's final expression is the value of the `match`, but it is
/// only a function return when the complete match is itself in callable-tail
/// position. The shared tail-return lowering intentionally synthesizes arm
/// returns for the latter case. When a `match` is the RHS of an assignment,
/// those same events would instead terminate the enclosing CFG and erase every
/// statement after the assignment.
///
/// Remove only the synthetic returns whose spans are the exact Tree-sitter
/// `value` nodes of arms owned by an assigned match. Explicit `return`,
/// `break`, and `continue` expressions have different CST spans and remain
/// abrupt. The assignment's compiler value-flow already retains the union of
/// its arm operands, so this changes control-flow classification without
/// discarding data dependencies.
fn normalize_rust_assigned_match_arm_exits(index: &mut DeclIndex, tree: &Tree, file: FileId, _src: &[u8]) {
    let mut value_spans = std::collections::HashSet::new();
    for assignment in collect_kinds(tree, &["let_declaration", "assignment_expression"]) {
        let Some(value) = assignment.child_by_field_name("value") else {
            continue;
        };
        let Some(match_expression) = rust_transparent_assigned_match(value) else {
            continue;
        };
        let Some(body) = match_expression.child_by_field_name("body") else {
            continue;
        };
        let mut cursor = body.walk();
        for arm in body
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "match_arm")
        {
            let Some(arm_value) = arm.child_by_field_name("value") else {
                continue;
            };
            if matches!(
                arm_value.kind(),
                "return_expression" | "break_expression" | "continue_expression"
            ) {
                continue;
            }
            value_spans.insert(span_of(file, &arm_value));
        }
    }
    if value_spans.is_empty() {
        return;
    }
    for declaration in &mut index.defs {
        remove_rust_synthetic_arm_returns(&mut declaration.flow_events, &value_spans);
    }
}

fn rust_transparent_assigned_match(mut value: Node<'_>) -> Option<Node<'_>> {
    while value.kind() == "parenthesized_expression" && value.named_child_count() == 1 {
        value = value.named_child(0)?;
    }
    (value.kind() == "match_expression").then_some(value)
}

fn remove_rust_synthetic_arm_returns(
    events: &mut Vec<FlowEvent>,
    value_spans: &std::collections::HashSet<Span>,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                remove_rust_synthetic_arm_returns(then_events, value_spans);
                remove_rust_synthetic_arm_returns(else_events, value_spans);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                remove_rust_synthetic_arm_returns(body, value_spans);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                remove_rust_synthetic_arm_returns(body, value_spans);
                remove_rust_synthetic_arm_returns(catch_events, value_spans);
                remove_rust_synthetic_arm_returns(finally_events, value_spans);
            }
            _ => {}
        }
    }
    events.retain(|event| !matches!(event, FlowEvent::Return { span, .. } if value_spans.contains(span)));
}

/// Treat a `match call() { Pattern(value) => value, ...abrupt arms... }`
/// initializer as the exact result of `call()`. This is a Rust control-flow
/// fact, independent of the enum or API spelling: every continuing arm must
/// return the one binding introduced by its own pattern, while every other
/// arm must leave the function.
fn normalize_rust_match_unwrap_assignments(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for declaration in collect_kinds(tree, &["let_declaration"]) {
        let (Some(pattern), Some(value)) = (
            declaration.child_by_field_name("pattern"),
            declaration.child_by_field_name("value"),
        ) else {
            continue;
        };
        if pattern.kind() != "identifier" || value.kind() != "match_expression" {
            continue;
        }
        let Some(discriminant) = value.child_by_field_name("value") else {
            continue;
        };
        if discriminant.kind() != "call_expression" {
            continue;
        }
        let Some(block) = value.child_by_field_name("body") else {
            continue;
        };
        let mut continuing_bindings = Vec::new();
        let mut every_other_arm_abrupt = true;
        let mut cursor = block.walk();
        for arm in block
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "match_arm")
        {
            let (Some(arm_pattern), Some(arm_value)) = (
                arm.child_by_field_name("pattern"),
                arm.child_by_field_name("value"),
            ) else {
                every_other_arm_abrupt = false;
                break;
            };
            if matches!(
                arm_value.kind(),
                "return_expression" | "break_expression" | "continue_expression"
            ) {
                continue;
            }
            if arm_value.kind() != "identifier" {
                every_other_arm_abrupt = false;
                break;
            }
            let returned = node_text(&arm_value, src).trim();
            let mut bound_here = false;
            let mut stack = vec![arm_pattern];
            while let Some(node) = stack.pop() {
                if node.kind() == "identifier" && node_text(&node, src).trim() == returned {
                    bound_here = true;
                    break;
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            if !bound_here {
                every_other_arm_abrupt = false;
                break;
            }
            continuing_bindings.push(returned.to_string());
        }
        if !every_other_arm_abrupt || continuing_bindings.len() != 1 {
            continue;
        }
        let target = node_text(&pattern, src).trim().to_string();
        if target.is_empty() {
            continue;
        }
        let Some(call_target) = rust_call_target(discriminant, src) else {
            continue;
        };
        let call_span = span_of(file, &call_target.node);
        let mut call_args = None;
        for decl in &index.defs {
            if decl.span.file == call_span.file
                && decl.span.start <= call_span.start
                && call_span.end <= decl.span.end
            {
                call_args = rust_flow_call_args(&decl.flow_events, call_span);
                if call_args.is_some() {
                    break;
                }
            }
        }
        let Some(call_args) = call_args else {
            continue;
        };
        let declaration_span = span_of(file, &declaration);
        for decl in &mut index.defs {
            rewrite_rust_match_assignment_event(
                &mut decl.flow_events,
                declaration_span,
                &target,
                &call_target.full_text,
                &call_args,
            );
        }
        if let Some(fact) = index
            .assignment_values
            .iter_mut()
            .find(|fact| fact.assignment_span == declaration_span && fact.target.as_deref() == Some(&target))
        {
            fact.direct_call_name = Some(call_target.full_text.clone());
            fact.direct_call_receiver = call_target
                .full_text
                .rsplit_once("::")
                .map(|(receiver, _)| receiver.to_string());
            fact.value_flow = bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                discriminant,
                file,
                src,
                &HANDLER,
            );
            fact.call_sites = fact.value_flow.call_sites.clone();
            fact.value_span = span_of(file, &discriminant);
        }
    }
}

fn rust_flow_call_args(events: &[FlowEvent], call_span: Span) -> Option<Vec<String>> {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } if *span == call_span => {
                return Some(args.iter().map(|arg| arg.value_text.clone()).collect());
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(args) = rust_flow_call_args(then_events, call_span)
                    .or_else(|| rust_flow_call_args(else_events, call_span))
                {
                    return Some(args);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(args) = rust_flow_call_args(body, call_span) {
                    return Some(args);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(args) = rust_flow_call_args(body, call_span)
                    .or_else(|| rust_flow_call_args(catch_events, call_span))
                    .or_else(|| rust_flow_call_args(finally_events, call_span))
                {
                    return Some(args);
                }
            }
            _ => {}
        }
    }
    None
}

fn rewrite_rust_match_assignment_event(
    events: &mut [FlowEvent],
    assignment_span: Span,
    target: &str,
    source_call: &str,
    source_call_args: &[String],
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target: event_target,
                source_call: event_source_call,
                source_call_args: event_args,
                value_kind,
                ..
            } if *span == assignment_span && event_target == target => {
                *event_source_call = Some(source_call.to_string());
                *event_args = source_call_args.to_vec();
                *value_kind = Some(bonsai_lang_api::AssignValueKind::CallResult);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_rust_match_assignment_event(
                    then_events,
                    assignment_span,
                    target,
                    source_call,
                    source_call_args,
                );
                rewrite_rust_match_assignment_event(
                    else_events,
                    assignment_span,
                    target,
                    source_call,
                    source_call_args,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_rust_match_assignment_event(
                    body,
                    assignment_span,
                    target,
                    source_call,
                    source_call_args,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_rust_match_assignment_event(
                    body,
                    assignment_span,
                    target,
                    source_call,
                    source_call_args,
                );
                rewrite_rust_match_assignment_event(
                    catch_events,
                    assignment_span,
                    target,
                    source_call,
                    source_call_args,
                );
                rewrite_rust_match_assignment_event(
                    finally_events,
                    assignment_span,
                    target,
                    source_call,
                    source_call_args,
                );
            }
            _ => {}
        }
    }
}

fn populate_rust_const_static_values(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    for declaration in collect_kinds(tree, &["const_item"]) {
        let (Some(name), Some(value)) = (
            declaration.child_by_field_name("name"),
            declaration.child_by_field_name("value"),
        ) else {
            continue;
        };
        let Some(static_value) = rust_static_scalar(value, src) else {
            continue;
        };
        let target = node_text(&name, src).trim();
        let span = span_of(file, &declaration);
        if index
            .assignment_values
            .iter()
            .any(|fact| fact.assignment_span == span && fact.target.as_deref() == Some(target))
        {
            continue;
        }
        index
            .assignment_values
            .push(bonsai_lang_api::AssignmentValueFact {
                assignment_span: span,
                target: Some(target.to_string()),
                target_is_immutable: true,
                target_owner: None,
                target_span: Some(span_of(file, &name)),
                value_span: span_of(file, &value),
                call_sites: Vec::new(),
                value_flow: bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                    value, file, src, &HANDLER,
                ),
                static_value: Some(static_value),
                exact_callable_return: None,
                inline_callback_static_return: None,
                inline_callback_fields: Vec::new(),
                exact_static_call_args: None,
                direct_call_name: None,
                direct_call_span: None,
                direct_call_receiver: None,
                direct_call_receiver_span: None,
                direct_call_receiver_flow: None,
            });
    }
    index.assignment_values.sort_by_key(|fact| {
        (
            fact.assignment_span.start,
            fact.assignment_span.end,
            fact.target_span.map_or(0, |span| span.start),
        )
    });
    index.assignment_values.dedup();
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
        if matches!(visibility, Visibility::Private | Visibility::ModuleTree) {
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
            if !rust_call_target_is_scoped_path(function) {
                return None;
            }
            // `rust_call_target` deliberately unwraps `generic_function` so
            // `path::call::<T>` has the same callable identity/span as
            // `path::call`. Classification must use that exact canonical
            // target span as well; comparing the surrounding turbofish span
            // cannot match the emitted Call fact.
            let canonical = if function.kind() == "generic_function" {
                function
                    .child_by_field_name("function")
                    .or_else(|| function.child_by_field_name("name"))
                    .or_else(|| function.named_child(0))?
            } else {
                function
            };
            Some(span_of(file, &canonical))
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

/// Attach the explicit return type of an immediately-invoked closure to a
/// method call on that result.
///
/// Rust permits expressions such as
/// `(|| -> Result<T, E> { ... })().unwrap_or_else(...)`. The shared receiver
/// typer intentionally works from addressable bindings and therefore cannot
/// infer the type of the anonymous call result. Tree-sitter exposes the
/// closure's declared `return_type` exactly, so the Rust frontend can retain
/// that compiler fact without assigning meaning to `Result` or to the method
/// being called. Rulepack typing summaries may then select the exact typed
/// call span.
fn apply_rust_iife_receiver_types(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut types_by_call_span = std::collections::HashMap::<Span, Vec<String>>::new();
    for call in collect_kinds(tree, &["call_expression"]) {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        if function.kind() != "field_expression" {
            continue;
        }
        let Some(receiver_call) = function.child_by_field_name("value") else {
            continue;
        };
        if receiver_call.kind() != "call_expression" {
            continue;
        }
        let Some(mut invoked) = receiver_call.child_by_field_name("function") else {
            continue;
        };
        while invoked.kind() == "parenthesized_expression" {
            let mut cursor = invoked.walk();
            let Some(inner) = invoked.named_children(&mut cursor).next() else {
                break;
            };
            invoked = inner;
        }
        if invoked.kind() != "closure_expression" {
            continue;
        }
        let Some(return_type) = invoked.child_by_field_name("return_type") else {
            continue;
        };
        let nominal = if return_type.kind() == "generic_type" {
            return_type.child_by_field_name("type").unwrap_or(return_type)
        } else {
            return_type
        };
        let type_name = node_text(&nominal, src).trim().to_string();
        if type_name.is_empty() || !rust_nominal_type_alias(&type_name) {
            continue;
        }
        types_by_call_span
            .entry(span_of(file, &function))
            .or_default()
            .push(type_name);
    }
    if types_by_call_span.is_empty() {
        return;
    }
    for decl in &mut idx.defs {
        apply_rust_iife_receiver_types_to_events(&mut decl.flow_events, &types_by_call_span);
    }
}

fn apply_rust_iife_receiver_types_to_events(
    events: &mut [FlowEvent],
    types_by_call_span: &std::collections::HashMap<Span, Vec<String>>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                span, receiver_types, ..
            } => {
                if let Some(types) = types_by_call_span.get(span) {
                    for type_name in types {
                        if !receiver_types.contains(type_name) {
                            receiver_types.push(type_name.clone());
                        }
                    }
                    receiver_types.sort();
                    receiver_types.dedup();
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_rust_iife_receiver_types_to_events(then_events, types_by_call_span);
                apply_rust_iife_receiver_types_to_events(else_events, types_by_call_span);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_rust_iife_receiver_types_to_events(body, types_by_call_span);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_rust_iife_receiver_types_to_events(body, types_by_call_span);
                apply_rust_iife_receiver_types_to_events(catch_events, types_by_call_span);
                apply_rust_iife_receiver_types_to_events(finally_events, types_by_call_span);
            }
            _ => {}
        }
    }
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

/// Preserve the addressable base of a chained method-call result used as an
/// assignment value. Rust represents `values.into_iter().map(...).collect()`
/// as nested call/field expressions. Shared call-result normalization keeps
/// data-bearing receivers, but the outer receiver is itself a call and has no
/// addressable place. Lower the exact parsed chain base (`values`) so iterator
/// and builder pipelines retain their input dependency without assigning
/// semantics to any method name.
fn collect_rust_chained_method_assignment_receivers(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for assignment in collect_kinds(tree, &["let_declaration", "assignment_expression"]) {
        let Some(value) = assignment.child_by_field_name("value") else {
            continue;
        };
        let Some(base) = rust_chained_method_call_base(value, file, src) else {
            continue;
        };
        out.push((span_of(file, &assignment), base));
    }
    out.sort();
    out.dedup();
    out
}

fn rust_chained_method_call_base(node: Node<'_>, file: FileId, src: &[u8]) -> Option<String> {
    let node = rust_transparent_value_node(node)?;
    if node.kind() != "call_expression" {
        return None;
    }
    let function = rust_transparent_call_target(node.child_by_field_name("function")?)?;
    if function.kind() != "field_expression" {
        return None;
    }
    let receiver = function.child_by_field_name("value")?;
    rust_method_receiver_base(receiver, file, src)
}

fn rust_method_receiver_base(node: Node<'_>, file: FileId, src: &[u8]) -> Option<String> {
    let node = rust_transparent_value_node(node)?;
    match node.kind() {
        "call_expression" => {
            let function = rust_transparent_call_target(node.child_by_field_name("function")?)?;
            if function.kind() != "field_expression" {
                return None;
            }
            rust_method_receiver_base(function.child_by_field_name("value")?, file, src)
        }
        "field_expression" => rust_method_receiver_base(node.child_by_field_name("value")?, file, src),
        _ => call_arg_from_node_with_handler(node, file, src, None, &HANDLER).and_then(|arg| arg.place),
    }
}

fn rust_transparent_call_target(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "generic_function" {
        node = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.named_child(0))?;
    }
    Some(node)
}

fn rust_transparent_value_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while matches!(
        node.kind(),
        "parenthesized_expression" | "try_expression" | "await_expression"
    ) && node.named_child_count() == 1
    {
        node = node.named_child(0)?;
    }
    Some(node)
}

fn enrich_rust_chained_method_assignment_receivers(events: &mut [FlowEvent], receivers: &[(Span, String)]) {
    let outer_calls = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                span,
                source_call: Some(source_call),
                ..
            } => receivers.iter().find_map(|(assignment_span, receiver)| {
                (assignment_span == span).then(|| (*span, source_call.clone(), receiver.clone()))
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_call: Some(_),
                source_names,
                ..
            } => {
                for (_, receiver) in receivers
                    .iter()
                    .filter(|(assignment_span, _)| assignment_span == span)
                {
                    if !source_names.iter().any(|source| source == receiver) {
                        source_names.push(receiver.clone());
                    }
                }
                source_names.sort();
                source_names.dedup();
            }
            FlowEvent::Call {
                span,
                name,
                receiver,
                call_kind,
                ..
            } => {
                if let Some((_, _, base)) = outer_calls.iter().find(|(assignment_span, source_call, _)| {
                    assignment_span.file == span.file
                        && assignment_span.start <= span.start
                        && span.end <= assignment_span.end
                        && source_call == name
                }) {
                    if receiver.is_none() {
                        *receiver = Some(base.clone());
                    }
                    *call_kind = CallKind::Method;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_chained_method_assignment_receivers(then_events, receivers);
                enrich_rust_chained_method_assignment_receivers(else_events, receivers);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_chained_method_assignment_receivers(body, receivers);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_chained_method_assignment_receivers(body, receivers);
                enrich_rust_chained_method_assignment_receivers(catch_events, receivers);
                enrich_rust_chained_method_assignment_receivers(finally_events, receivers);
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

#[derive(Clone, Debug)]
struct RustFormatMacroFact {
    call_span: Span,
    invocation_span: Span,
    owner_span: Span,
    captures: Vec<String>,
}

/// Lower the implicit named operands of Rust's standard formatting macros
/// from their exact Tree-sitter token trees. The format mini-language is Rust
/// compiler/runtime semantics; the surrounding expression is never recovered
/// by reparsing a rendered `CallArg::value_text` string.
fn collect_rust_format_macros(tree: &Tree, file: FileId, src: &[u8]) -> Vec<RustFormatMacroFact> {
    let mut facts = Vec::new();
    for invocation in collect_kinds(tree, &["macro_invocation"]) {
        let Some(macro_node) = invocation.child_by_field_name("macro") else {
            continue;
        };
        if !matches!(node_text(&macro_node, src).trim(), "format" | "format_args") {
            continue;
        }
        let Some(token_tree) = first_named_child_of_kind_local(invocation, "token_tree") else {
            continue;
        };
        let mut cursor = token_tree.walk();
        let Some(format_literal) = token_tree
            .named_children(&mut cursor)
            .find(|child| matches!(child.kind(), "string_literal" | "raw_string_literal"))
        else {
            continue;
        };
        let Some(literal) = rust_static_string(node_text(&format_literal, src).trim()) else {
            continue;
        };
        let Some(owner_span) = rust_nearest_callable_span(invocation, file) else {
            continue;
        };
        facts.push(RustFormatMacroFact {
            call_span: span_of(file, &macro_node),
            invocation_span: span_of(file, &invocation),
            owner_span,
            captures: rust_format_named_captures_from_literal(&literal),
        });
    }
    facts.sort_by_key(|fact| (fact.invocation_span.start, fact.invocation_span.end));
    facts.dedup_by(|left, right| left.invocation_span == right.invocation_span);
    facts
}

fn rust_nearest_callable_span(mut node: Node<'_>, file: FileId) -> Option<Span> {
    while let Some(parent) = node.parent() {
        if HANDLER.fn_kinds.contains(&parent.kind()) || HANDLER.lambda_kinds.contains(&parent.kind()) {
            return Some(span_of(file, &parent));
        }
        node = parent;
    }
    None
}

fn enrich_rust_format_macro_operands(
    events: &mut [FlowEvent],
    facts: &[RustFormatMacroFact],
    owner_span: Span,
) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    for fact in facts.iter().filter(|fact| {
                        fact.owner_span == owner_span
                            && arg.span.file == fact.invocation_span.file
                            && arg.span.start <= fact.invocation_span.start
                            && fact.invocation_span.end <= arg.span.end
                    }) {
                        for capture in &fact.captures {
                            if !arg.source_names.iter().any(|existing| existing == capture) {
                                arg.source_names.push(capture.clone());
                            }
                        }
                    }
                    arg.source_names.sort();
                    arg.source_names.dedup();
                }
            }
            FlowEvent::Assign {
                span, source_names, ..
            } => {
                for fact in facts.iter().filter(|fact| {
                    fact.owner_span == owner_span
                        && span.file == fact.invocation_span.file
                        && span.start <= fact.invocation_span.start
                        && fact.invocation_span.end <= span.end
                }) {
                    for capture in &fact.captures {
                        if !source_names.iter().any(|existing| existing == capture) {
                            source_names.push(capture.clone());
                        }
                    }
                }
                source_names.sort();
                source_names.dedup();
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_format_macro_operands(then_events, facts, owner_span);
                enrich_rust_format_macro_operands(else_events, facts, owner_span);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_format_macro_operands(body, facts, owner_span);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_format_macro_operands(body, facts, owner_span);
                enrich_rust_format_macro_operands(catch_events, facts, owner_span);
                enrich_rust_format_macro_operands(finally_events, facts, owner_span);
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug)]
struct RustFormatNestedCall {
    format_call_span: Span,
    call_span: Span,
    name: String,
    args: Vec<CallArg>,
}

/// Lower ordinary Rust expression calls nested inside `format!` and
/// `format_args!` token trees. Tree-sitter intentionally exposes macro input
/// as a token tree rather than a Rust expression, so the generic walker cannot
/// see `normalize(value)` in `format!("{}", normalize(value))`. The Rust
/// frontend still has exact CST structure for a function target immediately
/// followed by its argument token tree; retain that call edge without parsing
/// rendered text or assigning any library/security meaning.
fn collect_rust_format_nested_calls(tree: &Tree, file: FileId, src: &[u8]) -> Vec<RustFormatNestedCall> {
    let mut calls = Vec::new();
    for invocation in collect_kinds(tree, &["macro_invocation"]) {
        let Some(macro_node) = invocation.child_by_field_name("macro") else {
            continue;
        };
        if !matches!(node_text(&macro_node, src).trim(), "format" | "format_args") {
            continue;
        }
        let Some(token_tree) = first_named_child_of_kind_local(invocation, "token_tree") else {
            continue;
        };
        collect_rust_calls_from_format_token_tree(
            token_tree,
            span_of(file, &macro_node),
            file,
            src,
            &mut calls,
        );
    }
    calls.sort_by_key(|call| (call.call_span.start, call.call_span.end));
    calls.dedup_by(|left, right| left.call_span == right.call_span && left.name == right.name);
    calls
}

fn collect_rust_calls_from_format_token_tree(
    token_tree: Node<'_>,
    format_call_span: Span,
    file: FileId,
    src: &[u8],
    out: &mut Vec<RustFormatNestedCall>,
) {
    let mut cursor = token_tree.walk();
    let named = token_tree.named_children(&mut cursor).collect::<Vec<_>>();
    for pair in named.windows(2) {
        let [target, arguments] = pair else {
            continue;
        };
        if arguments.kind() != "token_tree"
            || !matches!(
                target.kind(),
                "identifier" | "scoped_identifier" | "generic_function"
            )
            || src
                .get(target.end_byte()..arguments.start_byte())
                .is_none_or(|gap| !gap.iter().all(u8::is_ascii_whitespace))
        {
            continue;
        }
        let name = bonsai_lang_api::kit::normalize_call_name_whitespace(node_text(target, src));
        if name.is_empty() {
            continue;
        }
        out.push(RustFormatNestedCall {
            format_call_span,
            call_span: span_of(file, target),
            name,
            args: rust_token_tree_call_args(*arguments, file, src),
        });
    }
    for child in named {
        if child.kind() == "token_tree" {
            collect_rust_calls_from_format_token_tree(child, format_call_span, file, src, out);
        }
    }
}

fn rust_token_tree_call_args(arguments: Node<'_>, file: FileId, src: &[u8]) -> Vec<CallArg> {
    let mut groups = Vec::<Vec<Node<'_>>>::new();
    let mut current = Vec::new();
    let mut cursor = arguments.walk();
    for child in arguments.children(&mut cursor) {
        if child.kind() == "," {
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
            }
        } else if child.is_named() {
            current.push(child);
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }

    groups
        .into_iter()
        .filter_map(|nodes| {
            if let [node] = nodes.as_slice() {
                return call_arg_from_node_with_handler(*node, file, src, None, &HANDLER);
            }
            let first = nodes.first()?;
            let last = nodes.last()?;
            let start = first.start_byte();
            let end = last.end_byte();
            let value_text = std::str::from_utf8(src.get(start..end)?).ok()?.trim().to_string();
            if value_text.is_empty() {
                return None;
            }
            let mut source_names = nodes
                .iter()
                .filter_map(|node| call_arg_from_node_with_handler(*node, file, src, None, &HANDLER))
                .flat_map(|argument| {
                    argument
                        .place
                        .into_iter()
                        .chain(argument.source_names)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            source_names.sort();
            source_names.dedup();
            Some(CallArg {
                span: Span::new(file, start as u64, end as u64),
                passing_mode: ArgumentPassingMode::Value,
                name: None,
                value_text,
                place: None,
                source_names,
            })
        })
        .collect()
}

fn enrich_rust_format_nested_call_events(events: &mut Vec<FlowEvent>, calls: &[RustFormatNestedCall]) {
    let mut enriched = Vec::with_capacity(events.len() + calls.len());
    for mut event in std::mem::take(events) {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_rust_format_nested_call_events(then_events, calls);
                enrich_rust_format_nested_call_events(else_events, calls);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_rust_format_nested_call_events(body, calls);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_rust_format_nested_call_events(body, calls);
                enrich_rust_format_nested_call_events(catch_events, calls);
                enrich_rust_format_nested_call_events(finally_events, calls);
            }
            _ => {}
        }
        if let FlowEvent::Call { span, .. } = &event {
            for call in calls.iter().filter(|call| call.format_call_span == *span) {
                enriched.push(FlowEvent::Call {
                    span: call.call_span,
                    name: call.name.clone(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args: call.args.clone(),
                });
            }
        }
        enriched.push(event);
    }
    *events = enriched;
}

fn enrich_rust_format_nested_call_value_facts(index: &mut DeclIndex, calls: &[RustFormatNestedCall]) {
    for fact in &mut index.assignment_values {
        for call in calls.iter().filter(|call| {
            call.call_span.file == fact.value_span.file
                && fact.value_span.start <= call.call_span.start
                && call.call_span.end <= fact.value_span.end
        }) {
            fact.call_sites.push(call.call_span);
            fact.value_flow.call_sites.push(call.call_span);
        }
        fact.call_sites.sort_unstable();
        fact.call_sites.dedup();
        fact.value_flow.call_sites.sort_unstable();
        fact.value_flow.call_sites.dedup();
    }
    for fact in &mut index.call_argument_values {
        for call in calls.iter().filter(|call| {
            call.call_span.file == fact.argument_span.file
                && fact.argument_span.start <= call.call_span.start
                && call.call_span.end <= fact.argument_span.end
        }) {
            fact.value_flow.call_sites.push(call.call_span);
        }
        fact.value_flow.call_sites.sort_unstable();
        fact.value_flow.call_sites.dedup();
    }
}

/// `format!` and `format_args!` are compiler-expanded value expressions: the
/// rendered result contains their format operands by Rust language semantics.
/// They are not ordinary calls whose result depends on an unresolved callee
/// body. Marking the exact argument expression this way lets shared IDG
/// lowering consume the adapter-emitted operand facts without teaching the
/// graph core any Rust macro names.
fn mark_rust_format_macro_values_as_syntax_propagated(index: &mut DeclIndex, facts: &[RustFormatMacroFact]) {
    for fact in &mut index.call_argument_values {
        if facts.iter().any(|format| {
            fact.argument_span.file == format.invocation_span.file
                && fact.argument_span.start <= format.invocation_span.start
                && format.invocation_span.end <= fact.argument_span.end
                && fact.direct_call_span == Some(format.call_span)
        }) {
            fact.direct_call_span = None;
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
                let value_flow =
                    bonsai_lang_api::kit::expression_flow_from_node_with_handler(value, file, src, &HANDLER);
                let mut source_names = value_flow.source_names;
                if let Some(place) = value_flow.place {
                    if !source_names.iter().any(|source| source == &place) {
                        source_names.push(place);
                    }
                }
                let mut nested_events = Vec::new();
                bonsai_lang_api::kit::walk_flow_node_into(
                    value,
                    file,
                    src,
                    &HANDLER,
                    &[],
                    &mut nested_events,
                );
                collect_rust_value_event_sources(&nested_events, &mut source_names);
                source_names.sort();
                source_names.dedup();
                if source_names.is_empty() {
                    continue;
                }
                // The synthetic field assignment is added after the generic
                // declaration walk because the field's storage base comes
                // from the assignment target type. Preserve the executable
                // facts inside the initializer as well: a value such as
                // `routed.clone()` is a method result derived from `routed`,
                // not a structural read of a hypothetical `clone` field.
                // Reuse the canonical Tree-sitter flow walker so shared IDG
                // lowering never has to infer call syntax from rendered
                // source names.
                out.extend(nested_events);
                out.push(FlowEvent::Assign {
                    span: span_of(file, &field_node),
                    target: format!("{target}.{field_name}"),
                    source_name: (value.kind() == "identifier" && rust_bare_identifier(value_text))
                        .then(|| value_text.to_string()),
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

fn collect_rust_value_event_sources(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Call { receiver, args, .. } => {
                if let Some(receiver) = receiver {
                    out.push(receiver.clone());
                }
                for argument in args {
                    if let Some(place) = argument.place.as_ref() {
                        out.push(place.clone());
                    }
                    out.extend(argument.source_names.iter().cloned());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_rust_value_event_sources(then_events, out);
                collect_rust_value_event_sources(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_rust_value_event_sources(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_rust_value_event_sources(body, out);
                collect_rust_value_event_sources(catch_events, out);
                collect_rust_value_event_sources(finally_events, out);
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

/// Collect only explicit `let binding: Type = value` receiver types.
///
/// An untyped initializer may itself contain arbitrary type syntax, notably
/// Rust's turbofish (`let filter = factory::<Payload>()`). That payload type
/// is an argument to the factory, not the declared type of `filter`, so this
/// frontend must never recover it through a descendant search. Complex
/// destructuring is excluded as well because one outer annotation does not
/// prove that every inner binding has the outer type. For one bare binding,
/// retain every nominal identity in the declared type (`Box<dyn Task>` proves
/// both `Box` and `Task`). These are compiler type facts, not initializer
/// guesses.
fn collect_rust_explicit_local_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    let mut out = std::collections::HashMap::new();
    for function in collect_kinds(tree, &["function_item"]) {
        let mut aliases = Vec::new();
        let mut stack = vec![function];
        while let Some(node) = stack.pop() {
            if node.kind() == "let_declaration" {
                let binding = node.child_by_field_name("pattern");
                let type_node = node.child_by_field_name("type");
                if let (Some(binding), Some(type_node)) = (binding, type_node) {
                    if binding.kind() == "identifier" {
                        let name = node_text(&binding, src).trim();
                        if rust_bare_identifier(name) {
                            for type_name in rust_parameter_type_identities(type_node, src) {
                                let alias = TypeAliasBinding {
                                    name: name.to_string(),
                                    type_name,
                                };
                                if !aliases.contains(&alias) {
                                    aliases.push(alias);
                                }
                            }
                        }
                    }
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        if !aliases.is_empty() {
            out.insert(span_of(file, &function), aliases);
        }
    }
    out
}

/// Collect the receiver type proven by an exact Rust `as`-cast initializer.
///
/// Only `let name = value as Type` is admitted: the binding must be a bare
/// identifier and the declaration's direct `value` field must be a
/// `type_cast_expression`. A cast nested inside a call argument therefore
/// cannot mistype the result binding, and turbofish type arguments remain
/// ordinary call syntax rather than receiver evidence.
fn collect_rust_cast_local_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    let mut out = std::collections::HashMap::new();
    for function in collect_kinds(tree, &["function_item"]) {
        let mut aliases = Vec::new();
        let mut stack = vec![function];
        while let Some(node) = stack.pop() {
            // A nested item owns its locals. Its own `collect_kinds` iteration
            // will attach them to that declaration instead of leaking them
            // into the enclosing function.
            if node != function && node.kind() == "function_item" {
                continue;
            }
            if node.kind() == "let_declaration" {
                let binding = node.child_by_field_name("pattern");
                let value = node.child_by_field_name("value");
                if let (Some(binding), Some(value)) = (binding, value) {
                    if binding.kind() == "identifier" && value.kind() == "type_cast_expression" {
                        let name = node_text(&binding, src).trim();
                        let type_name = value
                            .child_by_field_name("type")
                            .and_then(|type_node| rust_type_tail(node_text(&type_node, src)));
                        if let Some(type_name) = type_name.filter(|_| rust_bare_identifier(name)) {
                            let alias = TypeAliasBinding {
                                name: name.to_string(),
                                type_name,
                            };
                            if !aliases.contains(&alias) {
                                aliases.push(alias);
                            }
                        }
                    }
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        if !aliases.is_empty() {
            out.insert(span_of(file, &function), aliases);
        }
    }
    out
}

/// Retain every exact nominal type identity for Rust parameter bindings.
///
/// The shared short-type collector supplies the ordinary cross-language
/// alias. Rust additionally needs its grammar-classified qualified identity
/// (`crate::Type`) and nested trait identities (`Wrapper<dyn Trait>`) for
/// exact provider and dynamic-dispatch proofs. Tuple-struct patterns bind the
/// inner value rather than their constructor token.
fn collect_rust_param_type_identities(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Vec<TypeAliasBinding>> {
    let mut out = std::collections::HashMap::new();
    for function in collect_kinds(tree, &["function_item"]) {
        let Some(parameters) = function.child_by_field_name("parameters") else {
            continue;
        };
        let mut aliases = Vec::new();
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            if parameter.kind() != "parameter" {
                continue;
            }
            let Some(pattern) = parameter.child_by_field_name("pattern") else {
                continue;
            };
            let Some(type_node) = parameter.child_by_field_name("type") else {
                continue;
            };
            let type_names = rust_parameter_type_identities(type_node, src);
            if type_names.is_empty() {
                continue;
            }
            let excluded_constructor = pattern
                .child_by_field_name("type")
                .or_else(|| pattern.child_by_field_name("path"));
            let mut names = Vec::new();
            collect_rust_pattern_binding_names(pattern, excluded_constructor, src, &mut names);
            for name in names {
                for type_name in &type_names {
                    let binding = TypeAliasBinding {
                        name: name.clone(),
                        type_name: type_name.clone(),
                    };
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
        }
        if !aliases.is_empty() {
            out.insert(span_of(file, &function), aliases);
        }
    }
    out
}

/// Return every compiler-declared nominal identity carried by a parameter
/// type, from the outer extractor wrapper through nested generic/trait types.
///
/// Rust extractor parameters commonly bind the inner value while annotating
/// the parameter with `State<Arc<dyn Gateway>>`. Retaining only the outer
/// `State` identity prevents exact trait dispatch for `gateway.method()`.
/// Walking type syntax (never value tokens) preserves all identities without
/// teaching the adapter any framework or API names.
fn rust_parameter_type_identities(type_node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut identities = Vec::new();
    let mut stack = vec![type_node];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "type_identifier" | "scoped_type_identifier") {
            let identity = bonsai_common::normalize_qualified_name(node_text(&node, src));
            if !identity.is_empty() && !identities.contains(&identity) {
                identities.push(identity);
            }
            // A scoped type is already one canonical identity. Its children
            // are path components, not independent receiver types.
            if node.kind() == "scoped_type_identifier" {
                continue;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    identities
}

fn collect_rust_pattern_binding_names(
    node: Node<'_>,
    excluded_constructor: Option<Node<'_>>,
    src: &[u8],
    out: &mut Vec<String>,
) {
    if excluded_constructor.is_some_and(|excluded| {
        node.start_byte() >= excluded.start_byte() && node.end_byte() <= excluded.end_byte()
    }) {
        return;
    }
    if node.kind() == "identifier" {
        let name = node_text(&node, src).trim();
        if !name.is_empty() && !out.iter().any(|existing| existing == name) {
            out.push(name.to_string());
        }
        return;
    }
    for index in 0..node.child_count() {
        let Ok(index) = u32::try_from(index) else {
            continue;
        };
        let Some(child) = node.child(index).filter(Node::is_named) else {
            continue;
        };
        if matches!(
            node.field_name_for_child(index),
            Some("type" | "path" | "constructor" | "field" | "value")
        ) {
            continue;
        }
        collect_rust_pattern_binding_names(child, excluded_constructor, src, out);
    }
}

fn rust_type_tail(text: &str) -> Option<String> {
    let outer = text.split_once('<').map_or(text, |(outer, _)| outer);
    let tail = outer
        .trim()
        .trim_matches('&')
        .trim()
        .rsplit("::")
        .next()
        .unwrap_or(text)
        .trim();
    (rust_bare_identifier(tail)).then(|| tail.to_string())
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

fn rust_nominal_type_alias(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }
    let segments = bonsai_common::qualified_name_segments(value);
    !segments.is_empty() && segments.into_iter().all(rust_bare_identifier)
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

/// Walk the Rust tree and map function/struct/enum/trait/impl spans
/// to their syntactic Visibility:
///
/// - `pub` → Public
/// - `pub(crate)` → Crate
/// - `pub(super)` / `pub(in path)` → Module (treated as parent-scoped)
/// - no `pub` modifier / `pub(self)` → ModuleTree (the declaring module and
///   its lexical descendants)
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
        // `pub(self)` is visible in the current module and its descendants,
        // exactly like an item without a visibility modifier.
        return Visibility::ModuleTree;
    }
    Visibility::ModuleTree
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
        let Some(type_node) = impl_node.child_by_field_name("type") else {
            continue;
        };
        let type_name = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&type_node, src));
        if type_name.is_empty() {
            continue;
        }
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

/// Retain Rust's exact `impl Trait for Type` inheritance relation.
///
/// The callgraph uses declaration bases for compiler-justified dynamic trait
/// dispatch. Both identities come from Tree-sitter's named `trait` and `type`
/// fields; this does not infer a relationship from method spellings.
fn collect_rust_impl_trait_bases(tree: &Tree, src: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for impl_node in collect_kinds(tree, &["impl_item"]) {
        let Some(type_node) = impl_node.child_by_field_name("type") else {
            continue;
        };
        let Some(trait_node) = impl_node.child_by_field_name("trait") else {
            continue;
        };
        let type_name = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&type_node, src));
        let trait_name = bonsai_common::normalize_qualified_name(node_text(&trait_node, src));
        let trait_name = trait_name.rsplit('.').next().unwrap_or(&trait_name).to_string();
        if type_name.is_empty() || trait_name.is_empty() {
            continue;
        }
        let relation = (type_name, trait_name);
        if !out.contains(&relation) {
            out.push(relation);
        }
    }
    out
}

/// Return every function declaration syntactically owned by an
/// `impl Trait for Type` block.
///
/// These methods cannot carry their own Rust visibility modifier; their
/// cross-module callable visibility comes from the trait implementation.
fn collect_rust_trait_impl_method_spans(tree: &Tree, file: FileId) -> Vec<bonsai_common::Span> {
    let functions = collect_kinds(tree, &["function_item"]);
    let mut out = Vec::new();
    for impl_node in collect_kinds(tree, &["impl_item"]) {
        if impl_node.child_by_field_name("trait").is_none() {
            continue;
        }
        let impl_span = span_of(file, &impl_node);
        for function in &functions {
            let function_span = span_of(file, function);
            if function_span.start >= impl_span.start
                && function_span.end <= impl_span.end
                && !out.contains(&function_span)
            {
                out.push(function_span);
            }
        }
    }
    out
}

/// Add the exact imported identity for compiler-declared receiver types.
///
/// `use provider::Client as ExternalClient; value: ExternalClient` carries
/// both a local type spelling and an exact provider binding. Retaining both
/// lets rules and call resolution require the complete imported identity
/// without losing ordinary local type navigation. Wildcard imports remain
/// ambiguous and therefore cannot qualify a type.
fn qualify_rust_declared_type_aliases(idx: &mut DeclIndex, imports: &[ImportSpec]) {
    let imported_types = imports
        .iter()
        .filter(|import| !import.is_wildcard)
        .filter_map(|import| {
            let imported_name = import
                .alias
                .clone()
                .or_else(|| import.original_name.clone())
                .or_else(|| bonsai_lang_api::module_local_binding(&import.module))?;
            let target = if let Some(original) = import.original_name.as_deref() {
                if import.module.is_empty() {
                    original.to_string()
                } else {
                    format!("{}::{original}", import.module)
                }
            } else {
                import.module.clone()
            };
            let target = bonsai_common::normalize_qualified_name(&target);
            (!imported_name.is_empty() && !target.is_empty()).then_some((imported_name, target))
        })
        .collect::<Vec<_>>();
    if imported_types.is_empty() {
        return;
    }

    for decl in &mut idx.defs {
        let existing = decl.type_aliases.clone();
        for alias in existing {
            for (_, target) in imported_types
                .iter()
                .filter(|(local, _)| local == &alias.type_name)
            {
                let qualified = TypeAliasBinding {
                    name: alias.name.clone(),
                    type_name: target.clone(),
                };
                if !decl.type_aliases.contains(&qualified) {
                    decl.type_aliases.push(qualified);
                }
            }
        }
    }
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

/// Workspace-qualified module prefix for Rust's `crate::` root.
///
/// A workspace can contain many Cargo packages (`crates/a/src`,
/// `crates/b/src`). Keeping the path before the adapter-owned `src` root lets
/// rooted imports and calls identify the right crate without a workspace-wide
/// leaf-name fallback. When no conventional source root is present we retain
/// the source spelling and let the normal module resolver handle it.
fn rust_crate_root_segments(path: &std::path::Path) -> Option<Vec<String>> {
    let segments = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(segment) => Some(segment.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>();
    // Cargo source roots are the final `src` component before the source
    // module. A workspace itself may legitimately live below an ancestor
    // directory also named `src`; choosing the first such component would
    // collapse unrelated package identities.
    let source_root = segments.iter().rposition(|segment| segment == "src")?;
    Some(segments[..source_root].to_vec())
}

fn normalize_rust_rooted_path(raw: &str, current_module: &[String], crate_root: Option<&[String]>) -> String {
    let trimmed = raw.trim();
    let mut remainder = trimmed;
    let mut prefix = Vec::new();
    if let Some(rest) = remainder.strip_prefix("crate::") {
        let Some(crate_root) = crate_root else {
            return trimmed.to_string();
        };
        prefix.extend(crate_root.iter().cloned());
        remainder = rest;
    } else if let Some(rest) = remainder.strip_prefix("self::") {
        prefix.extend(current_module.iter().cloned());
        remainder = rest;
    } else if remainder.starts_with("super::") {
        prefix.extend(current_module.iter().cloned());
        while let Some(rest) = remainder.strip_prefix("super::") {
            prefix.pop();
            remainder = rest;
        }
    } else {
        return trimmed.to_string();
    }
    prefix.extend(
        remainder
            .split("::")
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(str::to_string),
    );
    prefix.join("::")
}

fn normalize_rust_rooted_calls(
    events: &mut [FlowEvent],
    current_module: &[String],
    crate_root: Option<&[String]>,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, .. } => {
                *name = normalize_rust_rooted_path(name, current_module, crate_root);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_rust_rooted_calls(then_events, current_module, crate_root);
                normalize_rust_rooted_calls(else_events, current_module, crate_root);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_rust_rooted_calls(body, current_module, crate_root);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_rust_rooted_calls(body, current_module, crate_root);
                normalize_rust_rooted_calls(catch_events, current_module, crate_root);
                normalize_rust_rooted_calls(finally_events, current_module, crate_root);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
