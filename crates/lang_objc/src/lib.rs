//! Objective-C language adapter.
//!
//! `.m` files can also legitimately be MATLAB source; the CLI's file
//! detection assigns `.m` to Objective-C by default (same convention
//! `tree-sitter-language-pack` uses). If a project mixes the two, the
//! user can scope `--include` / `--exclude` to disambiguate.
mod method_identity;
mod parse_recovery;

use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        c_family_preproc_imports, collect_kinds, first_named_child_of_kind, language_from_pack, node_text,
        package_module_segments_with_workspace_prefix, parse_with, span_of,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, AssignValueKind, CallTargetExtraction, DeclIndex,
    DeclKind, ExpressionPlaceExtraction, FieldWrite, FiniteLiteralSelectionFact, FlowEvent, GrammarHandler,
    ImportIndex, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath,
    StaticScalarValue, SyntaxSpecialForm, TypeAliasBinding,
};
use parse_recovery::{objc_parse_recovery_edits, objc_tree_proves_language};
use tree_sitter::{Language, Node, Tree};

fn objc_foreach_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "for_statement" {
        return None;
    }

    // tree-sitter-objc represents both C-style `for (;;)` and Objective-C
    // fast enumeration as `for_statement`.  The `in` token is the exact CST
    // discriminator.  Its nearest named siblings are the declarator pattern
    // and iterable expression; the preceding type node is intentionally not
    // treated as a binding.
    let child_count = u32::try_from(node.child_count()).ok()?;
    let in_index =
        (0..child_count).find(|index| node.child(*index).is_some_and(|child| child.kind() == "in"))?;
    let binding = (0..in_index)
        .rev()
        .filter_map(|index| node.child(index))
        .find(Node::is_named)?;
    let iterable = ((in_index + 1)..child_count)
        .filter_map(|index| node.child(index))
        .find(Node::is_named)?;
    Some((binding, iterable))
}

pub const LANG_ID: LanguageId = LanguageId::new("objc");
const PACK_NAME: &str = "objc";

fn objc_indirect_place_operand(node: Node<'_>) -> Option<Node<'_>> {
    if !matches!(node.kind(), "pointer_expression" | "unary_expression") {
        return None;
    }
    let mut cursor = node.walk();
    let has_indirection = node
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "*" | "&"));
    has_indirection
        .then(|| {
            node.child_by_field_name("argument")
                .or_else(|| node.child_by_field_name("operand"))
        })
        .flatten()
}

// Objective-C handler. Mixes C-style functions with Objective-C
// methods. `method_declaration` covers bodyless `@interface` prototypes;
// `method_definition` covers executable `@implementation` bodies. The global
// compiler index merges matching declaration/definition identities while the
// raw adapter IR preserves both syntax roles. ObjC's
// `@try/@catch/@finally` parses as `try_statement`. `@synchronized`
// and `@autoreleasepool` are scope-bracketed regions modeled as
// `using` (resource-managed scope) since `body` then runs under the
// managed lock / pool.
const HANDLER: GrammarHandler = GrammarHandler {
    literal_value_kinds: &["null", "true", "false"],
    string_literal_kinds: &["string_literal", "char_literal", "concatenated_string"],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["///", "//!", "/**"],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["parameter_list"],
    parameter_kinds: &["method_parameter", "parameter_declaration"],
    parameter_annotation_kinds: &["attribute"],
    parameter_annotation_name_extractor: None,
    keyword_parameter_kinds: &["keyword_declarator"],
    parameter_selector_kinds: &["method_identifier", "identifier"],
    last_identifier_parameter_kinds: &["method_parameter"],
    binding_identifier_kinds: &["identifier"],
    anonymous_variadic_token: Some("..."),
    identifier_kinds: &["identifier"],
    named_aggregate_kinds: &["initializer_list", "dictionary_literal"],
    positional_aggregate_kinds: &["initializer_list", "array_literal"],
    aggregate_pair_kinds: &["initializer_pair"],
    two_child_aggregate_pair_kinds: &["dictionary_pair"],
    aggregate_key_field_names: &["designator"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["field_identifier"],
    static_subscript_key_extractor: Some(objc_static_string_key),
    aggregate_syntax_only_kinds: &["type_identifier"],
    transparent_call_wrapper_kinds: &["field_expression", "parenthesized_expression"],
    single_expression_group_kinds: &[],
    assignment_target_wrapper_kinds: &[
        "init_declarator",
        "function_declarator",
        "pointer_declarator",
        "parenthesized_declarator",
        "block_pointer_declarator",
    ],
    binding_declaration_keyword_spellings: &["auto", "const"],
    nested_type_ownership: true,
    fn_kinds: &["function_definition", "method_definition", "method_declaration"],
    class_kinds: &["class_interface", "class_implementation", "protocol_declaration"],
    class_decl_kinds: &[
        ("class_interface", DeclKind::Class),
        ("class_implementation", DeclKind::Class),
        ("protocol_declaration", DeclKind::Interface),
    ],
    method_kinds: &["method_definition", "method_declaration"],
    method_context_kinds: &["class_implementation", "class_interface"],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    if_kinds: &["if_statement", "switch_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition"],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &["parenthesized_expression"],
    condition_all_operators: &["&&"],
    condition_any_operators: &["||"],
    condition_not_operators: &["!"],
    condition_not_operator_kinds: &[],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["compound_statement", "expression_statement"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &["update"],
    loop_condition_field_names: &["condition"],
    loop_condition_extractor: None,
    loop_kind_extractor: None,
    branch_arm_kinds: &["compound_statement", "expression_statement"],
    exclusive_branch_arm_kinds: &["case_statement"],
    fallthrough_branch_arm_kinds: &["case_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &[],
    foreach_binding_extractor: Some(objc_foreach_binding),
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    loop_kinds: &[],
    call_kinds: &["call_expression", "message_expression"],
    call_callee_field_names: &["function"],
    call_receiver_field_names: &["receiver"],
    call_member_field_names: &["method"],
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list"],
    direct_call_argument_excluded_fields: &["receiver", "method"],
    call_target_extractor: Some(objc_call_target),
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: Some(objc_argument_passing_mode),
    indirect_place_operand_extractor: Some(objc_indirect_place_operand),
    expression_value_kind_extractor: Some(objc_expression_value_kind),
    call_ref_kinds: &["call_expression", "message_expression"],
    member_expression_kinds: &["field_expression"],
    subscript_expression_kinds: &["subscript_expression"],
    member_base_field_names: &["argument"],
    member_name_field_names: &["field"],
    subscript_base_field_names: &["argument"],
    subscript_index_field_names: &["index"],
    expression_place_extractor: Some(objc_expression_places),
    syntax_error_tolerant_call_names: &["va_arg", "__builtin_va_arg"],
    assignment_kinds: &["assignment_expression", "init_declarator"],
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="],
    positional_aggregate_assignment_kinds: &["init_declarator"],
    positional_aggregate_value_kinds: &["initializer_list"],
    return_kinds: &["return_statement"],
    throw_kinds: &["throw_statement"],
    lambda_kinds: &["block_literal"],
    try_kinds: &["try_statement"],
    try_node_filter: None,
    catch_kinds: &["catch_clause"],
    exclusive_catch_arm_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    control_target_extractor: None,
    loop_label_extractor: None,
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &["synchronized_statement"],
    using_body_field_names: &["body"],
    try_body_field_names: &["body"],
    special_forms: &[SyntaxSpecialForm::DirectCallArguments],
    value_free_expression_kinds: &["sizeof_expression", "alignof_expression", "typeof_specifier"],
    method_receiver_param_index: None,
    implicit_receiver_names: &["self", "super"],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
    void_return_type_names: &[],
    ..bonsai_lang_api::EMPTY_HANDLER
};

fn objc_expression_value_kind(node: Node<'_>, _src: &[u8]) -> Option<AssignValueKind> {
    matches!(node.kind(), "string_literal" | "char_literal" | "number_literal")
        .then_some(AssignValueKind::Literal)
}

/// Decode Objective-C scalar literal syntax into the language-neutral
/// compiler fact consumed by exact rule semantics.
///
/// This is deliberately syntax-only. Framework names and security meaning
/// remain in rule data, while the adapter owns Objective-C's `@"..."`
/// spelling and C-family escape rules. Unknown escapes and multi-character
/// character constants fail closed instead of being guessed.
fn objc_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "null" => Some(StaticScalarValue::Null),
        // Objective-C's null object/class pointer sentinels are identifiers in
        // tree-sitter-objc even though the compiler defines their value as
        // zero. Retain that exact language literal fact for variadic
        // Foundation constructors such as `setWithObjects:..., nil`.
        "identifier" if matches!(node_text(&node, src).trim(), "nil" | "Nil") => {
            Some(StaticScalarValue::Null)
        }
        "string_literal" => Some(StaticScalarValue::String(objc_static_string_literal(node, src)?)),
        "char_literal" => {
            let value = objc_static_string_literal(node, src)?;
            (value.chars().count() == 1).then_some(StaticScalarValue::String(value))
        }
        "concatenated_string" => {
            let mut value = String::new();
            let mut saw_part = false;
            let mut cursor = node.walk();
            for part in node.named_children(&mut cursor) {
                if !matches!(part.kind(), "string_literal" | "char_literal") {
                    return None;
                }
                value.push_str(&objc_static_string_literal(part, src)?);
                saw_part = true;
            }
            saw_part.then_some(StaticScalarValue::String(value))
        }
        _ => None,
    }
}

fn objc_static_string_literal(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let raw = raw.strip_prefix('@').unwrap_or(raw);
    let quote = raw.chars().next()?;
    if !matches!(quote, '\'' | '"') || !raw.ends_with(quote) {
        return None;
    }
    let quote_len = quote.len_utf8();
    let body = raw.get(quote_len..raw.len().checked_sub(quote_len)?)?;
    let mut decoded = String::new();
    let mut chars = body.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let escaped = chars.next()?;
        match escaped {
            '\\' => decoded.push('\\'),
            '\'' => decoded.push('\''),
            '"' => decoded.push('"'),
            '?' => decoded.push('?'),
            'a' => decoded.push('\u{7}'),
            'b' => decoded.push('\u{8}'),
            'f' => decoded.push('\u{c}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{b}'),
            '\n' => {}
            'x' => {
                let mut value = 0_u32;
                let mut digits = 0_u32;
                while let Some(digit) = chars.peek().and_then(|ch| ch.to_digit(16)) {
                    chars.next();
                    value = value.checked_mul(16)?.checked_add(digit)?;
                    digits += 1;
                }
                if digits == 0 {
                    return None;
                }
                decoded.push(char::from_u32(value)?);
            }
            'u' | 'U' => {
                let digits = if escaped == 'u' { 4 } else { 8 };
                let mut value = 0_u32;
                for _ in 0..digits {
                    value = value.checked_mul(16)?.checked_add(chars.next()?.to_digit(16)?)?;
                }
                decoded.push(char::from_u32(value)?);
            }
            '0'..='7' => {
                let mut value = escaped.to_digit(8)?;
                for _ in 1..3 {
                    let Some(digit) = chars.peek().and_then(|ch| ch.to_digit(8)) else {
                        break;
                    };
                    chars.next();
                    value = value.checked_mul(8)?.checked_add(digit)?;
                }
                decoded.push(char::from_u32(value)?);
            }
            _ => return None,
        }
    }
    Some(decoded)
}

fn objc_argument_passing_mode(argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
    if [argument, value].into_iter().any(|node| {
        matches!(node.kind(), "unary_expression" | "pointer_expression") && {
            let mut cursor = node.walk();
            let has_address_of = node.children(&mut cursor).any(|child| child.kind() == "&");
            has_address_of
        }
    }) {
        ArgumentPassingMode::WriteBack
    } else {
        ArgumentPassingMode::Value
    }
}

/// Preserve the complete keyword selector of an Objective-C message send.
///
/// The grammar labels every selector keyword with the `method` field and the
/// receiver independently. A one-keyword message keeps the established
/// `receiver.method` identity; a multi-keyword message appends the exact `:`
/// punctuation to every parsed keyword so overload-like selector families
/// cannot collide. This is a generic Objective-C syntax fact: provider and
/// security meaning remain entirely in rule data.
fn objc_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if node.kind() == "call_expression" {
        let callee = node.child_by_field_name("function")?;
        let full_text = node_text(&callee, src).trim().to_string();
        return (!full_text.is_empty()).then_some(CallTargetExtraction {
            node: callee,
            full_text,
        });
    }
    if node.kind() != "message_expression" {
        return None;
    }

    let receiver = node.child_by_field_name("receiver")?;
    let receiver_text = objc_receiver_identity(receiver, src)?;
    if receiver_text.is_empty() {
        return None;
    }
    let mut first_method = None;
    let mut keywords = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.is_named() && cursor.field_name() == Some("method") {
                first_method.get_or_insert(child);
                let keyword = node_text(&child, src).trim();
                if !keyword.is_empty() {
                    keywords.push(keyword);
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    let first_method = first_method?;
    let selector = match keywords.as_slice() {
        [] => return None,
        [keyword] => (*keyword).to_string(),
        keywords => objc_selector_keywords(keywords),
    };
    Some(CallTargetExtraction {
        node: first_method,
        full_text: format!("{receiver_text}.{selector}"),
    })
}

fn objc_selector_keywords(keywords: &[&str]) -> String {
    let mut selector = String::with_capacity(keywords.iter().map(|keyword| keyword.len() + 1).sum());
    for keyword in keywords {
        selector.push_str(keyword);
        selector.push(':');
    }
    selector
}

/// Canonicalize a message-send receiver from its CST shape.
///
/// Objective-C permits another message expression as the receiver
/// (`[[Type sharedInstance] values]`). Recursing through that exact grammar
/// node preserves one stable compiler identity (`Type.sharedInstance.values`)
/// instead of embedding raw bracket syntax. Provider and API meaning remain
/// in rule data.
fn objc_receiver_identity(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "message_expression" {
        return objc_call_target(node, src).map(|target| target.full_text);
    }
    let text = node_text(&node, src).trim().to_string();
    (!text.is_empty()).then_some(text)
}

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
        // `.h` is shared with C and C++; the database evaluates every
        // candidate grammar against the concrete CST instead of assigning
        // headers by extension alone.
        &["m", "mm", "h"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn source_syntax_proves_language(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        tree: &Tree,
    ) -> bonsai_lang_api::LanguageOwnershipEvidence {
        if objc_tree_proves_language(snapshot, tree) {
            bonsai_lang_api::LanguageOwnershipEvidence::Proven
        } else {
            bonsai_lang_api::LanguageOwnershipEvidence::Excluded
        }
    }
    fn parse_context_fingerprint(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
    ) -> u64 {
        bonsai_lang_api::c_family_preprocessor_context_fingerprint(snapshot, vfs)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        objc_parse_recovery_edits(snapshot, vfs, tree)
    }
    fn parse_recovery_edit_batches(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<Vec<bonsai_lang_api::ParseRecoveryEdit>> {
        parse_recovery::objc_parse_recovery_edit_batches(snapshot, vfs, tree)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Macros: tree-sitter-objc parses `NSAssert(...)` / `NS_INLINE`
        // / `IB_DESIGNABLE` etc. as ordinary call expressions or
        // declarators, so name-resolution narrows them. Genuine
        // multi-statement `#define` expansion isn't performed.
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["id"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            macros: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: &["init"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["self"],
            same_directory_unqualified_calls: true,
            build_target_linkage: true,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("custom lowering", "&"),
            ("custom lowering", "*"),
            ("custom lowering", "NULL"),
            ("custom lowering", "argument_list"),
            ("custom lowering", "array_literal"),
            ("custom lowering", "at_expression"),
            ("custom lowering", "call_expression"),
            ("custom lowering", "cast_expression"),
            ("custom lowering", "catch_clause"),
            ("custom lowering", "char_literal"),
            ("custom lowering", "class_implementation"),
            ("custom lowering", "class_interface"),
            ("custom lowering", "conditional_expression"),
            ("custom lowering", "declaration"),
            ("custom lowering", "dictionary_literal"),
            ("custom lowering", "dictionary_pair"),
            ("custom lowering", "false"),
            ("custom lowering", "field_expression"),
            ("custom lowering", "field_identifier"),
            ("custom lowering", "for_statement"),
            ("custom lowering", "function_definition"),
            ("custom lowering", "identifier"),
            ("custom lowering", "in"),
            ("custom lowering", "init_declarator"),
            ("custom lowering", "message_expression"),
            ("custom lowering", "method_declaration"),
            ("custom lowering", "method_definition"),
            ("custom lowering", "method_parameter"),
            ("custom lowering", "method_type"),
            ("custom lowering", "null"),
            ("custom lowering", "number_literal"),
            ("custom lowering", "parameter_declaration"),
            ("custom lowering", "parameter_list"),
            ("custom lowering", "parenthesized_expression"),
            ("custom lowering", "parameterized_arguments"),
            ("custom lowering", "pointer_expression"),
            ("custom lowering", "primitive_type"),
            ("custom lowering", "protocol_declaration"),
            ("custom lowering", "protocol_reference_list"),
            ("custom lowering", "sized_type_specifier"),
            ("custom lowering", "string_literal"),
            ("custom lowering", "subscript_expression"),
            ("custom lowering", "true"),
            ("custom lowering", "type_descriptor"),
            ("custom lowering", "type_identifier"),
            ("custom lowering", "type_name"),
            ("custom lowering", "unary_expression"),
            ("custom lowering", "update_expression"),
        ]
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let parsed = parse_with(PACK_NAME, file, ctx);
        let mut decl_index = parsed.as_ref().map_or_else(
            || DeclIndex {
                file,
                ..DeclIndex::default()
            },
            |(snapshot, tree)| {
                decl_index_from_tree_with_handler(file, snapshot.text.as_bytes(), tree, &HANDLER)
            },
        );
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        apply_objc_class_semantic_identity(&mut decl_index, ctx);
        if let Some((snapshot, tree)) = parsed.as_ref() {
            mark_objc_method_prototypes_bodyless(&mut decl_index, tree);
            apply_objc_method_selector_identities(&mut decl_index, tree, snapshot.text.as_bytes());
        }
        // The leading `_` on an Objective-C method/selector is an Apple
        // naming convention, not a linkage boundary: selectors dispatch
        // dynamically across files. Marking `_`-prefixed decls
        // Visibility::Private would make the resolver enforce them as
        // strictly file-scoped, dropping every legitimate cross-file
        // flow through a `_`-prefixed helper to zero candidates. Leave
        // visibility at the kit default and let the resolver's name +
        // receiver-type narrowing do the work instead.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            method_identity::mark_initializers(&mut decl_index, tree, snapshot.text.as_bytes());
        }
        let constructor_selectors = method_identity::initializer_selectors(&decl_index);
        // Per-decl `type_aliases` from typed parameters
        // (`(NSString *)name`, `(HTTPRequest *)req`). Objective-C
        // method signatures and C-style function parameters both
        // carry an explicit type — extract them so
        // `attribute: [NSURL, absoluteString]`-style rules can
        // resolve `req.absoluteString` semantically per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            bonsai_lang_api::kit::inject_c_family_function_pointer_aliases(&mut decl_index, tree, src, file);
            let aliases_by_span = collect_objc_method_type_aliases(tree, file, src);
            for decl in &mut decl_index.defs {
                if !matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    continue;
                }
                // The generic kit deliberately gives a callable the span of
                // its executable body, while Tree-sitter's Objective-C method
                // node also owns the selector and typed parameter list. Match
                // those two exact compiler facts by containment of the
                // declaration's name, preferring the smallest owning method.
                // This stays syntax-only: no framework or API spelling enters
                // the adapter.
                if let Some((_, aliases)) = aliases_by_span
                    .iter()
                    .filter(|(span, _)| {
                        span.file == decl.name_span.file
                            && span.start <= decl.name_span.start
                            && span.end >= decl.name_span.end
                    })
                    .min_by_key(|(span, _)| span.len())
                {
                    for alias in aliases {
                        if !decl.type_aliases.contains(alias) {
                            decl.type_aliases.push(alias.clone());
                        }
                    }
                }
            }
            // Per-class `bases`: `@interface AuditedRepository :
            // Repository` → ["Repository"]. The engine's
            // `resolve_super_method_candidates` reads `Decl.bases`
            // when the receiver is `super`/`self.super` so
            // `[super run]` dispatches into the parent class's
            // `run` method instead of falling back to a name-only
            // candidate enumeration. Without populated bases,
            // every super dispatch is invisible.
            let bases_by_class = collect_objc_class_bases(tree, file, src);
            for decl in &mut decl_index.defs {
                if !matches!(
                    decl.kind,
                    DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct
                ) {
                    continue;
                }
                if let Some(bases) = bases_by_class.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
            }
            let bases_by_name = decl_index
                .defs
                .iter()
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct
                    ) && !decl.bases.is_empty()
                })
                .map(|decl| (decl.name.clone(), decl.bases.clone()))
                .collect::<std::collections::HashMap<_, _>>();
            for decl in &mut decl_index.defs {
                if !matches!(
                    decl.kind,
                    DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct
                ) || !decl.bases.is_empty()
                {
                    continue;
                }
                if let Some(bases) = bases_by_name.get(&decl.name) {
                    decl.bases = bases.clone();
                }
            }
            for decl in &mut decl_index.defs {
                suppress_objc_dynamic_subscript_literal_overwrites(&mut decl.flow_events, tree, src);
                augment_objc_dictionary_flow_events(&mut decl.flow_events, tree, src);
            }
            bonsai_lang_api::kit::populate_call_argument_static_values(
                &mut decl_index,
                tree,
                file,
                src,
                &HANDLER,
                objc_static_scalar,
            );
            decl_index.finite_literal_selections =
                collect_objc_finite_literal_selections(&decl_index, tree, file, src);
        }
        for decl in &mut decl_index.defs {
            enrich_objc_receiver_field_writes(decl);
            let value_binding_starts = objc_value_binding_starts(decl);
            // Tag `[[Class alloc] init...]` / `[[Class new] ...]`
            // chains with the constructed class so the engine's
            // receiver-type dispatch recognises the alloc-init
            // pattern without re-implementing the ObjC message-
            // syntax shape.
            tag_objc_alloc_receiver_types(
                &mut decl.flow_events,
                &constructor_selectors,
                &value_binding_starts,
            );
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Repair catch-param bindings: the kit's generic extractor
        // returns the first identifier descendant of `@catch
        // (NSException *e)`, which is the type — we want the
        // binding identifier.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let src = snapshot.text.as_bytes();
            for decl in &mut decl_index.defs {
                fix_objc_catch_params(&mut decl.flow_events, tree, src);
            }
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing follows Objective-C
        // message/constructor facts and declarations, not capitalization.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

fn apply_objc_class_semantic_identity(decl_index: &mut DeclIndex, ctx: &AdapterContext<'_>) {
    for decl in &mut decl_index.defs {
        if !matches!(
            decl.kind,
            DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct
        ) {
            continue;
        }
        let segments =
            package_module_segments_with_workspace_prefix(decl_index.file, ctx, [decl.name.clone()], &[]);
        let prefix = segments.join("::");
        decl.module_path = ModulePath::from_segments(segments);
        decl.qualified_name = Some(format!("{prefix}::{}", decl.name));
    }
}

/// Attach the complete multipart selector to each method declaration's
/// qualified semantic identity while retaining the first selector piece as
/// its concise display/search name. Interface prototypes are bodyless compiler
/// declarations; implementations remain the executable definitions.
///
/// Tree-sitter represents `-run:user:` as alternating direct `identifier`
/// and `method_parameter` children. The adapter owns that grammar fact. A
/// qualified tail such as `run:user:` lets compiler resolution distinguish
/// sibling selectors that share their first piece; shared crates only consume
/// the already-lowered qualified identity.
fn apply_objc_method_selector_identities(decl_index: &mut DeclIndex, tree: &Tree, src: &[u8]) {
    let selectors = collect_kinds(tree, &["method_definition", "method_declaration"])
        .into_iter()
        .filter_map(|node| objc_multipart_method_selector(node, decl_index.file, src))
        .collect::<Vec<_>>();
    for decl in &mut decl_index.defs {
        if decl.kind != DeclKind::Method {
            continue;
        }
        let Some((_, selector)) = selectors
            .iter()
            .filter(|(span, _)| {
                span.file == decl.name_span.file
                    && span.start <= decl.name_span.start
                    && span.end >= decl.name_span.end
            })
            .min_by_key(|(span, _)| span.len())
        else {
            continue;
        };
        let owner = decl
            .qualified_name
            .as_deref()
            .and_then(bonsai_common::qualified_name_owner)
            .map(ToString::to_string);
        decl.qualified_name = owner.map_or_else(
            || Some(selector.clone()),
            |owner| Some(format!("{owner}.{selector}")),
        );
    }
}

/// The generic declaration kit uses the declaration node itself as a fallback
/// body span when a configured callable kind has no `body` child. That is
/// correct for expression-bodied callables, but an Objective-C
/// `method_declaration` is a prototype by grammar definition. Clear the
/// fallback so resolvers can link it to a peer implementation without treating
/// the header as executable code.
fn mark_objc_method_prototypes_bodyless(decl_index: &mut DeclIndex, tree: &Tree) {
    let prototype_spans = collect_kinds(tree, &["method_declaration"])
        .into_iter()
        .map(|node| span_of(decl_index.file, &node))
        .collect::<Vec<_>>();
    for decl in &mut decl_index.defs {
        if decl.kind != DeclKind::Method {
            continue;
        }
        if prototype_spans.iter().any(|span| {
            span.file == decl.name_span.file
                && span.start <= decl.name_span.start
                && span.end >= decl.name_span.end
        }) {
            decl.body_span = None;
            decl.flow_events.clear();
        }
    }
}

fn objc_multipart_method_selector(node: Node<'_>, file: FileId, src: &[u8]) -> Option<(Span, String)> {
    if !matches!(node.kind(), "method_definition" | "method_declaration") {
        return None;
    }
    let mut pieces = Vec::new();
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    for pair in children.windows(2) {
        if pair[0].kind() != "identifier" || pair[1].kind() != "method_parameter" {
            continue;
        }
        let piece = node_text(&pair[0], src).trim();
        if !piece.is_empty() {
            pieces.push(piece);
        }
    }
    // One-piece selectors retain the established short identity. Multipart
    // selectors require every keyword to prevent overload-family collisions.
    (pieces.len() > 1).then(|| {
        let selector = objc_selector_keywords(&pieces);
        (span_of(file, &node), selector)
    })
}

fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = c_family_preproc_imports(tree, src, file);
    let framework_spans = collect_kinds(tree, &["preproc_include"])
        .into_iter()
        .filter(|include| {
            include
                .child_by_field_name("path")
                .is_some_and(|path| path.kind() == "system_lib_string")
        })
        .map(|include| span_of(file, &include))
        .collect::<std::collections::HashSet<_>>();
    for import in &mut imports {
        if framework_spans.contains(&import.span) {
            // `#import <Framework/Header.h>` exposes the header's public
            // declarations in the translation unit. This is a wildcard
            // compiler binding, unlike a quoted project header whose exact
            // path remains available to workspace resolution.
            import.is_wildcard = true;
        }
    }
    imports
}

/// Walk a decl's flow events and populate
/// `FlowEvent::Call::receiver_types` for ObjC chain calls of the
/// shape `[[Class alloc] init...]` or `[[Class new] init...]`. The
/// `[Class alloc]` / `[Class new]` inner message returns
/// `instancetype` (per ObjC convention), so the outer message's
/// receiver type is `Class`.
///
/// Tagging at index time means the engine's receiver-type dispatch
/// reads the pre-populated `receiver_types` directly instead of
/// reparsing the ObjC `[receiver selector]` syntax at every call
/// resolution.
fn tag_objc_alloc_receiver_types(
    events: &mut [bonsai_lang_api::FlowEvent],
    constructor_selectors: &std::collections::HashMap<(String, String), bool>,
    value_binding_starts: &std::collections::HashMap<String, u64>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
                span,
                ..
            } => {
                // Adapter-emitted `receiver` field takes precedence;
                // when absent (tree-sitter-objc doesn't use field
                // names on message expressions, so the kit walker
                // can't always recover the receiver), parse the
                // call name's leading `[Class alloc]` segment.
                let class_name = receiver
                    .as_deref()
                    .and_then(objc_alloc_class_name)
                    .or_else(|| objc_alloc_class_name_from_call_name(name));
                if let Some(class_name) = class_name.filter(|name| {
                    value_binding_starts
                        .get(name)
                        .is_none_or(|binding_start| *binding_start > span.start)
                }) {
                    // The nested allocation receiver plus a selector that
                    // resolved to an adapter-declared constructor proves this
                    // is construction syntax. Use those AST/declaration facts
                    // instead of teaching the IDG selector spellings.
                    let selector = name.rsplit('.').next().unwrap_or(name).trim();
                    let initializer = constructor_selectors
                        .get(&(class_name.clone(), selector.to_string()))
                        .copied()
                        .unwrap_or_else(|| objc_selector_is_initializer(selector));
                    if initializer {
                        *call_kind = bonsai_lang_api::CallKind::Constructor;
                    }
                    if !receiver_types.iter().any(|existing| existing == &class_name) {
                        receiver_types.push(class_name);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                tag_objc_alloc_receiver_types(then_events, constructor_selectors, value_binding_starts);
                tag_objc_alloc_receiver_types(else_events, constructor_selectors, value_binding_starts);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                tag_objc_alloc_receiver_types(body, constructor_selectors, value_binding_starts);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                tag_objc_alloc_receiver_types(body, constructor_selectors, value_binding_starts);
                tag_objc_alloc_receiver_types(catch_events, constructor_selectors, value_binding_starts);
                tag_objc_alloc_receiver_types(finally_events, constructor_selectors, value_binding_starts);
            }
            _ => {}
        }
    }
}

fn objc_selector_is_initializer(selector: &str) -> bool {
    selector
        .split(':')
        .next()
        .unwrap_or(selector)
        .trim_start_matches('_')
        .strip_prefix("init")
        .is_some_and(|suffix| suffix.chars().next().is_none_or(|ch| !ch.is_ascii_lowercase()))
}

fn objc_value_binding_starts(decl: &bonsai_lang_api::Decl) -> std::collections::HashMap<String, u64> {
    let mut starts = std::collections::HashMap::new();
    for name in decl
        .params
        .iter()
        .chain(decl.type_aliases.iter().map(|alias| &alias.name))
    {
        if objc_simple_identifier(name) {
            starts.entry(name.clone()).or_insert(0);
        }
    }
    collect_objc_value_binding_starts(&decl.flow_events, &mut starts);
    starts
}

fn collect_objc_value_binding_starts(
    events: &[FlowEvent],
    starts: &mut std::collections::HashMap<String, u64>,
) {
    for event in events {
        match event {
            FlowEvent::Assign { span, target, .. } if objc_simple_identifier(target) => {
                starts
                    .entry(target.clone())
                    .and_modify(|start| *start = (*start).min(span.start))
                    .or_insert(span.start);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_objc_value_binding_starts(then_events, starts);
                collect_objc_value_binding_starts(else_events, starts);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_objc_value_binding_starts(body, starts);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_objc_value_binding_starts(body, starts);
                collect_objc_value_binding_starts(catch_events, starts);
                collect_objc_value_binding_starts(finally_events, starts);
            }
            _ => {}
        }
    }
}

fn objc_simple_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn suppress_objc_dynamic_subscript_literal_overwrites(events: &mut Vec<FlowEvent>, tree: &Tree, src: &[u8]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                suppress_objc_dynamic_subscript_literal_overwrites(then_events, tree, src);
                suppress_objc_dynamic_subscript_literal_overwrites(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                suppress_objc_dynamic_subscript_literal_overwrites(body, tree, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                suppress_objc_dynamic_subscript_literal_overwrites(body, tree, src);
                suppress_objc_dynamic_subscript_literal_overwrites(catch_events, tree, src);
                suppress_objc_dynamic_subscript_literal_overwrites(finally_events, tree, src);
            }
            _ => {}
        }
    }

    let root = tree.root_node();
    events.retain(|event| {
        let FlowEvent::Assign {
            span,
            source_name,
            source_call,
            source_call_args,
            source_names,
            value_kind,
            ..
        } = event
        else {
            return true;
        };
        let source_free_literal = matches!(value_kind, Some(AssignValueKind::Literal))
            || (value_kind.is_none()
                && source_name.is_none()
                && source_call.is_none()
                && source_call_args.is_empty()
                && source_names.is_empty());
        if !source_free_literal {
            return true;
        }
        !objc_assignment_has_dynamic_subscript_lhs(root, *span, src)
    });
}

fn objc_assignment_has_dynamic_subscript_lhs(root: Node<'_>, span: Span, src: &[u8]) -> bool {
    let Some(node) =
        bonsai_lang_api::kit::node_at_span(root, span, &["assignment_expression", "subscript_expression"])
    else {
        return false;
    };
    let lhs = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("target"))
        .unwrap_or(node);
    let Some(subscript) = first_descendant_of_kind(lhs, "subscript_expression") else {
        return false;
    };
    let Some(index) = subscript.child_by_field_name("index") else {
        return true;
    };
    objc_static_string_key(index, src).is_none()
}

fn augment_objc_dictionary_flow_events(events: &mut Vec<FlowEvent>, tree: &Tree, src: &[u8]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_objc_dictionary_flow_events(then_events, tree, src);
                augment_objc_dictionary_flow_events(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_objc_dictionary_flow_events(body, tree, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_objc_dictionary_flow_events(body, tree, src);
                augment_objc_dictionary_flow_events(catch_events, tree, src);
                augment_objc_dictionary_flow_events(finally_events, tree, src);
            }
            _ => {}
        }
    }

    let root = tree.root_node();
    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let mut synthetic = Vec::new();
        if let FlowEvent::Assign { span, target, .. } = &event {
            if let Some(dict) = objc_assignment_dictionary_literal(root, *span) {
                synthetic.extend(objc_dictionary_field_assigns(target, *span, dict, src));
            }
        }
        rewritten.push(event);
        rewritten.extend(synthetic);
    }
    *events = rewritten;
}

fn objc_assignment_dictionary_literal<'tree>(root: Node<'tree>, span: Span) -> Option<Node<'tree>> {
    let node = bonsai_lang_api::kit::node_at_span(
        root,
        span,
        &["init_declarator", "assignment_expression", "dictionary_literal"],
    )?;
    if node.kind() == "dictionary_literal" {
        return Some(node);
    }
    let mut rhs = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("right"))
        .unwrap_or(node);
    while rhs.kind() == "parenthesized_expression" && rhs.named_child_count() == 1 {
        rhs = rhs.named_child(0)?;
    }
    (rhs.kind() == "dictionary_literal").then_some(rhs)
}

fn first_descendant_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_descendant_of_kind(child, kind) {
            return Some(found);
        }
    }
    None
}

fn objc_dictionary_field_assigns(
    target: &str,
    span: Span,
    dictionary: Node<'_>,
    src: &[u8],
) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    let mut cursor = dictionary.walk();
    for pair in dictionary.named_children(&mut cursor) {
        if pair.kind() != "dictionary_pair" {
            continue;
        }
        let Some((key_node, value_node)) = objc_dictionary_pair_nodes(pair) else {
            continue;
        };
        let Some(key) = objc_static_string_key(key_node, src) else {
            continue;
        };
        let source_names = objc_value_source_names(value_node, src);
        let value_kind = if source_names.is_empty() && objc_value_is_literal(value_node) {
            Some(AssignValueKind::Literal)
        } else {
            Some(AssignValueKind::Compound)
        };
        out.push(FlowEvent::Assign {
            span,
            target: format!("{target}.@{key}"),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names,
            declares_new_binding: false,
            value_kind,
        });
    }
    out
}

fn objc_dictionary_pair_nodes(pair: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut cursor = pair.walk();
    let mut children = pair.named_children(&mut cursor);
    let key = children.next()?;
    let value = children.next()?;
    Some((key, value))
}

#[derive(Copy, Clone)]
struct ObjcFiniteDictionaryBinding<'tree> {
    target: Node<'tree>,
    initializer: Node<'tree>,
    scope: Node<'tree>,
    owner: Node<'tree>,
}

/// Prove selections from one local dictionary literal without attaching any
/// library, helper, or security meaning to the syntax. The dynamic subscript
/// controls which literal is selected, while every dictionary key/value and
/// the nil-coalescing fallback must be a compiler literal.
fn collect_objc_finite_literal_selections(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<FiniteLiteralSelectionFact> {
    let bindings = collect_objc_finite_dictionary_bindings(index, tree, src);
    if bindings.is_empty() {
        return Vec::new();
    }

    let mut facts = Vec::new();
    let mut direct_return_candidates = vec![Vec::<Span>::new(); index.defs.len()];
    // A direct lookup from a stable literal dictionary is finite even
    // without an explicit `?:` fallback: a missing key produces ObjC `nil`,
    // so the result remains one of the literal values or the language null
    // value. Attach the fact only when the complete assignment/call argument
    // is exactly this subscript; compound expressions retain their ordinary
    // dataflow.
    for lookup in collect_kinds(tree, &["subscript_expression"]) {
        if objc_expression_is_assignment_target(lookup) {
            continue;
        }
        let Some(base) = lookup.child_by_field_name("argument") else {
            continue;
        };
        if base.kind() != "identifier"
            || !objc_has_one_finite_dictionary_binding(&bindings, lookup, base, src)
        {
            continue;
        }
        let selection_span = span_of(file, &lookup);
        if let Some(fact) = bonsai_lang_api::kit::finite_literal_selection_fact_for_span(
            index,
            tree,
            selection_span,
            |value| objc_value_is_exact_selection(value, lookup),
        ) {
            facts.push(fact);
            continue;
        }
        if objc_selection_is_complete_return_value(lookup) {
            if let Some((decl_index, _)) = index
                .defs
                .iter()
                .enumerate()
                .filter(|(_, decl)| {
                    matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    ) && decl.span.file == selection_span.file
                        && decl.span.start <= selection_span.start
                        && selection_span.end <= decl.span.end
                })
                .min_by_key(|(_, decl)| decl.span.len())
            {
                direct_return_candidates[decl_index].push(selection_span);
            }
        }
    }
    for selection in collect_kinds(tree, &["conditional_expression"]) {
        let Some((lookup, base)) = objc_finite_dictionary_selection(selection, src) else {
            continue;
        };
        if !objc_has_one_finite_dictionary_binding(&bindings, lookup, base, src) {
            continue;
        }

        let selection_span = span_of(file, &selection);
        if let Some(fact) = bonsai_lang_api::kit::finite_literal_selection_fact_for_span(
            index,
            tree,
            selection_span,
            |value| objc_value_is_exact_selection(value, selection),
        ) {
            facts.push(fact);
            continue;
        }
        if !objc_selection_is_complete_return_value(selection) {
            continue;
        }
        let Some((decl_index, _)) = index
            .defs
            .iter()
            .enumerate()
            .filter(|(_, decl)| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && decl.span.file == selection_span.file
                    && decl.span.start <= selection_span.start
                    && selection_span.end <= decl.span.end
            })
            .min_by_key(|(_, decl)| decl.span.len())
        else {
            continue;
        };
        direct_return_candidates[decl_index].push(selection_span);
    }

    for (decl_index, selections) in direct_return_candidates.into_iter().enumerate() {
        if selections.is_empty()
            || bonsai_lang_api::kit::complete_finite_selection_return_span(
                &index.defs[decl_index].flow_events,
                &selections,
            )
            .is_none()
        {
            continue;
        }
        facts.extend(
            selections
                .into_iter()
                .map(|selection_span| FiniteLiteralSelectionFact {
                    selection_span,
                    assignment_span: None,
                    target: None,
                    call_span: None,
                    argument_index: None,
                }),
        );
    }
    bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut facts);
    facts
}

fn objc_has_one_finite_dictionary_binding(
    bindings: &[ObjcFiniteDictionaryBinding<'_>],
    lookup: Node<'_>,
    base: Node<'_>,
    src: &[u8],
) -> bool {
    let base_name = node_text(&base, src).trim();
    let mut matching = bindings.iter().filter(|binding| {
        node_text(&binding.target, src).trim() == base_name
            && binding.initializer.end_byte() <= lookup.start_byte()
            && binding.scope.start_byte() <= lookup.start_byte()
            && lookup.end_byte() <= binding.scope.end_byte()
            && objc_enclosing_callable(lookup).is_some_and(|owner| owner.id() == binding.owner.id())
    });
    matching.next().is_some() && matching.next().is_none()
}

fn collect_objc_finite_dictionary_bindings<'tree>(
    index: &DeclIndex,
    tree: &'tree Tree,
    src: &[u8],
) -> Vec<ObjcFiniteDictionaryBinding<'tree>> {
    let mut bindings = Vec::new();
    for declarator in collect_kinds(tree, &["init_declarator"]) {
        let (Some(target), Some(initializer)) = (
            declarator
                .child_by_field_name("declarator")
                .and_then(objc_simple_binding_identifier),
            declarator.child_by_field_name("value"),
        ) else {
            continue;
        };
        let initializer = objc_unwrap_parenthesized(initializer);
        if !objc_finite_dictionary_literal(initializer, src) {
            continue;
        }
        let (Some(owner), Some(scope)) = (
            objc_enclosing_callable(declarator),
            objc_enclosing_compound_scope(declarator),
        ) else {
            continue;
        };
        let binding = ObjcFiniteDictionaryBinding {
            target,
            initializer,
            scope,
            owner,
        };
        if objc_finite_dictionary_binding_is_stable(index, binding, src) {
            bindings.push(binding);
        }
    }
    bindings
}

fn objc_finite_dictionary_binding_is_stable(
    index: &DeclIndex,
    binding: ObjcFiniteDictionaryBinding<'_>,
    src: &[u8],
) -> bool {
    let name = node_text(&binding.target, src).trim();
    if name.is_empty() {
        return false;
    }
    let target_span = span_of(index.file, &binding.target);
    let Some(owner_decl) = index
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) && decl.span.file == target_span.file
                && decl.span.start <= target_span.start
                && target_span.end <= decl.span.end
        })
        .min_by_key(|decl| decl.span.len())
    else {
        return false;
    };
    if owner_decl.params.iter().any(|parameter| parameter == name) {
        return false;
    }

    let body = binding.owner.child_by_field_name("body").unwrap_or(binding.scope);
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier"
            && node_text(&node, src).trim() == name
            && node.id() != binding.target.id()
            && !objc_identifier_is_finite_dictionary_read(node, binding)
        {
            return false;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    true
}

fn objc_identifier_is_finite_dictionary_read(
    identifier: Node<'_>,
    binding: ObjcFiniteDictionaryBinding<'_>,
) -> bool {
    if identifier.start_byte() < binding.initializer.end_byte()
        || identifier.start_byte() < binding.scope.start_byte()
        || binding.scope.end_byte() < identifier.end_byte()
    {
        return false;
    }
    let Some(subscript) = identifier
        .parent()
        .filter(|parent| parent.kind() == "subscript_expression")
    else {
        return false;
    };
    if subscript
        .child_by_field_name("argument")
        .is_none_or(|base| base.id() != identifier.id())
    {
        return false;
    }
    !objc_expression_is_assignment_target(subscript)
}

fn objc_expression_is_assignment_target(expression: Node<'_>) -> bool {
    let mut current = expression;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "assignment_expression" | "update_expression") {
            return parent.child_by_field_name("left").is_none_or(|left| {
                left.start_byte() <= expression.start_byte() && expression.end_byte() <= left.end_byte()
            });
        }
        if matches!(
            parent.kind(),
            "expression_statement"
                | "declaration"
                | "return_statement"
                | "argument_list"
                | "compound_statement"
        ) {
            break;
        }
        current = parent;
    }
    false
}

fn objc_finite_dictionary_selection<'tree>(
    selection: Node<'tree>,
    src: &[u8],
) -> Option<(Node<'tree>, Node<'tree>)> {
    if selection.kind() != "conditional_expression" || selection.child_by_field_name("consequence").is_some()
    {
        return None;
    }
    let lookup = objc_unwrap_parenthesized(selection.child_by_field_name("condition")?);
    let fallback = objc_unwrap_parenthesized(selection.child_by_field_name("alternative")?);
    if lookup.kind() != "subscript_expression" || !objc_finite_scalar_literal(fallback, src) {
        return None;
    }
    let base = lookup.child_by_field_name("argument")?;
    let subscript = lookup.child_by_field_name("index")?;
    (base.kind() == "identifier" && !node_text(&subscript, src).trim().is_empty()).then_some((lookup, base))
}

fn objc_finite_dictionary_literal(node: Node<'_>, src: &[u8]) -> bool {
    if node.kind() != "dictionary_literal" || node.named_child_count() == 0 {
        return false;
    }
    let mut cursor = node.walk();
    let finite = node.named_children(&mut cursor).all(|pair| {
        if pair.kind() != "dictionary_pair" || pair.named_child_count() != 2 {
            return false;
        }
        let Some((key, value)) = objc_dictionary_pair_nodes(pair) else {
            return false;
        };
        objc_finite_scalar_literal(key, src) && objc_finite_scalar_literal(value, src)
    });
    finite
}

fn objc_finite_scalar_literal(node: Node<'_>, src: &[u8]) -> bool {
    let node = objc_unwrap_parenthesized(node);
    if node.kind() == "at_expression" {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        let [value] = children.as_slice() else {
            return false;
        };
        return objc_finite_scalar_literal(*value, src);
    }
    match node.kind() {
        "number_literal" => !node_text(&node, src).trim().is_empty(),
        "string_literal" | "char_literal" | "concatenated_string" | "true" | "false" | "null" => {
            objc_static_scalar(node, src).is_some()
        }
        _ => false,
    }
}

fn objc_value_is_exact_selection(mut value: Node<'_>, selection: Node<'_>) -> bool {
    while value.kind() == "parenthesized_expression" {
        let mut cursor = value.walk();
        let children = value.named_children(&mut cursor).collect::<Vec<_>>();
        let [inner] = children.as_slice() else {
            return false;
        };
        value = *inner;
    }
    value.id() == selection.id()
}

fn objc_selection_is_complete_return_value(selection: Node<'_>) -> bool {
    let mut value = selection;
    while let Some(parent) = value.parent() {
        if parent.kind() == "return_statement" {
            return parent.named_child_count() == 1;
        }
        if parent.kind() != "parenthesized_expression" || parent.named_child_count() != 1 {
            return false;
        }
        value = parent;
    }
    false
}

fn objc_simple_binding_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "identifier" {
        return Some(node);
    }
    if !matches!(node.kind(), "pointer_declarator" | "parenthesized_declarator") {
        return None;
    }
    objc_simple_binding_identifier(node.child_by_field_name("declarator")?)
}

fn objc_unwrap_parenthesized(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        let Some(inner) = node.named_child(0) else {
            break;
        };
        node = inner;
    }
    node
}

fn objc_enclosing_callable(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "function_definition" | "method_definition" | "block_literal"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn objc_enclosing_compound_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "compound_statement" {
            return Some(parent);
        }
        if matches!(
            parent.kind(),
            "function_definition" | "method_definition" | "block_literal"
        ) {
            return None;
        }
        node = parent;
    }
    None
}

fn objc_static_string_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let without_at = raw.strip_prefix('@').unwrap_or(raw);
    let key = without_at
        .strip_prefix('"')
        .and_then(|part| part.strip_suffix('"'))
        .or_else(|| {
            without_at
                .strip_prefix('\'')
                .and_then(|part| part.strip_suffix('\''))
        })?;
    if key.is_empty()
        || !key
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !key.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(key.to_string())
}

fn objc_value_source_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    collect_objc_value_source_names(node, src, &mut out);
    out
}

fn collect_objc_value_source_names(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "string_literal" | "number_literal" | "char_literal" | "null" => return,
        "identifier" => {
            let text = node_text(&node, src).trim();
            if objc_identifier_is_value(text) {
                push_objc_source_name(out, text.to_string());
            }
            return;
        }
        "field_expression" => {
            if let Some(place) = objc_place_name(node, src) {
                push_objc_source_name(out, place);
                return;
            }
        }
        "subscript_expression" => {
            if let Some(place) = objc_place_name(node, src) {
                push_objc_source_name(out, place);
                return;
            }
        }
        "message_expression" => {
            let receiver = node.child_by_field_name("receiver");
            let method = node.child_by_field_name("method");
            if let Some(receiver) = receiver {
                collect_objc_value_source_names(receiver, src, out);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                let skip_receiver = receiver.is_some_and(|receiver| receiver.id() == child.id());
                let skip_method = method.is_some_and(|method| method.id() == child.id());
                if !skip_receiver && !skip_method {
                    collect_objc_value_source_names(child, src, out);
                }
            }
            return;
        }
        "call_expression" => {
            if let Some(args) = node
                .child_by_field_name("arguments")
                .or_else(|| node.child_by_field_name("argument_list"))
            {
                let mut cursor = args.walk();
                for arg in args.named_children(&mut cursor) {
                    collect_objc_value_source_names(arg, src, out);
                }
                return;
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_objc_value_source_names(child, src, out);
    }
}

fn objc_place_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "type_identifier" => {
            let text = node_text(&node, src).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "field_expression" => {
            let base = node
                .child_by_field_name("argument")
                .or_else(|| node.child_by_field_name("object"))
                .or_else(|| node.child_by_field_name("value"))?;
            let field = node.child_by_field_name("field")?;
            let base = objc_place_name(base, src)?;
            let field = node_text(&field, src).trim();
            (!field.is_empty()).then(|| format!("{base}.{field}"))
        }
        "message_expression" => {
            let receiver = node.child_by_field_name("receiver")?;
            let method = node.child_by_field_name("method")?;
            let mut cursor = node.walk();
            let has_value_arguments = node
                .named_children(&mut cursor)
                .any(|child| child.id() != receiver.id() && child.id() != method.id());
            if has_value_arguments {
                return None;
            }
            let receiver = objc_place_name(receiver, src)?;
            let method = node_text(&method, src).trim();
            (!method.is_empty()).then(|| format!("{receiver}.{method}"))
        }
        "subscript_expression" => {
            let base = node
                .child_by_field_name("argument")
                .or_else(|| node.child_by_field_name("object"))
                .or_else(|| node.child_by_field_name("value"))?;
            let index = node.child_by_field_name("index")?;
            let base = objc_place_name(base, src)?;
            let key = objc_static_string_key(index, src)?;
            Some(format!("{base}.@{key}"))
        }
        "parenthesized_expression" | "at_expression" => {
            let mut cursor = node.walk();
            let place = node
                .named_children(&mut cursor)
                .find_map(|child| objc_place_name(child, src));
            place
        }
        _ => None,
    }
}

/// Decode Objective-C property selection after a zero-argument message send,
/// such as `[NSProcessInfo processInfo].arguments`. Tree-sitter owns the
/// receiver/method/field roles; shared analysis receives only the canonical
/// place and never interprets framework names.
fn objc_expression_places(node: Node<'_>, src: &[u8]) -> ExpressionPlaceExtraction {
    if node.kind() != "field_expression" {
        return ExpressionPlaceExtraction::default();
    }
    objc_place_name(node, src).map_or_else(ExpressionPlaceExtraction::default, |place| {
        ExpressionPlaceExtraction {
            places: vec![place],
            consumed_node_ids: vec![node.id()],
        }
    })
}

fn objc_identifier_is_value(text: &str) -> bool {
    !matches!(text, "" | "nil" | "NULL" | "YES" | "NO" | "true" | "false")
}

fn objc_value_is_literal(node: Node<'_>) -> bool {
    match node.kind() {
        "string_literal" | "number_literal" | "char_literal" | "null" => true,
        "at_expression" | "parenthesized_expression" => {
            let mut cursor = node.walk();
            let all_literal = node.named_children(&mut cursor).all(objc_value_is_literal);
            all_literal
        }
        "array_literal" => {
            let mut cursor = node.walk();
            let all_literal = node.named_children(&mut cursor).all(objc_value_is_literal);
            all_literal
        }
        _ => false,
    }
}

fn push_objc_source_name(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

fn enrich_objc_receiver_field_writes(decl: &mut bonsai_lang_api::Decl) {
    let params = decl.params.clone();
    // Names declared as locals inside this body. The C-family local
    // declaration collector already records every typed local (with
    // the leading underscore preserved, e.g. `_buf`) in `type_aliases`
    // before this pass runs. An `_`-prefixed name that is a real local
    // is NOT an ivar, so it must not be rewritten to `self.<field>`.
    let local_names: std::collections::HashSet<String> =
        decl.type_aliases.iter().map(|alias| alias.name.clone()).collect();
    enrich_objc_receiver_field_writes_inner(
        &mut decl.receiver_field_writes,
        &decl.flow_events,
        &params,
        &local_names,
    );
    decl.receiver_field_writes
        .sort_by_key(|write| (write.span.start, write.target.clone()));
    decl.receiver_field_writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
}

fn enrich_objc_receiver_field_writes_inner(
    out: &mut Vec<FieldWrite>,
    events: &[FlowEvent],
    params: &[String],
    local_names: &std::collections::HashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_names,
                ..
            } if objc_target_is_receiver_field(target, local_names) => {
                let source_param_indices = params
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, param)| {
                        let source_matches = source_name.as_deref() == Some(param.as_str())
                            || source_names.iter().any(|source| source == param);
                        source_matches.then_some(idx)
                    })
                    .collect::<Vec<_>>();
                if source_param_indices.is_empty() {
                    continue;
                }
                out.push(FieldWrite {
                    span: *span,
                    target: objc_receiver_field_target(target),
                    source_param_indices,
                });
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                enrich_objc_receiver_field_writes_inner(out, then_events, params, local_names);
                enrich_objc_receiver_field_writes_inner(out, else_events, params, local_names);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                enrich_objc_receiver_field_writes_inner(out, body, params, local_names);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                enrich_objc_receiver_field_writes_inner(out, body, params, local_names);
                enrich_objc_receiver_field_writes_inner(out, catch_events, params, local_names);
                enrich_objc_receiver_field_writes_inner(out, finally_events, params, local_names);
            }
            _ => {}
        }
    }
}

fn objc_target_is_receiver_field(target: &str, local_names: &std::collections::HashSet<String>) -> bool {
    // A `_`-prefixed name that is declared as a local in this body is a
    // plain variable, not an ivar — do not treat it as a receiver field.
    if local_names.contains(target) {
        return target.starts_with("self.");
    }
    target
        .strip_prefix('_')
        .is_some_and(|tail| !tail.is_empty() && !tail.starts_with('_'))
        || target.starts_with("self.")
}

fn objc_receiver_field_target(target: &str) -> String {
    if let Some(field) = target.strip_prefix('_') {
        format!("self.{field}")
    } else {
        target.to_string()
    }
}

/// Repair ObjC catch bindings on `Try` events. The kit's generic
/// extractor returns the first identifier descendant of `@catch
/// (NSException *e)`, which is the type identifier. Re-extract the
/// binding from the `parameter_declaration` → `declarator`
/// chain and retain it on the exact arm that owns it. Arm-local facts are the
/// authoritative compiler contract; the aggregate `catch_param` exists only
/// for compatibility with older compiler objects.
fn fix_objc_catch_params(events: &mut [bonsai_lang_api::FlowEvent], tree: &Tree, src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_arms,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if let Some(name) = objc_catch_param_binding(node, src) {
                        *catch_param = Some(name);
                    }
                }
                for arm in catch_arms {
                    let Some(clause) =
                        bonsai_lang_api::kit::node_at_span(tree.root_node(), arm.span, &["catch_clause"])
                    else {
                        continue;
                    };
                    if let Some(name) = objc_catch_clause_param_binding(clause, src) {
                        arm.parameter = Some(name);
                    }
                }
                fix_objc_catch_params(body, tree, src);
                fix_objc_catch_params(catch_events, tree, src);
                fix_objc_catch_params(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                fix_objc_catch_params(then_events, tree, src);
                fix_objc_catch_params(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                fix_objc_catch_params(body, tree, src);
            }
            _ => {}
        }
    }
}

fn objc_catch_param_binding(try_node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut tcur = try_node.walk();
    for child in try_node.named_children(&mut tcur) {
        if child.kind() != "catch_clause" {
            continue;
        }
        if let Some(name) = objc_catch_clause_param_binding(child, src) {
            return Some(name);
        }
    }
    None
}

fn objc_catch_clause_param_binding(clause: Node<'_>, src: &[u8]) -> Option<String> {
    // tree-sitter-objc flattens `@catch (T *name)` into a single
    // `type_name` node that contains both the type and the identifier. The
    // trailing identifier descendant is the binding.
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "type_name" | "parameter_list" | "parameter_declaration"
        ) {
            continue;
        }
        if let Some(text) = last_identifier_text_in_subtree(child, src) {
            return Some(text);
        }
    }
    None
}

fn last_identifier_text_in_subtree(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut last: Option<Node<'_>> = None;
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "identifier" | "field_identifier") {
            // Pick the rightmost-by-byte identifier.
            match last {
                Some(prev) if prev.start_byte() >= n.start_byte() => {}
                _ => last = Some(n),
            }
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    last.map(|n| node_text(&n, src).trim().to_string())
}

/// Pull the leading `[Class alloc]` / `[Class new]` segment out of
/// a chained call name like `[Box alloc].initWithP` so the outer
/// message's receiver type can be recovered when the kit's
/// receiver-field extraction came up empty (tree-sitter-objc
/// doesn't expose receiver as a named field).
fn objc_alloc_class_name_from_call_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if !trimmed.starts_with('[') {
        return None;
    }
    let mut depth: i32 = 0;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    let segment = &trimmed[..=idx];
                    return objc_alloc_class_name(segment);
                }
            }
            _ => {}
        }
    }
    None
}

/// Match the source-shaped or compiler-canonical identity of an Objective-C
/// allocation message and return its class. Calls are normalized to
/// `Class.alloc` by the adapter, while older/synthetic paths may still carry
/// `[Class alloc]`; both encode the same grammar-proven message syntax.
fn objc_alloc_class_name(receiver: &str) -> Option<String> {
    let trimmed = receiver.trim();
    let (class, selector) = if let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
    {
        inner.trim().rsplit_once(char::is_whitespace)?
    } else {
        trimmed.rsplit_once('.')?
    };
    let class = class.trim();
    let selector = selector.trim();
    if !matches!(selector, "alloc" | "new") {
        return None;
    }
    let class = class.split_whitespace().last()?.trim();
    if class.is_empty() {
        return None;
    }
    let mut chars = class.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|character| character.is_alphanumeric() || character == '_')
    {
        return None;
    }
    Some(class.to_string())
}

/// Walk Objective-C interface / implementation nodes and pull bare base type
/// names from the grammar's exact `superclass` field plus protocol references.
/// Categories use the same `class_interface` / `class_implementation` nodes
/// with a `category` field in the current grammar.
fn collect_objc_class_bases(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String, Vec<String>)> {
    let class_kinds = &["class_interface", "class_implementation"];
    let mut out: Vec<(Span, String, Vec<String>)> = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let class_name = objc_class_name(class_node, src).unwrap_or_default();
        let mut bases: Vec<String> = Vec::new();
        if let Some(superclass) = class_node.child_by_field_name("superclass") {
            let raw = node_text(&superclass, src).trim().to_string();
            if let Some(name) = canonical_objc_base_name(&raw) {
                if !bases.iter().any(|existing| existing == &name) {
                    bases.push(name);
                }
            }
        }
        let mut cursor = class_node.walk();
        for child in class_node.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "protocol_reference_list" | "parameterized_arguments"
            ) {
                let mut protocol_nodes = vec![child];
                while let Some(protocol_node) = protocol_nodes.pop() {
                    if matches!(protocol_node.kind(), "identifier" | "type_identifier") {
                        if let Some(name) = canonical_objc_base_name(node_text(&protocol_node, src)) {
                            if !bases.iter().any(|existing| existing == &name) {
                                bases.push(name);
                            }
                        }
                        continue;
                    }
                    let mut protocol_cursor = protocol_node.walk();
                    protocol_nodes.extend(protocol_node.named_children(&mut protocol_cursor));
                }
            }
        }
        let class_span = span_of(file, &class_node);
        if !bases.is_empty() {
            // Merge into an existing entry for the same span if the
            // adapter already collected partial info.
            if let Some((_, _, existing)) = out.iter_mut().find(|(span, _, _)| *span == class_span) {
                for base in bases {
                    if !existing.iter().any(|already| already == &base) {
                        existing.push(base);
                    }
                }
            } else {
                out.push((class_span, class_name, bases));
            }
        }
    }
    out
}

fn objc_class_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let name_node = node
        .child_by_field_name("name")
        .or_else(|| first_named_child_of_kind(&node, "type_identifier"))
        .or_else(|| first_named_child_of_kind(&node, "identifier"))?;
    let name = node_text(&name_node, src).trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Strip a base entry to the bare type name. Drops trailing
/// generics/typed-pointer chrome (`NSDictionary<NSString *, id> *`
/// → `NSDictionary`) and trims protocol-qualifier brackets.
fn canonical_objc_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches(':').trim();
    let head = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let head = head.split('*').next().unwrap_or(head).trim();
    let bare = head.rsplit("::").next().unwrap_or(head).trim();
    let bare = bare.trim_start_matches('@').trim();
    if bare.is_empty()
        || !bare
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return None;
    }
    Some(bare.to_string())
}

/// Walk every Objective-C method declaration / definition and C function
/// definition once and
/// record parameter type-alias bindings. The grammar names
/// implementation methods as `method_definition`; interface-only
/// `method_declaration` nodes have no runtime body and must not become a
/// second callable candidate. Selector pieces are `method_parameter` nodes.
/// A nested `parameter_list`
/// carries C-style `(Type) name` declarations. C
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
        &["function_definition", "method_definition", "method_declaration"],
    ) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        // C-style parameters live under a nested
        // `function_declarator` whose `parameters` field is the
        // `parameter_list`. Walk the declarator chain so pointer-
        // /array-decorated function shapes still surface the list.
        if let Some(params_list) = find_objc_parameter_list(fn_node) {
            collect_objc_c_parameter_aliases(params_list, src, &mut aliases);
        }
        collect_objc_local_type_aliases(fn_node, src, &mut aliases);
        // Selector parameters are direct `method_parameter` children and
        // retain an exact type/name pair.
        let mut cursor = fn_node.walk();
        for child in fn_node.named_children(&mut cursor) {
            if child.kind() == "method_parameter" {
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

fn collect_objc_local_type_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "declaration" {
            objc_declaration_aliases(current, src, aliases);
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn objc_declaration_aliases(node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    let Some(type_node) = node
        .child_by_field_name("type")
        .or_else(|| objc_declaration_type_node(node))
    else {
        return;
    };
    let Some(canonical_type) = canonical_objc_type_name(node_text(&type_node, src)) else {
        return;
    };
    if let Some(declarator) = node.child_by_field_name("declarator") {
        if let Some(name) = objc_declarator_identifier(declarator, src) {
            push_objc_type_alias(aliases, &name, &canonical_type);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "init_declarator" {
            continue;
        }
        if let Some(declarator) = child.child_by_field_name("declarator") {
            if let Some(name) = objc_declarator_identifier(declarator, src) {
                // WS2 cast typing: when the declared type is the dynamic `id`
                // placeholder, a C-style cast on the initializer carries the
                // real receiver type — `id f = (Foo *)make()` → `f: Foo`.
                // Read the init_declarator's DIRECT `value` so a cast nested in
                // a call argument cannot mistype the local; only override `id`,
                // never a real declared type.
                let effective_type = if canonical_type == "id" {
                    child
                        .child_by_field_name("value")
                        .and_then(|value| objc_cast_type_of_value(&value, src))
                        .unwrap_or_else(|| canonical_type.clone())
                } else {
                    canonical_type.clone()
                };
                push_objc_type_alias(aliases, &name, &effective_type);
            }
        }
    }
}

/// The cast target type of a direct initializer value (`(Foo *) x` →
/// `Foo`), or `None` for any non-cast shape. ObjC has only the C-style
/// `cast_expression` (no `static_cast`).
fn objc_cast_type_of_value(value: &Node<'_>, src: &[u8]) -> Option<String> {
    if value.kind() != "cast_expression" {
        return None;
    }
    let type_node = value.child_by_field_name("type")?;
    let ti = if type_node.kind() == "type_identifier" {
        type_node
    } else {
        objc_first_descendant_of_kind(&type_node, "type_identifier")?
    };
    canonical_objc_type_name(node_text(&ti, src))
}

/// First descendant found by a depth-first syntax-tree walk, or `None`.
fn objc_first_descendant_of_kind<'a>(node: &Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            if child.kind() == kind {
                return Some(child);
            }
            stack.push(child);
        }
    }
    None
}

fn objc_declaration_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "type_identifier" | "primitive_type" | "sized_type_specifier"
        ) {
            return Some(child);
        }
    }
    None
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
            "method_type" => {
                // `method_type` includes the surrounding parentheses and
                // pointer declarator. The named type descendant is the exact
                // declared receiver/value type and avoids text heuristics.
                type_text = objc_first_descendant_of_kind(&child, "type_identifier")
                    .or_else(|| objc_first_descendant_of_kind(&child, "primitive_type"))
                    .map(|type_node| node_text(&type_node, src).to_string());
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
