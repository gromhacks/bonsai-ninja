//! C language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        c_family_preproc_imports, collect_kinds, collect_param_type_aliases, first_named_child_of_kind,
        language_from_pack, node_text, parse_with, span_of,
    },
    AdapterContext, AdapterError, ArgumentPassingMode, DeclIndex, GrammarHandler, GuardedValueFilterFact,
    ImportIndex, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasVocabulary,
    Visibility, EMPTY_HANDLER,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("c");
const PACK_NAME: &str = "c";

fn c_indirect_place_operand(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "pointer_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let has_indirection = node
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "*" | "&"));
    has_indirection
        .then(|| node.child_by_field_name("argument"))
        .flatten()
}

const HANDLER: GrammarHandler = GrammarHandler {
    literal_value_kinds: &["null", "true", "false"],
    string_literal_kinds: &["string_literal", "char_literal"],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["///", "//!", "/**"],
    decorator_kinds: &["attribute"],
    parameter_container_kinds: &["parameter_list"],
    parameter_kinds: &["parameter_declaration", "optional_parameter_declaration"],
    parameter_annotation_kinds: &["attribute"],
    variadic_parameter_kinds: &["variadic_parameter"],
    binding_identifier_kinds: &["identifier"],
    anonymous_variadic_token: Some("..."),
    identifier_kinds: &["identifier"],
    named_aggregate_kinds: &["initializer_list"],
    positional_aggregate_kinds: &["initializer_list"],
    aggregate_pair_kinds: &["initializer_pair"],
    aggregate_key_field_names: &["designator"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["field_identifier"],
    aggregate_syntax_only_kinds: &["type_identifier"],
    transparent_call_wrapper_kinds: &["field_expression", "parenthesized_expression"],
    single_expression_group_kinds: &["expression_list"],
    assignment_target_wrapper_kinds: &[
        "init_declarator",
        "declarator",
        "function_declarator",
        "pointer_declarator",
        "parenthesized_declarator",
    ],
    binding_declaration_keyword_spellings: &["auto", "const"],
    fn_kinds: &["function_definition"],
    if_kinds: &["if_statement", "conditional_expression", "switch_statement"],
    branch_then_field_names: &["consequence", "body"],
    branch_else_field_names: &["alternative"],
    branch_condition_field_names: &["condition", "value"],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["compound_statement", "expression_statement"],
    branch_arm_kinds: &["compound_statement", "expression_statement"],
    for_kinds: &["for_statement"],
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    call_kinds: &["call_expression"],
    call_callee_field_names: &["function"],
    call_argument_field_names: &["arguments"],
    call_argument_container_kinds: &["argument_list"],
    writeback_operand_field_names: &["argument"],
    indirect_place_operand_extractor: Some(c_indirect_place_operand),
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: Some(c_argument_passing_mode),
    expression_value_kind_extractor: Some(c_expression_value_kind),
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    value_free_expression_kinds: &["sizeof_expression", "alignof_expression"],
    call_ref_kinds: &["call_expression"],
    member_expression_kinds: &["field_expression"],
    subscript_expression_kinds: &["subscript_expression"],
    member_base_field_names: &["argument"],
    member_name_field_names: &["field"],
    subscript_base_field_names: &["argument"],
    subscript_index_field_names: &["index"],
    syntax_error_tolerant_call_names: &["va_arg", "__builtin_va_arg"],
    class_kinds: &["struct_specifier", "union_specifier"],
    class_decl_kinds: &[
        ("struct_specifier", bonsai_lang_api::DeclKind::Struct),
        ("union_specifier", bonsai_lang_api::DeclKind::Struct),
    ],
    assignment_kinds: &["assignment_expression", "init_declarator"],
    compound_assignment_operators: &["+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="],
    positional_aggregate_assignment_kinds: &["init_declarator"],
    positional_aggregate_value_kinds: &["initializer_list"],
    return_kinds: &["return_statement"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    control_label_field_names: &[],
    nested_type_ownership: false,
    ..EMPTY_HANDLER
};

fn c_expression_value_kind(node: Node<'_>, _src: &[u8]) -> Option<bonsai_lang_api::AssignValueKind> {
    matches!(node.kind(), "string_literal" | "char_literal" | "number_literal")
        .then_some(bonsai_lang_api::AssignValueKind::Literal)
}

fn c_argument_passing_mode(argument: Node<'_>, value: Node<'_>) -> ArgumentPassingMode {
    if [argument, value].into_iter().any(|node| {
        matches!(node.kind(), "pointer_expression" | "unary_expression") && {
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
    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &bonsai_lang_api::Vfs,
        tree: &Tree,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        bonsai_lang_api::c_family_declaration_macro_recovery_edits(
            snapshot,
            vfs,
            tree,
            &["va_arg", "__builtin_va_arg"],
        )
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
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
            same_directory_unqualified_calls: true,
            build_target_linkage: true,
            callable_declaration_family: bonsai_lang_api::CallableDeclarationFamily::SameSignature,
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
            decl_index.guarded_value_filters = c_guarded_value_filter_facts(&decl_index, &tree, file, src);
        }
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            let has_variadic_param = decl
                .params
                .iter()
                .any(|param| param == bonsai_lang_api::kit::SYNTHETIC_VARARGS_PARAM);
            bonsai_lang_api::kit::normalize_variadic_builtin_flow(
                &mut decl.flow_events,
                has_variadic_param,
                &["va_start", "__builtin_va_start"],
                &["va_arg", "__builtin_va_arg"],
            );
        }
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Lower C's element-at-a-time filtered-buffer construction without assigning
/// security meaning to the predicate call. A security rule must match the
/// exact predicate span before this compiler fact can receive sanitizer
/// credit.
fn c_guarded_value_filter_facts(
    index: &DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<GuardedValueFilterFact> {
    let mut facts = Vec::new();
    for function in collect_kinds(tree, &["function_definition"]) {
        let function_span = span_of(file, &function);
        if !index.defs.iter().any(|decl| decl.span == function_span) {
            continue;
        }
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let assignments = descendant_nodes_of_kind(body, "assignment_expression");
        let initializers = descendant_nodes_of_kind(body, "init_declarator");
        for branch in descendant_nodes_of_kind(body, "if_statement") {
            if !has_loop_ancestor_within(branch, function) {
                continue;
            }
            let Some(condition) = branch.child_by_field_name("condition") else {
                continue;
            };
            let mut predicates = Vec::new();
            collect_positively_required_predicate_calls(condition, src, &mut predicates);
            let Some(consequence) = branch.child_by_field_name("consequence") else {
                continue;
            };
            for predicate in predicates {
                let Some(input_place) = predicate_subscript_input(predicate, src) else {
                    continue;
                };
                for write in descendant_nodes_of_kind(consequence, "assignment_expression") {
                    let Some((output_place, copied_input)) = filtered_element_copy(write, src) else {
                        continue;
                    };
                    if copied_input != input_place
                        || !output_is_zero_initialized(&initializers, &output_place, write.start_byte(), src)
                        || !output_has_only_filtered_or_zero_writes(&assignments, &output_place, write, src)
                        || !output_is_zero_terminated_after(
                            &assignments,
                            &output_place,
                            write.end_byte(),
                            src,
                        )
                    {
                        continue;
                    }
                    let predicate_callee = predicate.child_by_field_name("function").unwrap_or(predicate);
                    facts.push(GuardedValueFilterFact {
                        function_span,
                        predicate_call_span: span_of(file, &predicate_callee),
                        write_span: span_of(file, &write),
                        input_place: input_place.clone(),
                        output_place,
                    });
                }
            }
        }
    }
    facts.sort_by(|left, right| {
        (
            left.function_span.start,
            left.predicate_call_span.start,
            left.write_span.start,
            left.input_place.as_str(),
            left.output_place.as_str(),
        )
            .cmp(&(
                right.function_span.start,
                right.predicate_call_span.start,
                right.write_span.start,
                right.input_place.as_str(),
                right.output_place.as_str(),
            ))
    });
    facts.dedup();
    facts
}

fn descendant_nodes_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    let mut work = vec![root];
    while let Some(node) = work.pop() {
        if node != root && node.kind() == kind {
            matches.push(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        work.extend(children.into_iter().rev());
    }
    matches
}

fn has_loop_ancestor_within(node: Node<'_>, function: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        if ancestor == function {
            return false;
        }
        if matches!(
            ancestor.kind(),
            "for_statement" | "while_statement" | "do_statement"
        ) {
            return true;
        }
        parent = ancestor.parent();
    }
    false
}

/// Collect calls whose truth is required for the enclosing condition to be
/// true. Positive conjunctions preserve that implication; disjunctions,
/// negation, and comparisons do not.
fn collect_positively_required_predicate_calls<'tree>(
    condition: Node<'tree>,
    src: &[u8],
    out: &mut Vec<Node<'tree>>,
) {
    match condition.kind() {
        "parenthesized_expression" => {
            if let Some(inner) = first_named_child(condition) {
                collect_positively_required_predicate_calls(inner, src, out);
            }
        }
        "call_expression" => out.push(condition),
        "binary_expression" if binary_operator_text(condition, src) == Some("&&") => {
            if let Some(left) = condition.child_by_field_name("left") {
                collect_positively_required_predicate_calls(left, src, out);
            }
            if let Some(right) = condition.child_by_field_name("right") {
                collect_positively_required_predicate_calls(right, src, out);
            }
        }
        _ => {}
    }
}

fn binary_operator_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    let mut cursor = node.walk();
    let operator = node
        .children(&mut cursor)
        .find(|child| !child.is_named())
        .map(|child| node_text(&child, src).trim());
    operator
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let child = node.named_children(&mut cursor).next();
    child
}

fn predicate_subscript_input(predicate: Node<'_>, src: &[u8]) -> Option<String> {
    let arguments = predicate.child_by_field_name("arguments")?;
    let argument = first_named_child(arguments)?;
    let subscripts = node_and_descendants_of_kind(argument, "subscript_expression");
    let [subscript] = subscripts.as_slice() else {
        return None;
    };
    subscript_base_place(*subscript, src)
}

fn node_and_descendants_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    if root.kind() == kind {
        matches.push(root);
    }
    matches.extend(descendant_nodes_of_kind(root, kind));
    matches
}

fn filtered_element_copy(write: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    if assignment_operator_text(write, src)? != "=" {
        return None;
    }
    let left = write.child_by_field_name("left")?;
    let right = write.child_by_field_name("right")?;
    if left.kind() != "subscript_expression" || right.kind() != "subscript_expression" {
        return None;
    }
    Some((
        subscript_base_place(left, src)?,
        subscript_base_place(right, src)?,
    ))
}

fn assignment_operator_text<'a>(node: Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let between = src.get(left.end_byte()..right.start_byte())?;
    std::str::from_utf8(between).ok().map(str::trim)
}

fn subscript_base_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    let base = node.child_by_field_name("argument")?;
    let value = node_text(&base, src).trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn output_is_zero_initialized(initializers: &[Node<'_>], output: &str, before: usize, src: &[u8]) -> bool {
    initializers
        .iter()
        .copied()
        .filter(|declarator| declarator.end_byte() <= before)
        .any(|declarator| {
            let Some(binding) = declarator.child_by_field_name("declarator") else {
                return false;
            };
            let Some(value) = declarator.child_by_field_name("value") else {
                return false;
            };
            binding.kind() == "array_declarator"
                && declarator_base_place(binding, src).as_deref() == Some(output)
                && zero_initializer(value, src)
        })
}

fn declarator_base_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(&node, src).to_string());
    }
    node.child_by_field_name("declarator")
        .and_then(|inner| declarator_base_place(inner, src))
}

fn zero_initializer(node: Node<'_>, src: &[u8]) -> bool {
    if node.kind() != "initializer_list" {
        return false;
    }
    let mut cursor = node.walk();
    let values: Vec<_> = node.named_children(&mut cursor).collect();
    !values.is_empty() && values.into_iter().all(|value| zero_scalar(value, src))
}

fn zero_scalar(node: Node<'_>, src: &[u8]) -> bool {
    matches!(node.kind(), "number_literal" | "char_literal")
        && matches!(node_text(&node, src).trim(), "0" | "'\\0'")
}

fn output_has_only_filtered_or_zero_writes(
    assignments: &[Node<'_>],
    output: &str,
    filtered_write: Node<'_>,
    src: &[u8],
) -> bool {
    let mut dynamic_writes = 0usize;
    for assignment in assignments {
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        let targets_output = if left.kind() == "subscript_expression" {
            subscript_base_place(left, src).as_deref() == Some(output)
        } else {
            node_text(&left, src).trim() == output
        };
        if !targets_output {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            return false;
        };
        if zero_scalar(right, src) {
            continue;
        }
        dynamic_writes += 1;
        if *assignment != filtered_write || filtered_element_copy(*assignment, src).is_none() {
            return false;
        }
    }
    dynamic_writes == 1
}

fn output_is_zero_terminated_after(assignments: &[Node<'_>], output: &str, after: usize, src: &[u8]) -> bool {
    assignments
        .iter()
        .copied()
        .filter(|assignment| assignment.start_byte() >= after)
        .any(|assignment| {
            assignment
                .child_by_field_name("left")
                .filter(|left| left.kind() == "subscript_expression")
                .and_then(|left| subscript_base_place(left, src))
                .as_deref()
                == Some(output)
                && assignment
                    .child_by_field_name("right")
                    .is_some_and(|right| zero_scalar(right, src))
        })
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
    let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
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
