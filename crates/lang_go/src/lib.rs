//! Go language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, CallArg, DeclIndex, FlowEvent, GrammarHandler, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, TypeAliasBinding, Visibility,
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

type GoRangeAssignments = Vec<FlowEvent>;
type GoRangeLoopAssignments = Vec<(Span, GoRangeAssignments)>;
type GoRangeAssignmentsByDecl = Vec<(Span, GoRangeLoopAssignments)>;
type GoIfInitAssignments = Vec<FlowEvent>;
type GoIfInitAssignmentsByDecl = Vec<(Span, Vec<(Span, GoIfInitAssignments)>)>;

const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &["function_declaration", "method_declaration"],
    call_kinds: GO_CALL_KINDS,
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
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
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: bonsai_lang_api::NO_SUPER_RECEIVER_TOKENS,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Go module_path = workspace-relative package directory plus
        // the file's `package <name>` declaration. The package name
        // alone is not semantic identity: unrelated command packages
        // are often all named `main`, and must not resolve into one
        // another. Falls back to file-stem when the package
        // declaration isn't present.
        let parsed = parse_with(PACK_NAME, file, ctx);
        let package_segment = parsed.as_ref().and_then(|(snapshot, tree)| {
            extract_go_package(tree.root_node(), snapshot.text.as_bytes())
                .map(|name| go_module_segments(file, ctx, &name))
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
            // Phase-6 return-type extraction: `func f() T {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            // Go uses `result` field for return type in the grammar.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            let aliases_by_span = collect_go_method_type_aliases(&tree, file, src);
            let method_receivers_by_span = collect_go_method_receiver_types(&tree, file, src);
            let bases_by_span = collect_go_class_bases(&tree, file, src);
            let range_assignments_by_span = collect_go_range_assignments_by_decl(&tree, file, src);
            let if_init_assignments_by_span = collect_go_if_init_assignments_by_decl(&tree, file, src);
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
                if let Some(range_assignments) = range_assignments_by_span
                    .iter()
                    .find_map(|(span, assignments)| (*span == decl.span).then_some(assignments.as_slice()))
                {
                    augment_go_range_assignments(&mut decl.flow_events, range_assignments);
                }
                if let Some(if_init_assignments) = if_init_assignments_by_span
                    .iter()
                    .find_map(|(span, assignments)| (*span == decl.span).then_some(assignments.as_slice()))
                {
                    augment_go_if_init_assignments(
                        &mut decl.flow_events,
                        if_init_assignments,
                        &decl.type_aliases,
                    );
                }
            }
        }
        // Append `FlowEvent::Lifecycle` for recognised Go
        // resource transitions (`f.Close()`, `mu.Unlock()`,
        // `cancel()`, `C.free`). Receiver-style calls land with
        // `name = "Close"` and `args[0] = "f"`, so arg_index 0
        // points at the receiver text.
        for decl in &mut idx.defs {
            augment_go_composite_literal_field_assignments(&mut decl.flow_events);
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, GO_LIFECYCLE_TRANSITIONS);
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        apply_go_projected_receiver_aliases(&mut idx);
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
    for fn_node in collect_kinds(
        tree,
        &["function_declaration", "method_declaration", "func_literal"],
    ) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        // `method_declaration` has a `receiver` (parameter_list with
        // one entry); both function and method have `parameters`.
        if let Some(receiver) = fn_node.child_by_field_name("receiver") {
            collect_go_parameter_aliases(receiver, src, &mut aliases);
        }
        if let Some(params) = fn_node.child_by_field_name("parameters") {
            collect_go_parameter_aliases(params, src, &mut aliases);
        }
        collect_go_func_literal_parameter_aliases(fn_node, src, &mut aliases);
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
        if child.kind() != "parameter_declaration" && child.kind() != "variadic_parameter_declaration" {
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

fn collect_go_range_assignments_by_decl(tree: &Tree, file: FileId, src: &[u8]) -> GoRangeAssignmentsByDecl {
    let channel_returns = collect_go_channel_return_functions(tree, src);
    let mut out = Vec::new();
    for fn_node in collect_kinds(
        tree,
        &["function_declaration", "method_declaration", "func_literal"],
    ) {
        let mut loop_assignments = Vec::new();
        for for_stmt in collect_kinds_under(&fn_node, &["for_statement"]) {
            let Some(range_clause) = direct_go_range_clause(for_stmt) else {
                continue;
            };
            let assignments = go_range_clause_assignments(range_clause, file, src, &channel_returns);
            if !assignments.is_empty() {
                loop_assignments.push((span_of(file, &for_stmt), assignments));
            }
        }
        if !loop_assignments.is_empty() {
            out.push((span_of(file, &fn_node), loop_assignments));
        }
    }
    out
}

fn collect_go_if_init_assignments_by_decl(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> GoIfInitAssignmentsByDecl {
    let mut out = Vec::new();
    for fn_node in collect_kinds(
        tree,
        &["function_declaration", "method_declaration", "func_literal"],
    ) {
        let mut init_assignments = Vec::new();
        for if_stmt in collect_kinds_under(&fn_node, &["if_statement"]) {
            let Some(init) = if_stmt.child_by_field_name("initializer") else {
                continue;
            };
            let events = go_initializer_assignment_events(init, file, src);
            if !events.is_empty() {
                init_assignments.push((span_of(file, &if_stmt), events));
            }
        }
        if !init_assignments.is_empty() {
            out.push((span_of(file, &fn_node), init_assignments));
        }
    }
    out
}

fn collect_go_channel_return_functions(tree: &Tree, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, &["function_declaration", "method_declaration"]) {
        let Some(result) = fn_node.child_by_field_name("result") else {
            continue;
        };
        if !go_type_text_is_channel(node_text(&result, src)) {
            continue;
        }
        if let Some(name_node) = fn_node.child_by_field_name("name") {
            push_unique_string(&mut out, node_text(&name_node, src).trim().to_string());
        }
    }
    out
}

fn direct_go_range_clause(for_stmt: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = for_stmt.walk();
    for child in for_stmt.named_children(&mut cursor) {
        if child.kind() == "range_clause" {
            return Some(child);
        }
    }
    None
}

fn go_range_clause_assignments(
    range_clause: Node<'_>,
    file: FileId,
    src: &[u8],
    channel_returns: &[String],
) -> Vec<FlowEvent> {
    let Some(left) = range_clause.child_by_field_name("left") else {
        return Vec::new();
    };
    let Some(right) = range_clause.child_by_field_name("right") else {
        return Vec::new();
    };
    let targets = direct_go_range_targets(left, src);
    if targets.is_empty() {
        return Vec::new();
    }
    let span = span_of(file, &range_clause);
    let right_text = node_text(&right, src).trim();
    let mut out = Vec::new();

    if targets.len() >= 2 {
        if let Some(target) = targets.get(1).filter(|target| target.as_str() != "_") {
            out.push(go_range_value_assignment(span, target, right, right_text, src));
        }
        return out;
    }

    let target = &targets[0];
    if target == "_" || !go_range_single_target_is_value(right, src, channel_returns) {
        return Vec::new();
    }
    out.push(go_range_value_assignment(span, target, right, right_text, src));
    out
}

fn direct_go_range_targets(left: Node<'_>, src: &[u8]) -> Vec<String> {
    if left.kind() == "identifier" {
        return vec![node_text(&left, src).trim().to_string()];
    }
    let mut out = Vec::new();
    let mut cursor = left.walk();
    for child in left.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            out.push(node_text(&child, src).trim().to_string());
        }
    }
    out
}

fn go_range_value_assignment(
    span: Span,
    target: &str,
    right: Node<'_>,
    right_text: &str,
    src: &[u8],
) -> FlowEvent {
    let call = go_call_expression_parts(right, src);
    let source_call = call.as_ref().map(|(name, _)| name.clone());
    let source_call_args = if source_call.is_some() {
        call.map(|(_, args)| args).unwrap_or_default()
    } else {
        Vec::new()
    };
    let source_name = if source_call.is_none() {
        go_bare_value_name(right_text)
    } else {
        None
    };
    let source_names = if source_call.is_none() {
        go_range_value_source_names(right_text, source_name.as_deref())
    } else {
        Vec::new()
    };
    let value_kind = if source_call.is_some() {
        bonsai_lang_api::AssignValueKind::CallResult
    } else {
        bonsai_lang_api::AssignValueKind::Compound
    };
    FlowEvent::Assign {
        span,
        target: target.to_string(),
        source_name,
        source_call,
        source_call_args,
        source_names,
        declares_new_binding: true,
        value_kind: Some(value_kind),
    }
}

fn go_range_single_target_is_value(right: Node<'_>, src: &[u8], channel_returns: &[String]) -> bool {
    if right.kind() == "channel_type" || go_type_text_is_channel(node_text(&right, src)) {
        return true;
    }
    if let Some((callee, _)) = go_call_expression_parts(right, src) {
        return channel_returns.iter().any(|return_name| return_name == &callee);
    }
    false
}

fn go_call_expression_parts(node: Node<'_>, src: &[u8]) -> Option<(String, Vec<String>)> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node
        .child_by_field_name("function")
        .map(|function| node_text(&function, src).trim().to_string())
        .filter(|name| !name.is_empty())?;
    let args = node
        .child_by_field_name("arguments")
        .map(|arguments| {
            let mut out = Vec::new();
            let mut cursor = arguments.walk();
            for child in arguments.named_children(&mut cursor) {
                let text = node_text(&child, src).trim();
                if !text.is_empty() {
                    out.push(text.to_string());
                }
            }
            out
        })
        .unwrap_or_default();
    Some((callee, args))
}

fn go_initializer_assignment_events(init: Node<'_>, file: FileId, src: &[u8]) -> Vec<FlowEvent> {
    if !matches!(init.kind(), "short_var_declaration" | "assignment_statement") {
        return Vec::new();
    }
    let Some(left) = init.child_by_field_name("left") else {
        return Vec::new();
    };
    let Some(right) = init.child_by_field_name("right") else {
        return Vec::new();
    };
    let targets = direct_go_range_targets(left, src);
    let rhs_values = go_expression_list_values(right);
    if targets.is_empty() || rhs_values.is_empty() {
        return Vec::new();
    }
    let span = span_of(file, &init);
    let mut out = Vec::new();
    for (idx, target) in targets.iter().enumerate() {
        if target == "_" {
            continue;
        }
        let rhs = rhs_values
            .get(idx)
            .copied()
            .or_else(|| rhs_values.first().copied());
        let Some(rhs) = rhs else {
            continue;
        };
        let call = go_call_expression_parts(rhs, src);
        let (source_name, source_call, source_call_args, source_names, value_kind) =
            if let Some((callee, args)) = call.clone() {
                (
                    None,
                    Some(callee),
                    args,
                    Vec::new(),
                    Some(bonsai_lang_api::AssignValueKind::CallResult),
                )
            } else {
                let rhs_text = node_text(&rhs, src).trim();
                let source_name = go_bare_value_name(rhs_text);
                (
                    source_name.clone(),
                    None,
                    Vec::new(),
                    go_range_value_source_names(rhs_text, source_name.as_deref()),
                    Some(bonsai_lang_api::AssignValueKind::Compound),
                )
            };
        out.push(FlowEvent::Assign {
            span,
            target: target.to_string(),
            source_name,
            source_call,
            source_call_args,
            source_names,
            declares_new_binding: init.kind() == "short_var_declaration",
            value_kind,
        });
        if let Some((callee, args)) = call {
            out.push(go_call_event_from_parts(span_of(file, &rhs), &callee, args, file));
        }
    }
    out
}

fn go_expression_list_values(node: Node<'_>) -> Vec<Node<'_>> {
    if node.kind() != "expression_list" {
        return vec![node];
    }
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        out.push(child);
    }
    out
}

fn go_call_event_from_parts(span: Span, callee: &str, args: Vec<String>, file: FileId) -> FlowEvent {
    let receiver = callee.rsplit_once('.').map(|(recv, _)| recv.to_string());
    let call_kind = if receiver.is_some() {
        bonsai_lang_api::CallKind::Method
    } else {
        bonsai_lang_api::CallKind::Function
    };
    FlowEvent::Call {
        span,
        name: callee.to_string(),
        receiver,
        receiver_types: Vec::new(),
        call_kind,
        args: args
            .into_iter()
            .map(|value_text| {
                let source_names = go_value_source_names(&value_text);
                let place = go_argument_place(&value_text);
                CallArg {
                    passing_mode: Default::default(),
                    span: Span::new(file, span.start, span.end),
                    name: None,
                    value_text,
                    place,
                    source_names,
                }
            })
            .collect(),
    }
}

fn go_argument_place(value_text: &str) -> Option<String> {
    let trimmed = value_text.trim();
    let place = trimmed.strip_prefix('&').unwrap_or(trimmed).trim();
    if place.is_empty() {
        return None;
    }
    let mut chars = place.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    if chars.all(|ch| ch == '_' || ch == '.' || ch.is_ascii_alphanumeric()) {
        Some(place.to_string())
    } else {
        None
    }
}

fn go_range_value_source_names(right_text: &str, source_name: Option<&str>) -> Vec<String> {
    let mut names = go_value_source_names(right_text);
    if let Some(source_name) = source_name {
        names.retain(|name| name != source_name);
    }
    names
}

fn go_type_text_is_channel(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("<-chan ")
        || trimmed.starts_with("chan<- ")
        || trimmed.starts_with("chan ")
        || trimmed == "chan"
}

fn augment_go_range_assignments(events: &mut Vec<FlowEvent>, range_assignments: &[(Span, Vec<FlowEvent>)]) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_go_range_assignments(then_events, range_assignments);
                augment_go_range_assignments(else_events, range_assignments);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_go_range_assignments(body, range_assignments);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_go_range_assignments(body, range_assignments);
                augment_go_range_assignments(catch_events, range_assignments);
                augment_go_range_assignments(finally_events, range_assignments);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        if let FlowEvent::Assign { span, .. } = &event {
            if range_assignments.iter().any(|(loop_span, _)| loop_span == span) {
                continue;
            }
        }
        if let FlowEvent::Loop { span, .. } = &event {
            if let Some(assignments) = range_assignments
                .iter()
                .find_map(|(loop_span, assignments)| (loop_span == span).then_some(assignments))
            {
                rewritten.extend(assignments.iter().cloned());
            }
        }
        rewritten.push(event);
    }
    *events = rewritten;
}

fn augment_go_if_init_assignments(
    events: &mut Vec<FlowEvent>,
    if_init_assignments: &[(Span, Vec<FlowEvent>)],
    aliases: &[TypeAliasBinding],
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_go_if_init_assignments(then_events, if_init_assignments, aliases);
                augment_go_if_init_assignments(else_events, if_init_assignments, aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_go_if_init_assignments(body, if_init_assignments, aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_go_if_init_assignments(body, if_init_assignments, aliases);
                augment_go_if_init_assignments(catch_events, if_init_assignments, aliases);
                augment_go_if_init_assignments(finally_events, if_init_assignments, aliases);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        if let FlowEvent::Branch { span, .. } = &event {
            if let Some(init_events) = if_init_assignments
                .iter()
                .find_map(|(if_span, init_events)| (if_span == span).then_some(init_events))
            {
                rewritten.extend(init_events.iter().cloned().map(|mut event| {
                    enrich_go_synthetic_receiver_types(&mut event, aliases);
                    event
                }));
            }
        }
        rewritten.push(event);
    }
    *events = rewritten;
}

fn enrich_go_synthetic_receiver_types(event: &mut FlowEvent, aliases: &[TypeAliasBinding]) {
    let FlowEvent::Call {
        receiver: Some(receiver),
        receiver_types,
        ..
    } = event
    else {
        return;
    };
    if !receiver_types.is_empty() {
        return;
    }
    for alias in aliases {
        if alias.name == *receiver {
            push_unique_string(receiver_types, alias.type_name.clone());
        }
    }
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
        // WS2: `var c = make().(Foo)` — the type assertion is the only
        // type signal; binds the (first) name to the asserted type.
        let assertion_type = var_spec
            .child_by_field_name("value")
            .and_then(|value_node| go_direct_type_assertion_type(value_node, src));
        for (index, name) in names.iter().enumerate() {
            if let Some(ty) = declared_type.as_deref() {
                push_go_type_alias(aliases, name, ty);
            }
            if let Some(ty) = concrete_type.as_deref() {
                push_go_type_alias(aliases, name, ty);
            }
            if index == 0 {
                if let Some(ty) = assertion_type.as_deref() {
                    push_go_type_alias(aliases, name, ty);
                }
            }
        }
    }
    // WS2: `c := make().(Foo)` — short var declaration with a type
    // assertion RHS (not a `var_spec`, so the loop above never sees it).
    for short_var in collect_kinds_under(&node, &["short_var_declaration"]) {
        let Some(ty) = short_var
            .child_by_field_name("right")
            .and_then(|right| go_direct_type_assertion_type(right, src))
        else {
            continue;
        };
        // Bind the FIRST LHS name (the value; a comma-ok `v, ok :=` form
        // makes `ok` a bool, never the asserted type).
        if let Some(left) = short_var.child_by_field_name("left") {
            let mut cursor = left.walk();
            for child in left.named_children(&mut cursor) {
                if child.kind() == "identifier" {
                    let name = node_text(&child, src).trim();
                    if !name.is_empty() {
                        push_go_type_alias(aliases, name, &ty);
                    }
                    break;
                }
            }
        }
    }
}

/// WS2: the asserted type of a direct type-assertion RHS (`x.(Foo)` ->
/// `Foo`), unwrapping a single-element `expression_list` / parens. Returns
/// `None` for any other RHS shape so only a genuine assertion types the
/// local (a nested assertion inside a call arg must not leak).
fn go_direct_type_assertion_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut n = node;
    while matches!(n.kind(), "expression_list" | "parenthesized_expression") {
        let mut cursor = n.walk();
        n = n.named_children(&mut cursor).next()?;
    }
    if n.kind() == "type_assertion_expression" {
        let type_node = n.child_by_field_name("type")?;
        return canonical_go_type_name(node_text(&type_node, src));
    }
    None
}

fn apply_go_projected_receiver_aliases(idx: &mut DeclIndex) {
    for decl in &mut idx.defs {
        if decl.type_aliases.is_empty() {
            continue;
        }
        let base_aliases = decl.type_aliases.clone();
        let mut projected = Vec::new();
        collect_go_projected_receiver_aliases(&decl.flow_events, &base_aliases, &mut projected);
        for alias in projected {
            if !decl.type_aliases.contains(&alias) {
                decl.type_aliases.push(alias);
            }
        }
    }
}

fn collect_go_projected_receiver_aliases(
    events: &[FlowEvent],
    base_aliases: &[TypeAliasBinding],
    out: &mut Vec<TypeAliasBinding>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                receiver: Some(receiver),
                ..
            } => {
                if let Some(root) = go_projected_receiver_root(receiver) {
                    for alias in base_aliases.iter().filter(|alias| alias.name == root) {
                        let projected = TypeAliasBinding {
                            name: receiver.clone(),
                            type_name: alias.type_name.clone(),
                        };
                        if !out.contains(&projected) {
                            out.push(projected);
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_go_projected_receiver_aliases(then_events, base_aliases, out);
                collect_go_projected_receiver_aliases(else_events, base_aliases, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_go_projected_receiver_aliases(body, base_aliases, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_go_projected_receiver_aliases(body, base_aliases, out);
                collect_go_projected_receiver_aliases(catch_events, base_aliases, out);
                collect_go_projected_receiver_aliases(finally_events, base_aliases, out);
            }
            FlowEvent::Call { receiver: None, .. }
            | FlowEvent::Assign { .. }
            | FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. }
            | FlowEvent::Yield { .. }
            | FlowEvent::Await { .. }
            | FlowEvent::Lifecycle { .. } => {}
        }
    }
}

fn go_projected_receiver_root(receiver: &str) -> Option<&str> {
    if receiver.contains('(') || receiver.contains(')') {
        return None;
    }
    let (root, rest) = receiver.split_once('.')?;
    if !go_identifier_like(root) {
        return None;
    }
    let first_projection = rest.split('.').next().unwrap_or(rest);
    go_identifier_like(first_projection).then_some(root)
}

fn go_identifier_like(segment: &str) -> bool {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
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

fn augment_go_composite_literal_field_assignments(events: &mut Vec<FlowEvent>) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_go_composite_literal_field_assignments(then_events);
                augment_go_composite_literal_field_assignments(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_go_composite_literal_field_assignments(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_go_composite_literal_field_assignments(body);
                augment_go_composite_literal_field_assignments(catch_events);
                augment_go_composite_literal_field_assignments(finally_events);
            }
            _ => {}
        }
    }

    let snapshot = events.clone();
    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let mut synthetic = Vec::new();
        let mut carrier_span = None;
        if let FlowEvent::Assign { span, target, .. } = &event {
            if !target.trim().is_empty() && !target.contains('.') {
                carrier_span = Some(*span);
                for candidate in &snapshot {
                    let FlowEvent::Call {
                        span: call_span,
                        args,
                        ..
                    } = candidate
                    else {
                        continue;
                    };
                    if call_span.file != span.file || call_span.start < span.start || call_span.end > span.end
                    {
                        continue;
                    }
                    for arg in args {
                        collect_go_composite_field_assignments(
                            target,
                            &arg.value_text,
                            *span,
                            &mut synthetic,
                        );
                    }
                }
            }
        }
        rewritten.push(event);
        let Some(carrier_span) = carrier_span else {
            continue;
        };
        let mut expanded = synthetic.clone();
        for field_event in &synthetic {
            let FlowEvent::Assign {
                target: field_target,
                source_name: Some(source_name),
                ..
            } = field_event
            else {
                continue;
            };
            let source_prefix = format!("{source_name}.");
            for prior in &rewritten {
                let FlowEvent::Assign {
                    target: prior_target,
                    source_name: prior_source_name,
                    source_names: prior_source_names,
                    ..
                } = prior
                else {
                    continue;
                };
                let Some(tail) = prior_target.strip_prefix(&source_prefix) else {
                    continue;
                };
                if tail.is_empty() {
                    continue;
                }
                expanded.push(FlowEvent::Assign {
                    span: carrier_span,
                    target: format!("{field_target}.{tail}"),
                    source_name: prior_source_name.clone(),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: prior_source_names.clone(),
                    declares_new_binding: false,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                });
            }
        }
        for event in expanded {
            if !rewritten
                .iter()
                .any(|existing| go_flow_event_same_assignment(existing, &event))
            {
                rewritten.push(event);
            }
        }
    }
    *events = rewritten;
}

fn go_flow_event_same_assignment(existing: &FlowEvent, candidate: &FlowEvent) -> bool {
    matches!(
        (existing, candidate),
        (
            FlowEvent::Assign {
                span: existing_span,
                target: existing_target,
                source_names: existing_sources,
                ..
            },
            FlowEvent::Assign {
                span: candidate_span,
                target: candidate_target,
                source_names: candidate_sources,
                ..
            }
        ) if existing_span == candidate_span
            && existing_target == candidate_target
            && existing_sources == candidate_sources
    )
}

fn collect_go_composite_field_assignments(
    base_target: &str,
    field_expr: &str,
    span: Span,
    out: &mut Vec<FlowEvent>,
) {
    let Some((field, value)) = go_split_top_level_once(field_expr, ':') else {
        return;
    };
    let field = field.trim();
    if !go_identifier_like(field) {
        return;
    }
    let value = value.trim();
    let target = format!("{base_target}.{field}");
    let source_names = go_value_source_names(value);
    out.push(FlowEvent::Assign {
        span,
        target: target.clone(),
        source_name: go_bare_value_name(value),
        source_call: None,
        source_call_args: Vec::new(),
        source_names,
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    });
    for body in go_composite_literal_bodies(value) {
        for part in go_split_top_level(&body, ',') {
            collect_go_composite_field_assignments(&target, &part, span, out);
        }
    }
}

fn go_bare_value_name(value: &str) -> Option<String> {
    let value = value.trim();
    go_identifier_like(value).then(|| value.to_string())
}

fn go_value_source_names(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in value.chars().chain(std::iter::once(' ')) {
        if let Some(quote_ch) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote_ch {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            push_unique_string(&mut out, token.trim_matches('.').to_string());
            token.clear();
            quote = Some(ch);
            continue;
        }
        if ch == '.' || ch == '_' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }
        push_unique_string(&mut out, token.trim_matches('.').to_string());
        token.clear();
    }
    out.retain(|name| !name.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()));
    out
}

fn go_composite_literal_bodies(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(quote_ch) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote_ch {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '{' => stack.push(idx),
            '}' => {
                if let Some(start) = stack.pop() {
                    if start < idx {
                        out.push(text[start + 1..idx].to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn go_split_top_level(text: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(quote_ch) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote_ch {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            c if c == sep && depth == 0 => {
                let part = text[start..idx].trim();
                if !part.is_empty() {
                    parts.push(part.to_string());
                }
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    let part = text[start..].trim();
    if !part.is_empty() {
        parts.push(part.to_string());
    }
    parts
}

fn go_split_top_level_once(text: &str, sep: char) -> Option<(String, String)> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(quote_ch) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote_ch {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            c if c == sep && depth == 0 => {
                return Some((
                    text[..idx].trim().to_string(),
                    text[idx + ch.len_utf8()..].trim().to_string(),
                ));
            }
            _ => {}
        }
    }
    None
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

fn collect_go_func_literal_parameter_aliases(
    fn_node: Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    for literal in collect_kinds_under(&fn_node, &["func_literal"]) {
        if let Some(params) = literal.child_by_field_name("parameters") {
            collect_go_parameter_aliases(params, src, aliases);
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
    // Also keep the package-qualified form when present (`gin.Context`
    // alongside `Context`). The unqualified canonical drives method
    // dispatch lookup; the qualified form is what the rule-matcher
    // chases through the alias map for the package gate
    // (`alias_map.get("gin")` → `Namespace{github.com/gin-gonic/gin}`).
    let qualified =
        qualified_go_type_name(node_text(&type_node, src)).filter(|qualified| qualified != &canonical);
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
                if let Some(q) = qualified.as_deref() {
                    push_go_type_alias(aliases, &name, q);
                }
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
                if let Some(q) = qualified.as_deref() {
                    push_go_type_alias(aliases, &name, q);
                }
            }
        }
    }
}

/// Strip pointer / array / map / generic wrappers but keep the
/// package qualifier when present. `*gin.Context` → `gin.Context`,
/// `*http.Request` → `http.Request`, `[]string` → `string`,
/// `Foo[T]` → `Foo`. Returns `None` when no qualifier survives the
/// strip (so callers can skip the redundant push).
fn qualified_go_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('*').trim_start_matches('&').trim();
    let after_brackets = if let Some(rest) = trimmed.strip_prefix("[]") {
        rest.trim()
    } else if let Some(rest) = trimmed.strip_prefix("map[") {
        rest.split_once(']')
            .map_or(rest, |(_, value_type)| value_type)
            .trim()
    } else if trimmed.starts_with('[') {
        trimmed
            .split_once(']')
            .map_or(trimmed, |(_, value_type)| value_type)
            .trim()
    } else {
        trimmed
    };
    let without_generic = after_brackets.split('[').next().unwrap_or(after_brackets).trim();
    if without_generic.contains('.') && !without_generic.is_empty() {
        Some(without_generic.to_string())
    } else {
        None
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

fn go_module_segments(file: FileId, ctx: &AdapterContext<'_>, package_name: &str) -> Vec<String> {
    let mut segments: Vec<String> = ctx
        .workspace_relative_path(file)
        .and_then(|path| {
            let parent = path.parent()?;
            Some(
                parent
                    .components()
                    .filter_map(|component| match component {
                        std::path::Component::Normal(part) => {
                            let text = part.to_string_lossy();
                            (!text.is_empty()).then(|| text.into_owned())
                        }
                        _ => None,
                    })
                    .collect(),
            )
        })
        .unwrap_or_default();
    if segments.last().is_none_or(|last| last != package_name) {
        segments.push(package_name.to_string());
    }
    segments
}
