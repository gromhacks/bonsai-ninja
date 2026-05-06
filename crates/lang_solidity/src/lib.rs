//! Solidity language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_modifier_visibility, collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, CallArg, CallKind, DeclIndex, DeclKind, FlowEvent, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId,
    ModifierVocabulary, TypeAliasVocabulary, Visibility,
};

const SOLIDITY_VOCAB: ModifierVocabulary = ModifierVocabulary {
    decl_kinds: &[
        "function_definition",
        "modifier_definition",
        "constructor_definition",
        "fallback_receive_definition",
        "state_variable_declaration",
    ],
    modifier_container_kinds: &["visibility"],
    keyword_to_visibility: &[
        ("private", Visibility::Private),
        ("internal", Visibility::Crate),
        ("external", Visibility::Public),
        ("public", Visibility::Public),
    ],
    // Solidity functions default to `public` if the visibility
    // keyword is omitted (older versions); newer compilers require
    // it. `Public` is the safest default.
    default_visibility: Visibility::Public,
};

const SOLIDITY_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &[
        "function_definition",
        "constructor_definition",
        "modifier_definition",
        "fallback_receive_definition",
    ],
    param_kinds: &["parameter"],
    name_field: "name",
    type_field: "type",
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("solidity");
const PACK_NAME: &str = "solidity";

// tree-sitter-solidity handler. Function-shaped decls cover regular
// contract functions, constructors, modifiers, and the special
// fallback/receive functions. Solidity uses `revert` (and `require`)
// as throw-equivalents — we surface revert_statement explicitly.
const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &[
        "function_definition",
        "constructor_definition",
        "modifier_definition",
        "fallback_receive_definition",
    ],
    class_kinds: &[
        "contract_declaration",
        "interface_declaration",
        "library_declaration",
    ],
    method_kinds: &["function_definition"],
    method_context_kinds: &[
        "contract_declaration",
        "interface_declaration",
        "library_declaration",
    ],
    constructor_method_kinds: &["constructor_definition"],
    constructor_names: &[],
    if_kinds: &["if_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &[],
    while_kinds: &["while_statement"],
    do_kinds: &["do_while_statement"],
    loop_kinds: &[],
    call_kinds: &["call_expression", "modifier_invocation"],
    assignment_kinds: &["assignment_expression", "variable_declaration_statement"],
    return_kinds: &["return_statement"],
    throw_kinds: &["revert_statement"],
    lambda_kinds: &[],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    finally_kinds: &[],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &[],
    method_receiver_param_index: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct SolidityAdapter;

impl SolidityAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for SolidityAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Solidity"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["sol"]
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
        // Synthesize Call events for Yul function calls inside
        // `assembly { ... }` blocks. tree-sitter-solidity surfaces Yul
        // calls as `yul_function_call` (or `yul_evm_builtin_call` on
        // older grammar revisions); the generic walker doesn't know
        // about Yul because Yul is a separate sub-grammar inside
        // Solidity. Without lowering, the canonical reentrancy /
        // selfdestruct shape `assembly { call(gas(), target, ...) }`
        // is invisible to the engine.
        let source = ctx
            .vfs
            .snapshot(file)
            .ok()
            .map(|s| s.text.to_string())
            .unwrap_or_default();
        if !source.is_empty() {
            if let Ok(lang) = language_from_pack(PACK_NAME) {
                let mut parser = tree_sitter::Parser::new();
                if parser.set_language(&lang).is_ok() {
                    if let Some(tree) = parser.parse(&source, None) {
                        let mut synthetic_calls = synthesize_yul_call_events(&tree, source.as_bytes(), file);
                        synthetic_calls.extend(synthesize_emit_call_events(&tree, source.as_bytes(), file));
                        if !synthetic_calls.is_empty() {
                            attach_synthesized_calls_to_decls(&mut idx, synthetic_calls);
                        }
                    }
                }
            }
        }
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_modifier_visibility(tree.root_node(), file, src, &SOLIDITY_VOCAB);
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
            }
            let type_aliases_by_span = collect_param_type_aliases(&tree, file, src, &SOLIDITY_TYPE_ALIASES);
            for decl in &mut idx.defs {
                if let Some(aliases) = type_aliases_by_span.get(&decl.span) {
                    decl.type_aliases = aliases.clone();
                }
            }
            // Per-contract `bases`: `contract A is B, C { … }` →
            // ["B", "C"]. Solidity wraps each parent in a separate
            // `inheritance_specifier` direct child of the contract,
            // each with `ancestor:` field naming a `user_defined_type`.
            let bases_by_span = collect_solidity_class_bases(&tree, file, src);
            for decl in &mut idx.defs {
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
            for decl in &mut idx.defs {
                synthesize_try_return_assigns(&mut decl.flow_events, src);
            }
        }
        // Recognised Solidity lifecycle transitions. `selfdestruct`
        // wipes contract code/state (freed). `transfer` moves ETH
        // ownership (modeled as `moved`); the matcher treats this
        // conservatively — many `transfer(...)` shapes are token
        // transfers that don't actually move ownership in the
        // lifecycle sense, but the lattice tolerates over-tagging
        // since `moved` is a use-after-move signal, not a sink.
        const SOLIDITY_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "selfdestruct",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "transfer",
                transition: "moved",
                arg_index: 0,
            },
        ];
        for decl in &mut idx.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, SOLIDITY_LIFECYCLE_TRANSITIONS);
        }
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Walk every `assembly` / `yul_block` node and synthesise a Call
/// event for each Yul `yul_function_call` (or older `yul_evm_builtin_call`)
/// inside. The Yul callee text becomes the Call's name (e.g. `call`,
/// `delegatecall`, `selfdestruct`, `sstore`); arguments are best-effort
/// extracted from the yul_function_call's named children.
fn synthesize_yul_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    const ASSEMBLY_KINDS: &[&str] = &["assembly_statement", "yul_block"];
    const YUL_CALL_KINDS: &[&str] = &["yul_function_call", "yul_evm_builtin_call", "yul_call"];
    let mut synthesized = Vec::new();
    let assembly_blocks = collect_kinds(tree, ASSEMBLY_KINDS);
    if assembly_blocks.is_empty() {
        return synthesized;
    }
    for asm in assembly_blocks {
        // DFS the Yul sub-grammar manually; collect_kinds doesn't recurse into it.
        let mut stack: Vec<tree_sitter::Node<'_>> = Vec::new();
        let mut cursor = asm.walk();
        for child in asm.named_children(&mut cursor) {
            stack.push(child);
        }
        while let Some(node) = stack.pop() {
            if YUL_CALL_KINDS.contains(&node.kind()) {
                let span = span_of(file, &node);
                // Yul function call: first named child is the callee
                // identifier (`call`, `gas`, `selfdestruct`, …);
                // remaining named children are positional arguments.
                let mut child_cursor = node.walk();
                let children: Vec<tree_sitter::Node<'_>> = node.named_children(&mut child_cursor).collect();
                let Some(callee_node) = children.first() else {
                    continue;
                };
                let name = node_text(callee_node, src).trim().to_string();
                if name.is_empty() {
                    continue;
                }
                let mut args: Vec<CallArg> = Vec::new();
                for arg_node in children.iter().skip(1) {
                    let text = node_text(arg_node, src).trim().to_string();
                    if text.is_empty() {
                        continue;
                    }
                    args.push(CallArg {
                        span: span_of(file, arg_node),
                        name: None,
                        value_text: text,
                        place: None,
                    });
                }
                let event = FlowEvent::Call {
                    span,
                    name,
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args,
                };
                synthesized.push((span, event));
            }
            // Descend into nested Yul scopes (loops, switches, blocks).
            let mut descend_cursor = node.walk();
            for child in node.named_children(&mut descend_cursor) {
                stack.push(child);
            }
        }
    }
    synthesized
}

/// Synthesize an `emit(...)` FlowEvent carrying the event payload args.
///
/// The generic Solidity walker records the event constructor call
/// (`Action(userId, action)`) and the ref index records `emit`, but the
/// security rulepack intentionally keys event-log sinks on the Solidity
/// keyword. Taint needs the payload arguments on that keyword-shaped sink,
/// so add a parallel synthetic call at the `emit_statement` span.
fn synthesize_emit_call_events(tree: &Tree, src: &[u8], file: FileId) -> Vec<(Span, FlowEvent)> {
    let mut synthesized = Vec::new();
    for emit_node in collect_kinds(tree, &["emit_statement"]) {
        let span = span_of(file, &emit_node);
        let mut args = Vec::new();
        let mut cursor = emit_node.walk();
        for child in emit_node.named_children(&mut cursor) {
            if child.kind() != "call_argument" {
                continue;
            }
            // Unwrap the `call_argument` to its inner expression so the value
            // text matches what shows up at non-emit call sites.
            let value_node = first_named_child(child).unwrap_or(child);
            let value_text = collapse_whitespace(node_text(&value_node, src));
            if value_text.is_empty() {
                continue;
            }
            args.push(CallArg {
                span: span_of(file, &child),
                name: None,
                place: simple_identifier_place(&value_node, src),
                value_text,
            });
        }
        synthesized.push((
            span,
            FlowEvent::Call {
                span,
                name: "emit".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args,
            },
        ));
    }
    synthesized
}

/// Route each synthetic FlowEvent to the innermost decl whose body contains it.
///
/// Solidity functions don't nest at the language level, but defensive picking
/// matches the PHP / Perl implementations and means a future grammar change
/// that exposes nested scopes (e.g. inline-assembly Yul function defs) won't
/// silently route synthetic events to the outer contract.
fn attach_synthesized_calls_to_decls(idx: &mut DeclIndex, events: Vec<(Span, FlowEvent)>) {
    for (event_span, event) in events {
        let mut best_decl_idx: Option<usize> = None;
        let mut best_body_len: u64 = u64::MAX;
        for (decl_idx, decl) in idx.defs.iter().enumerate() {
            let body = decl.body_span.unwrap_or(decl.span);
            // Same-file, fully nested span — candidate container.
            if event_span.file == body.file && event_span.start >= body.start && event_span.end <= body.end {
                let body_len = body.end.saturating_sub(body.start);
                // Innermost wins: smaller body span is more specific.
                if body_len < best_body_len {
                    best_decl_idx = Some(decl_idx);
                    best_body_len = body_len;
                }
            }
        }
        if let Some(target_idx) = best_decl_idx {
            idx.defs[target_idx].flow_events.push(event);
        }
    }
}

/// For every `try (...) returns (T name) { ... }` block, prepend a synthetic
/// `Assign { target: name, source_call: ... }` to the try body so taint flows
/// from the called expression into the bound return variable.
fn synthesize_try_return_assigns(events: &mut Vec<FlowEvent>, src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(target) = solidity_try_return_binding(*span, src) {
                    // Skip if the user already assigns the bound name explicitly.
                    let already_assigned = body.iter().any(|event| {
                        matches!(event, FlowEvent::Assign { target: existing, .. } if existing == &target)
                    });
                    if !already_assigned {
                        if let Some(call) = first_call_event(body) {
                            let (source_call, source_call_args, source_names, call_span) =
                                call_as_assignment_source(call);
                            body.insert(
                                0,
                                FlowEvent::Assign {
                                    span: call_span,
                                    target,
                                    source_name: None,
                                    source_call: Some(source_call),
                                    source_call_args,
                                    source_names,
                                },
                            );
                        }
                    }
                }
                // Recurse into try/catch/finally to handle nested try blocks.
                synthesize_try_return_assigns(body, src);
                synthesize_try_return_assigns(catch_events, src);
                synthesize_try_return_assigns(finally_events, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                synthesize_try_return_assigns(then_events, src);
                synthesize_try_return_assigns(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                synthesize_try_return_assigns(body, src);
            }
            _ => {}
        }
    }
}

/// Extract the bound return identifier from `try ... returns (T name) { ... }`.
///
/// Returns `None` for catch-only try blocks or when the binding is just a type
/// (no name). We text-scan rather than tree-walk because the grammar's
/// `try_statement` shape doesn't expose the returns clause as a named field.
fn solidity_try_return_binding(span: Span, src: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(src.get(span.start as usize..span.end as usize)?).ok()?;
    let returns_start = text.find("returns")?;
    let after_returns = &text[returns_start + "returns".len()..];
    let open = after_returns.find('(')?;
    let after_open = &after_returns[open + 1..];
    let close = after_open.find(')')?;
    let binding = &after_open[..close];
    // Tokenise on non-identifier characters so we can pick the trailing name.
    let tokens: Vec<&str> = binding
        .split(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
        .filter(|part| !part.is_empty())
        .collect();
    // Need at least `<type> <name>`; bare `returns (uint)` carries no binding.
    if tokens.len() < 2 {
        return None;
    }
    let candidate = tokens.last().copied()?;
    // Reject Solidity type/storage keywords masquerading as the trailing token.
    if matches!(
        candidate,
        "memory"
            | "calldata"
            | "storage"
            | "uint"
            | "uint256"
            | "int"
            | "int256"
            | "address"
            | "bool"
            | "string"
            | "bytes"
    ) {
        return None;
    }
    Some(candidate.to_string())
}

/// Find the first `Call` event in pre-order, descending into nested scopes.
///
/// Used to find the call expression a `try` block targets, since the
/// kit-emitted try body lists the call as a regular FlowEvent::Call.
fn first_call_event(events: &[FlowEvent]) -> Option<&FlowEvent> {
    for event in events {
        match event {
            FlowEvent::Call { .. } => return Some(event),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(found) = first_call_event(then_events).or_else(|| first_call_event(else_events)) {
                    return Some(found);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(found) = first_call_event(body) {
                    return Some(found);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(found) = first_call_event(body)
                    .or_else(|| first_call_event(catch_events))
                    .or_else(|| first_call_event(finally_events))
                {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// Decompose a `Call` event into the fields needed to seed an `Assign`'s
/// `source_call` / `source_call_args` / `source_names` / span.
///
/// Returns the canonical name, argument value-texts, deduplicated alias
/// candidates (receiver, full name, dotted halves), and the call span.
fn call_as_assignment_source(call: &FlowEvent) -> (String, Vec<String>, Vec<String>, Span) {
    let FlowEvent::Call {
        span,
        name,
        receiver,
        args,
        ..
    } = call
    else {
        unreachable!("first_call_event only returns call events")
    };
    let mut source_names = Vec::new();
    if let Some(receiver) = receiver {
        source_names.push(receiver.clone());
    }
    source_names.push(name.clone());
    // Split `obj.method` into both halves so name-based matching catches either form.
    if let Some((receiver_half, method_half)) = name.rsplit_once('.') {
        source_names.push(receiver_half.to_string());
        source_names.push(method_half.to_string());
    }
    source_names.sort();
    source_names.dedup();
    (
        name.clone(),
        args.iter().map(|arg| arg.value_text.clone()).collect(),
        source_names,
        *span,
    )
}

/// First named child of `node`, or `None` for leaf nodes.
fn first_named_child(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut cursor = node.walk();
    let first = node.named_children(&mut cursor).next();
    first
}

/// Normalize whitespace runs in `text` to single spaces.
fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Return the node text as a `place` only when it's a simple identifier or
/// field access — the engine's place-tracking can match those reliably.
/// Anything more complex (calls, indexing, casts) returns `None`.
fn simple_identifier_place(node: &tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    matches!(
        node.kind(),
        "identifier" | "member_expression" | "field_expression"
    )
    .then(|| collapse_whitespace(node_text(node, src)))
    .filter(|s| !s.is_empty())
}

/// True when the decl is a type-defining container that can carry `bases`.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Solidity contract / interface / library declarations and
/// collect bare base contract names from `inheritance_specifier`
/// children. Grammar shape (verified):
///
///   `contract A is B, C { … }` →
///     (contract_declaration name: (identifier)
///        (inheritance_specifier ancestor: (user_defined_type (identifier)))
///        (inheritance_specifier ancestor: (user_defined_type (identifier)))
///        body: (contract_body))
///
/// Solidity contracts can list multiple parent contracts (multiple
/// inheritance via C3 linearization). Each parent surfaces as its
/// own `inheritance_specifier` direct child; the `ancestor:` field
/// holds the type name (with optional constructor args we ignore).
fn collect_solidity_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &[
        "contract_declaration",
        "interface_declaration",
        "library_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut child_cursor = class_node.walk();
        for child in class_node.named_children(&mut child_cursor) {
            if child.kind() != "inheritance_specifier" {
                continue;
            }
            // `ancestor:` field → user_defined_type containing
            // `identifier` (or qualified path). Fall back to the
            // specifier itself if the field isn't exposed.
            let ancestor = child.child_by_field_name("ancestor");
            let target = ancestor.unwrap_or(child);
            let raw = node_text(&target, src);
            if let Some(name) = canonical_solidity_base_name(raw) {
                // Dedupe: a contract may list the same parent twice in unusual sources.
                if !bases.iter().any(|existing| existing == &name) {
                    bases.push(name);
                }
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Canonicalize a base-contract reference to a bare type name.
///
/// Strips trailing constructor args (`Base(arg)` → `Base`) and any qualifying
/// path (`pkg.Base` → `Base`) so the result matches downstream resolution.
fn canonical_solidity_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Strip any trailing call-args: `Base(arg)` → `Base`.
    let head_slice = trimmed.split('(').next().unwrap_or(trimmed).trim();
    // Strip any qualifying prefix: `lib.Base` → `Base`.
    let bare = head_slice.rsplit('.').next().unwrap_or(head_slice).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Parse `import_directive` nodes into `ImportSpec`s, one per surfaced symbol.
///
/// Solidity import shapes:
///   `import "X";`                       — source field only
///   `import "X" as Y;`                  — source + module-level alias
///   `import {A, B as BB} from "X";`     — source + repeated `import_name`,
///                                          each carrying its own alias child
///   `import * as Y from "X";`           — source + module-level alias
///                                          (wildcard star not stored)
///
/// tree-sitter-solidity exposes `import_directive` with `source: string`. For
/// the named-import form each `import_name` node has an optional `alias:
/// identifier` child of its own — the module-level `alias` field belongs to
/// the file-level `as` form and must NOT be applied to per-symbol entries.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for import_node in collect_kinds(tree, &["import_directive"]) {
        let Some(source_node) = import_node.child_by_field_name("source") else {
            continue;
        };
        // Strip the surrounding quote characters from the literal source string.
        let module = node_text(&source_node, src)
            .trim_matches(|c: char| matches!(c, '"' | '\''))
            .to_string();
        if module.is_empty() {
            continue;
        }
        // File-level alias from `import "X" as Y;` — only applied when there
        // are no per-symbol entries below.
        let module_alias = import_node
            .child_by_field_name("alias")
            .map(|alias_node| node_text(&alias_node, src).to_string());
        let mut child_cursor = import_node.walk();
        let import_name_nodes: Vec<tree_sitter::Node<'_>> = import_node
            .named_children(&mut child_cursor)
            .filter(|child| child.kind() == "import_name")
            .collect();
        if import_name_nodes.is_empty() {
            imports.push(ImportSpec {
                span: span_of(file, &import_node),
                module,
                alias: module_alias,
                is_wildcard: false,
                original_name: None,
                scope: ImportScope::Module,
            });
        } else {
            for name_node in import_name_nodes {
                // Per-symbol alias is the `import_name`'s own alias child;
                // fall back to scanning named children for older grammars.
                let alias_node = name_node.child_by_field_name("alias").or_else(|| {
                    let mut alias_cursor = name_node.walk();
                    // Use `named_child(0)` rather than `child(0)`:
                    // older grammars expose the unnamed `as` token
                    // as `child(0)`, and skipping the wrong node
                    // would let `find` return the symbol identifier
                    // instead of the alias.
                    let first_named_id = name_node.named_child(0).map(|node| node.id());
                    let found = name_node.named_children(&mut alias_cursor).find(|child| {
                        (child.kind() == "identifier" || child.kind() == "alias")
                            && Some(child.id()) != first_named_id
                    });
                    found
                });
                let symbol_alias = alias_node.map(|alias_node| node_text(&alias_node, src).to_string());
                let original_name = name_node.child_by_field_name("name").map_or_else(
                    || {
                        // Older grammar revisions don't expose a
                        // `name` field; the entire `import_name`
                        // text would include `... as alias`. Strip
                        // the alias suffix so the original name is
                        // just the imported symbol.
                        let raw = node_text(&name_node, src);
                        raw.split(" as ").next().unwrap_or(raw).trim().to_string()
                    },
                    |name_field_node| node_text(&name_field_node, src).to_string(),
                );
                imports.push(ImportSpec {
                    span: span_of(file, &import_node),
                    module: module.clone(),
                    alias: symbol_alias,
                    is_wildcard: false,
                    original_name: Some(original_name),
                    scope: ImportScope::Module,
                });
            }
        }
    }
    imports
}
