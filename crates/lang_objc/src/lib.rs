//! Objective-C language adapter.
//!
//! `.m` files can also legitimately be MATLAB source; the CLI's file
//! detection assigns `.m` to Objective-C by default (same convention
//! `tree-sitter-language-pack` uses). If a project mixes the two, the
//! user can scope `--include` / `--exclude` to disambiguate.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        c_family_preproc_imports, collect_kinds, first_named_child_of_kind, language_from_pack, node_text,
        package_module_segments_with_workspace_prefix, parse_with, span_of,
    },
    AdapterContext, AdapterError, AssignValueKind, DeclIndex, DeclKind, FieldWrite, FlowEvent,
    GrammarHandler, ImportIndex, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath,
    SyntaxSpecialForm, TypeAliasBinding,
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
    // Current tree-sitter-objc emits `block_literal`; keep the older
    // `block_literal_expression` spelling for grammar-version compatibility.
    lambda_kinds: &["block_literal", "block_literal_expression"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &["synchronized_statement", "autoreleasepool_statement"],
    special_forms: &[SyntaxSpecialForm::DirectCallArguments],
    method_receiver_param_index: None,
    implicit_receiver_names: &["self", "super"],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
    void_return_type_names: &[],
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
        // `.h` is shared with C and C++; the database evaluates every
        // candidate grammar against the concrete CST instead of assigning
        // headers by extension alone.
        &["m", "mm", "h"]
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
        bonsai_lang_api::c_family_declaration_macro_recovery_edits(snapshot, vfs, tree)
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
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        apply_objc_class_semantic_identity(&mut decl_index, ctx);
        // The leading `_` on an Objective-C method/selector is an Apple
        // naming convention, not a linkage boundary: selectors dispatch
        // dynamically across files. Marking `_`-prefixed decls
        // Visibility::Private would make the resolver enforce them as
        // strictly file-scoped, dropping every legitimate cross-file
        // flow through a `_`-prefixed helper to zero candidates. Leave
        // visibility at the kit default and let the resolver's name +
        // receiver-type narrowing do the work instead.
        mark_objc_initializer_methods(&mut decl_index);
        let constructor_selectors = decl_index
            .defs
            .iter()
            .filter(|decl| decl.kind == DeclKind::Constructor)
            .map(|decl| decl.name.clone())
            .collect::<std::collections::HashSet<_>>();
        // Per-decl `type_aliases` from typed parameters
        // (`(NSString *)name`, `(HTTPRequest *)req`). Objective-C
        // method signatures and C-style function parameters both
        // carry an explicit type — extract them so
        // `attribute: [NSURL, absoluteString]`-style rules can
        // resolve `req.absoluteString` semantically per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            bonsai_lang_api::kit::inject_c_family_function_pointer_aliases(&mut decl_index, &tree, src, file);
            let aliases_by_span = collect_objc_method_type_aliases(&tree, file, src);
            for decl in &mut decl_index.defs {
                if let Some(aliases) = aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
                {
                    decl.type_aliases = aliases.clone();
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
            let bases_by_class = collect_objc_class_bases(&tree, file, src);
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
                suppress_objc_dynamic_subscript_literal_overwrites(&mut decl.flow_events, &tree, src);
                augment_objc_dictionary_flow_events(&mut decl.flow_events, &tree, src);
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
            enrich_objc_receiver_field_writes(decl);
            // Tag `[[Class alloc] init...]` / `[[Class new] ...]`
            // chains with the constructed class so the engine's
            // receiver-type dispatch recognises the alloc-init
            // pattern without re-implementing the ObjC message-
            // syntax shape.
            tag_objc_alloc_receiver_types(&mut decl.flow_events, &constructor_selectors);
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        // Repair catch-param bindings: the kit's generic extractor
        // returns the first identifier descendant of `@catch
        // (NSException *e)`, which is the type — we want the
        // binding identifier.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            for decl in &mut decl_index.defs {
                fix_objc_catch_params(&mut decl.flow_events, &tree, src);
            }
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`new Foo()` / `Foo()` / `Foo::new()` -> typed receiver) so `recv.method(...)` resolves
        // `receiver_type_in` / `[Type, method]` rules; the constructor heuristic only
        // types PascalCase callees, so language exported-function calls are unaffected.
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
            package_module_segments_with_workspace_prefix(decl_index.file, ctx, [decl.name.clone()]);
        let prefix = segments.join("::");
        decl.module_path = ModulePath::from_segments(segments);
        decl.qualified_name = Some(format!("{prefix}::{}", decl.name));
    }
}

fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    c_family_preproc_imports(tree, src, file)
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
    constructor_selectors: &std::collections::HashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
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
                if let Some(class_name) = class_name {
                    if !receiver_types.iter().any(|existing| existing == &class_name) {
                        receiver_types.push(class_name);
                    }
                    // The nested allocation receiver plus a selector that
                    // resolved to an adapter-declared constructor proves this
                    // is construction syntax. Use those AST/declaration facts
                    // instead of teaching the IDG selector spellings.
                    let selector = name.rsplit('.').next().unwrap_or(name).trim();
                    if constructor_selectors.contains(selector) {
                        *call_kind = bonsai_lang_api::CallKind::Constructor;
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                tag_objc_alloc_receiver_types(then_events, constructor_selectors);
                tag_objc_alloc_receiver_types(else_events, constructor_selectors);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                tag_objc_alloc_receiver_types(body, constructor_selectors);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                tag_objc_alloc_receiver_types(body, constructor_selectors);
                tag_objc_alloc_receiver_types(catch_events, constructor_selectors);
                tag_objc_alloc_receiver_types(finally_events, constructor_selectors);
            }
            _ => {}
        }
    }
}

fn mark_objc_initializer_methods(decl_index: &mut DeclIndex) {
    for decl in &mut decl_index.defs {
        if matches!(decl.kind, DeclKind::Method | DeclKind::Function)
            && (decl.name == "init" || decl.name.starts_with("initWith"))
        {
            decl.kind = DeclKind::Constructor;
        }
    }
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
    let rhs = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("right"))
        .unwrap_or(node);
    first_descendant_of_kind(rhs, "dictionary_literal")
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
        })?
        .trim();
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

/// Repair `catch_param` on ObjC `Try` events. The kit's generic
/// extractor returns the first identifier descendant of `@catch
/// (NSException *e)`, which is the type identifier. Re-extract the
/// binding from the `parameter_declaration` → `declarator`
/// chain.
fn fix_objc_catch_params(events: &mut [bonsai_lang_api::FlowEvent], tree: &Tree, src: &[u8]) {
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
                    if let Some(name) = objc_catch_param_binding(node, src) {
                        *catch_param = Some(name);
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
        // tree-sitter-objc flattens `@catch (T *name)` into a single
        // `type_name` node that contains both the type and the
        // identifier. The trailing identifier descendant is the
        // binding.
        let mut ccur = child.walk();
        for sub in child.named_children(&mut ccur) {
            if !matches!(
                sub.kind(),
                "type_name" | "parameter_list" | "parameter_declaration"
            ) {
                continue;
            }
            // Walk every descendant; the binding is the last
            // identifier (after the type).
            if let Some(text) = last_identifier_text_in_subtree(sub, src) {
                return Some(text);
            }
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

/// Match `[<Class> alloc]` / `[<Class> new]` (with optional
/// surrounding whitespace) and return `Class`. Returns `None` for
/// any other receiver shape so non-constructor message receivers
/// don't get a bogus type.
fn objc_alloc_class_name(receiver: &str) -> Option<String> {
    let trimmed = receiver.trim();
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?.trim();
    let (class, selector) = inner.rsplit_once(char::is_whitespace)?;
    let class = class.trim();
    let selector = selector.trim();
    if !matches!(selector, "alloc" | "new") {
        return None;
    }
    let class = class.split_whitespace().last()?.trim();
    if class.is_empty() {
        return None;
    }
    let first = class.chars().next()?;
    if !(first.is_ascii_uppercase() || first == '_') {
        return None;
    }
    Some(class.to_string())
}

/// Walk Objective-C class / category / interface / implementation
/// nodes and pull bare base type names from the
/// `superclass`/`superclass_reference` field plus any
/// protocol-qualifier identifiers. Both `@interface
/// AuditedRepository : Repository` and `@interface Foo (Cat) :
/// Bar` shapes surface here so super dispatch + protocol
/// conformance both inform the resolver.
fn collect_objc_class_bases(tree: &Tree, file: FileId, src: &[u8]) -> Vec<(Span, String, Vec<String>)> {
    let class_kinds = &[
        "class_interface",
        "class_implementation",
        "category_interface",
        "category_implementation",
    ];
    let mut out: Vec<(Span, String, Vec<String>)> = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let class_name = objc_class_name(class_node, src).unwrap_or_default();
        let mut bases: Vec<String> = Vec::new();
        if let Some(superclass) = class_node
            .child_by_field_name("superclass")
            .or_else(|| class_node.child_by_field_name("superclass_reference"))
            .or_else(|| class_node.child_by_field_name("base"))
        {
            let raw = node_text(&superclass, src).trim().to_string();
            if let Some(name) = canonical_objc_base_name(&raw) {
                if !bases.iter().any(|existing| existing == &name) {
                    bases.push(name);
                }
            }
        }
        // Fallback: a few grammar revisions expose the superclass as
        // a `superclass_reference` named child rather than a field.
        let mut cursor = class_node.walk();
        for child in class_node.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "superclass_reference" | "superclass" | "protocol_reference_list" | "protocol_qualifiers"
            ) {
                let raw = node_text(&child, src).trim().to_string();
                for piece in raw.split(',') {
                    let cleaned = piece
                        .trim()
                        .trim_matches(|c: char| matches!(c, '<' | '>' | ':' | '*'));
                    if let Some(name) = canonical_objc_base_name(cleaned) {
                        if !bases.iter().any(|existing| existing == &name) {
                            bases.push(name);
                        }
                    }
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
        collect_objc_local_type_aliases(fn_node, src, &mut aliases);
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
            "type_identifier"
                | "primitive_type"
                | "sized_type_specifier"
                | "qualified_type_identifier"
                | "generic_type_specifier"
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
