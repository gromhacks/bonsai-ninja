//! Dart language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{
        collect_kinds, first_named_child, first_named_child_of_kind, language_from_pack, node_text,
        parse_with, span_of,
    },
    AdapterContext, AdapterError, AssignValueKind, CallKind, DeclIndex, DeclKind, FieldWrite, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities,
    LanguageId, TypeAliasBinding, Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("dart");
const PACK_NAME: &str = "dart";

// Dart (tree-sitter-dart UserNobody14) handler. Function bodies live in
// a sibling `function_body` of the signature (kit's body fallback finds
// it via the parent chain). Class methods wrap the signature in a
// `method_signature` — we index only the inner signature to avoid
// double-counting. Calls in Dart use the unique split-grammar pattern
// `identifier selector(args)`; the walker has a Dart-specific branch
// that synthesizes a Call event from the previous-sibling identifier.
const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &[
        "function_signature",
        "getter_signature",
        "setter_signature",
        "constructor_signature",
        "factory_constructor_signature",
    ],
    class_kinds: &[
        "class_definition",
        "mixin_declaration",
        "extension_declaration",
        "enum_declaration",
    ],
    method_kinds: &["method_signature"],
    method_context_kinds: &["class_definition", "mixin_declaration", "extension_declaration"],
    constructor_method_kinds: &["constructor_signature", "factory_constructor_signature"],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    if_kinds: &["if_statement"],
    for_kinds: &["for_statement"],
    foreach_kinds: &[],
    while_kinds: &["while_statement"],
    do_kinds: &["do_statement"],
    loop_kinds: &[],
    call_kinds: &[],
    assignment_kinds: &["assignment_expression", "initialized_variable_definition"],
    return_kinds: &["return_statement"],
    throw_kinds: &["throw_expression"],
    lambda_kinds: &["function_expression", "lambda_expression"],
    try_kinds: &["try_statement"],
    catch_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    yield_kinds: &["yield_statement"],
    await_kinds: &["await_expression"],
    defer_kinds: &[],
    using_kinds: &[],
    method_receiver_param_index: None,
    implicit_receiver_names: &["this", "super"],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct DartAdapter;

impl DartAdapter {
    /// Construct a stateless Dart adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for DartAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Dart"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["dart"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        // Dart privacy is name-based: `_`-prefixed identifiers are
        // library-private (Visibility::Module).
        for decl in &mut decl_index.defs {
            if decl.name.starts_with('_') {
                decl.visibility = Visibility::Module;
            }
        }
        // Per-decl `type_aliases` from typed parameters
        // (`String name`, `HttpClient client`). Brings Dart in
        // lockstep with Java/Kotlin/Scala/TS/C#/Swift/Rust/Python so
        // `attribute: [HttpClient, getUrl]`-style rules can resolve
        // `client.getUrl(...)` semantically per
        // docs/contributing/design-patterns.mdx::Semantic Resolution Always.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let source_bytes = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `T foo() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut decl_index, &tree, source_bytes, &HANDLER);
            let aliases_by_span = collect_dart_method_type_aliases(&tree, file, source_bytes);
            for decl in &mut decl_index.defs {
                if let Some(aliases) = aliases_by_span
                    .iter()
                    .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
                {
                    decl.type_aliases = aliases.clone();
                }
            }
            // Per-class `bases`: `class Echo extends WebSocketHandler with M implements I`
            // → ["WebSocketHandler", "M", "I"]. Dart wraps the parent
            // class under `superclass:` (which can also embed a
            // `mixins` sibling carrying `with` clauses) and lists
            // `interfaces:` separately.
            let bases_by_span = collect_dart_class_bases(&tree, file, source_bytes);
            for decl in &mut decl_index.defs {
                if !is_class_like(decl.kind) {
                    continue;
                }
                // Match by exact span first; fall back to name to handle
                // cases where the decl span differs from the class node.
                if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                    (*span == decl.span || name == &decl.name).then_some(bases)
                }) {
                    decl.bases = bases.clone();
                }
            }
            let signature_formals_by_span = collect_dart_signature_formals(&tree, file, source_bytes);
            let expression_returns_by_span = collect_dart_expression_body_returns(&tree, file, source_bytes);
            for decl in &mut decl_index.defs {
                if let Some((params, writes)) = dart_formals_for_decl(decl, &signature_formals_by_span) {
                    if !params.is_empty() {
                        decl.params = params.clone();
                    }
                    if decl.kind == DeclKind::Constructor {
                        decl.receiver_field_writes.extend(writes.clone());
                    }
                }
                if let Some(return_event) = dart_expression_return_for_decl(decl, &expression_returns_by_span)
                {
                    if !decl.flow_events.iter().any(|event| {
                        matches!(
                            (event, return_event),
                            (FlowEvent::Return { span: existing, .. }, FlowEvent::Return { span: added, .. })
                                if existing == added
                        )
                    }) {
                        decl.flow_events.push(return_event.clone());
                        decl.has_implicit_returns = true;
                    }
                }
            }
            // The kit's generic catch-param walk picks Dart's `on Type`
            // identifier over the bound variable in `on E catch (e)`.
            // Recompute `Try::catch_param` from the structural context so
            // the catch body's read of `e` gets G8-seeded.
            for decl in &mut decl_index.defs {
                fix_dart_catch_params(&mut decl.flow_events, &tree, source_bytes);
            }
        }
        // Recognised Dart lifecycle transitions — `close` for streams /
        // sinks / files, `cancel` for stream subscriptions and timers,
        // `dispose` for `ChangeNotifier`/`AnimationController`-style
        // resources whose freed state is observable.
        const DART_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "dispose",
                transition: "freed",
                arg_index: 0,
            },
        ];
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, DART_LIFECYCLE_TRANSITIONS);
        }
        // Mirror the lang_csharp fixes that unblocked the parallel
        // mega_flow: (1) convert a getter / expression-body whose
        // single Return reads a dotted receiver field (`String get
        // cmd => data.cmd`) into a `Call+Return` chain so the call
        // resolves to the receiver-typed member (record accessor /
        // sibling getter) instead of being a single 2-level field
        // read the bridge can't follow; (2) qualify bare reads of a
        // sibling zero-arg member (`final c = cmd;`) into an
        // `Assign{source_call}` plus an explicit `Call` event whose
        // argless walk_call fallback synthesizes a `CallArg{idx=0}`
        // recv-slot so `recv_slots_for_call_span` has something to
        // bridge caller-receiver taint through.
        rewrite_dart_member_access_getters(&mut decl_index);
        qualify_dart_implicit_member_reads(&mut decl_index);
        // Synthesize an implicit Return for ctors with no flow events.
        // `BaseRepository(this.data);` declares but has no body; with
        // no Return, the ConstructorReturn stitch can't connect
        // `new BaseRepository(envelope)`'s allocation target to a
        // tainted return — so `repo` stays whole-object untainted
        // even though `repo.data.cmd` becomes tainted field-precisely.
        // Emit a Return whose value_text is the param-name list; the
        // transfer's identifier tokenization picks up each param so
        // the ctor's CallRet inherits the args' taint at object level.
        // Mirrors the lang_csharp `synthesize_csharp_constructor_
        // implicit_returns` pass.
        synthesize_dart_constructor_implicit_returns(&mut decl_index);
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

/// For each Dart Constructor decl whose `flow_events` is empty,
/// synthesize a `Return` whose `value_text` is the joined param-name
/// list. `bridge_value_expr_to_node` tokenizes that text so each
/// param identifier bridges into `Place::Return`; the standard
/// callee-Return → caller-CallRet inter-procedural edge then carries
/// the ctor's args' taint onto the caller's allocation target,
/// tainting `repo` whole-object even when receiver-field-write
/// extraction missed the param's field-initializing semantics.
fn synthesize_dart_constructor_implicit_returns(index: &mut DeclIndex) {
    for decl in &mut index.defs {
        if !matches!(decl.kind, DeclKind::Constructor) {
            continue;
        }
        if !decl.flow_events.is_empty() {
            continue;
        }
        if decl.params.is_empty() {
            continue;
        }
        let value_text = decl.params.join(" ");
        let span = decl.body_span.unwrap_or(decl.span);
        decl.flow_events.push(FlowEvent::Return {
            span,
            value_text: Some(value_text),
            value_name: None,
        });
    }
}

/// The kit's generic `extract_catch_param` returns the first
/// identifier descendant of the catch arm. For Dart's `on E catch (e)`
/// the arm is an `on_part` whose `type_not_void` (`FormatException`)
/// precedes the nested `catch_clause`, so the generic walk returns the
/// TYPE instead of the bound variable `e` and the catch body's read of
/// `e` is never seeded, dropping exception taint. Recompute
/// `Try::catch_param` from the structural context here — mirrors
/// `collect_java_catch_param_name`. Plain `catch (e)` (no preceding
/// `on` type) is already correct, so we only overwrite when we
/// positively find a binding identifier.
fn fix_dart_catch_params(events: &mut [FlowEvent], tree: &Tree, src: &[u8]) {
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
                    if let Some(name) = dart_catch_param_name(node, src) {
                        *catch_param = Some(name);
                    }
                }
                fix_dart_catch_params(body, tree, src);
                fix_dart_catch_params(catch_events, tree, src);
                fix_dart_catch_params(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                fix_dart_catch_params(then_events, tree, src);
                fix_dart_catch_params(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                fix_dart_catch_params(body, tree, src);
            }
            _ => {}
        }
    }
}

/// Extract the bound exception variable from a Dart `try_statement`.
/// `on E catch (e)` parses as an `on_part` holding a `type_not_void`
/// (the `on` type) followed by a nested `catch_clause`; the binding is
/// the first plain `identifier` of that `catch_clause`. Plain
/// `catch (e)` parses the `catch_clause` as a direct try child. Returns
/// the first such binding in source order, or `None` for parameterless
/// `catch { }` / `on E { }` arms (leaving the kit value untouched).
fn dart_catch_param_name(try_node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = try_node.walk();
    for child in try_node.named_children(&mut cursor) {
        // Descend an `on E catch (e)` arm to its nested catch_clause; a
        // bare `catch (e)` arm is already a catch_clause itself.
        let catch_clause = match child.kind() {
            "catch_clause" => Some(child),
            "on_part" => first_descendant_of_kind(child, "catch_clause"),
            _ => None,
        };
        if let Some(catch_clause) = catch_clause {
            if let Some(name) = dart_catch_clause_binding(catch_clause, src) {
                return Some(name);
            }
        }
    }
    None
}

/// First plain `identifier` child of a `catch_clause` — the bound
/// exception variable. The `on`-clause type lives outside the
/// catch_clause so it is never seen here; the optional second
/// (stack-trace) identifier is ignored since only the primary binding
/// carries the thrown value.
fn dart_catch_clause_binding(catch_clause: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = catch_clause.walk();
    for child in catch_clause.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            return Some(node_text(&child, src).trim().to_string());
        }
    }
    None
}

/// Convert a getter / expression-bodied function whose body is a
/// simple dotted member-access (`String get cmd => data.cmd;`) into a
/// `Call+Return` chain. The IDG's interprocedural receiver-field
/// bridge is 1-level — modeling the body as a single 2-level field
/// read (`Read{name:"data.cmd"}`) never matches the caller's
/// receiver-state composition (`recv.data.cmd`). Modeling it as
/// `Call data.cmd(); Return data.cmd()` lets the call resolve to the
/// receiver-typed member (e.g. a record component accessor) and
/// thread taint through the chain — mirrors the lang_csharp /
/// lang_java patterns and Java's natural `data.cmd()` accessor body.
fn rewrite_dart_member_access_getters(index: &mut DeclIndex) {
    for decl in &mut index.defs {
        if !matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
            continue;
        }
        if !decl.params.is_empty() {
            continue;
        }
        if decl.flow_events.len() != 1 {
            continue;
        }
        let FlowEvent::Return {
            span,
            value_text,
            ..
        } = &decl.flow_events[0]
        else {
            continue;
        };
        let Some(body) = value_text.as_ref() else {
            continue;
        };
        let Some((call_receiver, call_name)) = dart_dotted_member_access_call_parts(body) else {
            continue;
        };
        let body_span = *span;
        decl.flow_events = vec![
            FlowEvent::Call {
                span: body_span,
                name: call_name.clone(),
                receiver: Some(call_receiver),
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            },
            FlowEvent::Return {
                span: body_span,
                value_text: Some(format!("{call_name}()")),
                value_name: None,
            },
        ];
    }
}

/// If `body` is a simple dotted member-access of identifiers
/// (`data.cmd`, optionally `this.X.Y`), return `(receiver, call_name)`.
fn dart_dotted_member_access_call_parts(body: &str) -> Option<(String, String)> {
    let trimmed = body.trim();
    let inner = trimmed
        .strip_prefix("this.")
        .or_else(|| trimmed.strip_prefix("super."))
        .unwrap_or(trimmed);
    let segments: Vec<&str> = inner.split('.').collect();
    if segments.len() < 2 {
        return None;
    }
    for seg in &segments {
        if seg.is_empty()
            || !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || !seg.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            return None;
        }
    }
    let last_dot = inner.rfind('.').unwrap();
    Some((inner[..last_dot].to_string(), inner.to_string()))
}

/// Rewrite a bare read (`final c = cmd;`) of a sibling zero-arg member
/// (getter / property / record accessor) into an `Assign{source_call}`
/// plus an explicit `Call` event so `walk_call`'s argless fallback
/// creates a `CallArg{idx=0}` recv-slot. Without that synthetic slot,
/// `recv_slots_for_call_span` returns nothing and the interprocedural
/// receiver-field bridge can't propagate caller-receiver taint into
/// the getter's body.
fn qualify_dart_implicit_member_reads(index: &mut DeclIndex) {
    use std::collections::HashSet;
    let getter_names: HashSet<String> = index
        .defs
        .iter()
        .filter(|d| matches!(d.kind, DeclKind::Method | DeclKind::Function) && d.params.is_empty() && !d.name.is_empty())
        .map(|d| d.name.clone())
        .collect();
    if getter_names.is_empty() {
        return;
    }
    for decl in &mut index.defs {
        if decl.flow_events.is_empty() {
            continue;
        }
        let mut locals: HashSet<String> = decl.params.iter().cloned().collect();
        collect_dart_assign_targets(&decl.flow_events, &mut locals);
        rewrite_dart_member_reads(&mut decl.flow_events, &getter_names, &locals);
    }
}

/// Walk the flow-event tree and collect every assignment target name
/// — used to mask shadowing locals out of the qualify pass below.
fn collect_dart_assign_targets(events: &[FlowEvent], out: &mut std::collections::HashSet<String>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } => {
                if !target.is_empty() {
                    out.insert(target.trim().to_string());
                }
            }
            // Recurse through nested-vec variants so we don't miss
            // a `final c = cmd;` hidden inside an if/loop/try arm.
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_dart_assign_targets(then_events, out);
                collect_dart_assign_targets(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_dart_assign_targets(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_dart_assign_targets(body, out);
                collect_dart_assign_targets(catch_events, out);
                collect_dart_assign_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

/// Rewrite each bare-getter read (`final c = cmd;`) into a
/// `Call{name:"cmd"} + Assign{source_call:"cmd"}` pair so the
/// interprocedural receiver-field bridge can route caller-receiver
/// taint through the getter. Same pattern as `lang_csharp` — see
/// `qualify_dart_implicit_member_reads` for the full rationale.
fn rewrite_dart_member_reads(
    events: &mut Vec<FlowEvent>,
    getters: &std::collections::HashSet<String>,
    locals: &std::collections::HashSet<String>,
) {
    // Pass 1: recurse first so later insertions can't shift indices
    // the inner walks would have used.
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_dart_member_reads(then_events, getters, locals);
                rewrite_dart_member_reads(else_events, getters, locals);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_dart_member_reads(body, getters, locals);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_dart_member_reads(body, getters, locals);
                rewrite_dart_member_reads(catch_events, getters, locals);
                rewrite_dart_member_reads(finally_events, getters, locals);
            }
            _ => {}
        }
    }
    // Pass 2: walk this level with an explicit index so insertions
    // don't invalidate the loop.
    let mut idx = 0usize;
    while idx < events.len() {
        // Decide qualify-eligibility without holding a mut borrow yet.
        let (qualify_name, span) = match &events[idx] {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                span,
                ..
            } => {
                if source_call.is_some() {
                    // Already converted — skip.
                    (None, *span)
                } else if let Some(name) = source_name.as_deref().map(str::trim).map(str::to_string) {
                    // Only qualify zero-arg-member reads that aren't
                    // shadowed locals and aren't self-assigns.
                    if getters.contains(&name)
                        && !locals.contains(&name)
                        && name != target.trim()
                    {
                        (Some(name), *span)
                    } else {
                        (None, *span)
                    }
                } else {
                    (None, *span)
                }
            }
            _ => {
                idx += 1;
                continue;
            }
        };
        let Some(name) = qualify_name else {
            idx += 1;
            continue;
        };
        // Step A — Assign goes to a `source_call` shape so c gets
        // bridged from the cmd-call's CallRet.
        if let FlowEvent::Assign {
            source_name,
            source_call,
            source_call_args,
            source_names,
            value_kind,
            ..
        } = &mut events[idx]
        {
            *source_call = Some(name.clone());
            *source_call_args = Vec::new();
            *source_name = None;
            source_names.retain(|s| s.trim() != name);
            *value_kind = Some(AssignValueKind::CallResult);
        }
        // Step B — explicit Call event before the Assign; its
        // args-empty fallback synthesizes the recv-slot the bridge
        // needs (mirrors Java's `String c = cmd();` shape).
        events.insert(
            idx,
            FlowEvent::Call {
                span,
                name: name.clone(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: Vec::new(),
            },
        );
        // Skip past both the inserted Call and the modified Assign.
        idx += 2;
    }
}

fn dart_expression_return_for_decl<'a>(
    decl: &bonsai_lang_api::Decl,
    returns_by_span: &'a [(bonsai_common::Span, FlowEvent)],
) -> Option<&'a FlowEvent> {
    returns_by_span
        .iter()
        .find(|(span, _)| span.file == decl.span.file && span.start == decl.span.start)
        .map(|(_, event)| event)
        .or_else(|| {
            returns_by_span
                .iter()
                .find(|(span, _)| {
                    span.file == decl.span.file && span.start <= decl.span.start && decl.span.end <= span.end
                })
                .map(|(_, event)| event)
        })
}

fn dart_formals_for_decl<'a>(
    decl: &bonsai_lang_api::Decl,
    formals_by_span: &'a [(bonsai_common::Span, Vec<String>, Vec<FieldWrite>)],
) -> Option<(&'a Vec<String>, &'a Vec<FieldWrite>)> {
    let same_file = |span: &bonsai_common::Span| span.file == decl.span.file;
    let exact_start = |span: &bonsai_common::Span| same_file(span) && span.start == decl.span.start;
    let contains_decl = |span: &bonsai_common::Span| {
        same_file(span) && span.start <= decl.span.start && decl.span.end <= span.end
    };

    if decl.kind == DeclKind::Constructor {
        if let Some((_, params, writes)) = formals_by_span
            .iter()
            .find(|(span, _, writes)| exact_start(span) && !writes.is_empty())
        {
            return Some((params, writes));
        }
    }
    if let Some((_, params, writes)) = formals_by_span.iter().find(|(span, _, _)| exact_start(span)) {
        return Some((params, writes));
    }

    if decl.kind == DeclKind::Constructor {
        if let Some((_, params, writes)) = formals_by_span
            .iter()
            .find(|(span, _, writes)| contains_decl(span) && !writes.is_empty())
        {
            return Some((params, writes));
        }
    }
    if let Some((_, params, writes)) = formals_by_span.iter().find(|(span, _, _)| contains_decl(span)) {
        return Some((params, writes));
    }

    if decl.kind != DeclKind::Constructor {
        return None;
    }
    formals_by_span
        .iter()
        .find(|(span, params, writes)| {
            same_file(span) && !writes.is_empty() && params.as_slice() == decl.params.as_slice()
        })
        .map(|(_, params, writes)| (params, writes))
}

fn collect_dart_expression_body_returns(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, FlowEvent)> {
    let mut out = Vec::new();
    for signature in collect_kinds(
        tree,
        &[
            "function_signature",
            "getter_signature",
            "setter_signature",
            "method_signature",
            "constructor_signature",
            "factory_constructor_signature",
        ],
    ) {
        let signature = dart_signature_node_for_formals(signature);
        let Some(body) = dart_signature_body_node(signature) else {
            continue;
        };
        if !dart_function_body_is_expression(&body) {
            continue;
        }
        let Some(value_text) = dart_expression_body_text(&body, src) else {
            continue;
        };
        let value_name = first_named_child_of_kind(&body, "identifier")
            .map(|identifier| node_text(&identifier, src).trim().to_string())
            .filter(|name| !name.is_empty());
        out.push((
            span_of(file, &signature),
            FlowEvent::Return {
                span: span_of(file, &body),
                value_text: Some(value_text),
                value_name,
            },
        ));
    }
    out
}

fn dart_signature_body_node(signature: Node<'_>) -> Option<Node<'_>> {
    signature
        .next_named_sibling()
        .filter(|node| node.kind() == "function_body")
        .or_else(|| {
            let parent = signature.parent()?;
            parent
                .next_named_sibling()
                .filter(|node| node.kind() == "function_body")
        })
}

fn dart_function_body_is_expression(body: &Node<'_>) -> bool {
    first_named_child_of_kind(body, "block").is_none()
}

fn dart_expression_body_text(body: &Node<'_>, src: &[u8]) -> Option<String> {
    let text = node_text(body, src).trim();
    let text = text.strip_prefix("=>").unwrap_or(text).trim();
    let text = text.strip_suffix(';').unwrap_or(text).trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn collect_dart_signature_formals(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>, Vec<FieldWrite>)> {
    let mut out = Vec::new();
    for signature in collect_kinds(
        tree,
        &[
            "function_signature",
            "getter_signature",
            "setter_signature",
            "method_signature",
            "constructor_signature",
            "factory_constructor_signature",
        ],
    ) {
        let signature = dart_signature_node_for_formals(signature);
        let Some(params) = first_named_child_of_kind(&signature, "formal_parameter_list") else {
            continue;
        };
        let mut formals = Vec::new();
        collect_dart_constructor_formal_params(params, file, src, &mut formals);
        let param_names = formals
            .iter()
            .map(|formal| formal.name.clone())
            .collect::<Vec<_>>();
        let mut writes = Vec::new();
        for (idx, formal) in formals.iter().enumerate() {
            if let Some(field_span) = formal.field_formal_span {
                writes.push(FieldWrite {
                    span: field_span,
                    target: format!("this.{}", formal.name),
                    source_param_indices: vec![idx],
                });
            }
        }
        if !param_names.is_empty() || !writes.is_empty() {
            out.push((span_of(file, &signature), param_names, writes));
        }
    }
    out
}

fn dart_signature_node_for_formals(signature: Node<'_>) -> Node<'_> {
    if signature.kind() == "method_signature" {
        if let Some(inner) = first_named_child_of_kind(&signature, "function_signature") {
            return inner;
        }
    }
    if signature.kind() == "declaration" {
        if let Some(inner) = first_named_child(&signature) {
            if matches!(
                inner.kind(),
                "function_signature"
                    | "getter_signature"
                    | "setter_signature"
                    | "method_signature"
                    | "constructor_signature"
                    | "factory_constructor_signature"
            ) {
                return dart_signature_node_for_formals(inner);
            }
        }
    }
    signature
}

struct DartConstructorFormal {
    name: String,
    field_formal_span: Option<bonsai_common::Span>,
}

fn collect_dart_constructor_formal_params(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<DartConstructorFormal>,
) {
    if matches!(
        node.kind(),
        "formal_parameter"
            | "normal_formal_parameter"
            | "simple_formal_parameter"
            | "default_formal_parameter"
            | "default_named_parameter"
    ) {
        if let Some(formal) = dart_constructor_formal(node, file, src) {
            out.push(formal);
            return;
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_dart_constructor_formal_params(child, file, src, out);
    }
}

fn dart_constructor_formal(
    parameter_node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<DartConstructorFormal> {
    if let Some(field_formal) = first_descendant_of_kind(parameter_node, "constructor_param") {
        let field_name = first_named_child_of_kind(&field_formal, "identifier")
            .map(|identifier| node_text(&identifier, src).trim().to_string())
            .filter(|field_name| !field_name.is_empty())?;
        return Some(DartConstructorFormal {
            name: field_name,
            field_formal_span: Some(span_of(file, &field_formal)),
        });
    }
    let name = dart_parameter_binding_name(parameter_node, src)?;
    Some(DartConstructorFormal {
        name,
        field_formal_span: None,
    })
}

fn dart_parameter_binding_name(parameter_node: Node<'_>, src: &[u8]) -> Option<String> {
    if let Some(name_node) = parameter_node.child_by_field_name("name") {
        let name = node_text(&name_node, src).trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    let mut last_identifier: Option<Node<'_>> = None;
    let mut cursor = parameter_node.walk();
    for child in parameter_node.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            last_identifier = Some(child);
        }
    }
    last_identifier
        .map(|identifier| node_text(&identifier, src).trim().to_string())
        .filter(|name| !name.is_empty())
}

fn first_descendant_of_kind<'tree>(
    node: tree_sitter::Node<'tree>,
    kind: &str,
) -> Option<tree_sitter::Node<'tree>> {
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

/// Extract Dart `import` directives into the canonical `ImportSpec` shape
/// used by the matcher index.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Dart's `import 'pkg:foo/bar.dart' as x show A, B;` parses as
    //   import_or_export
    //     library_import
    //       import_specification
    //         configurable_uri > uri > string_literal "'pkg:...'"
    //         identifier "x"               <- alias (optional)
    for import_node in collect_kinds(tree, &["import_or_export"]) {
        let Some(import_spec) = first_named_child_of_kind(&import_node, "library_import")
            .and_then(|library_import| first_named_child_of_kind(&library_import, "import_specification"))
        else {
            continue;
        };
        let Some(uri_node) = first_named_child_of_kind(&import_spec, "configurable_uri")
            .and_then(|configurable_uri| first_named_child_of_kind(&configurable_uri, "uri"))
            .and_then(|uri| first_named_child_of_kind(&uri, "string_literal"))
        else {
            continue;
        };
        // Dart import URIs come in three flavours:
        //   1. `package:foo/foo.dart` — pub package; canonical name is `foo`.
        //   2. `dart:io` — core library; canonical name is `dart:io`.
        //   3. `relative.dart` — local file; pass through unchanged.
        // Strip the `package:` prefix so the matcher's import-index
        // sees the package name (`foo/foo.dart` → first-segment
        // `foo`) instead of being shadowed by the `package:` scheme.
        // Without this strip, `pkg::import_matches_package(needle="foo",
        // module="package:foo/foo.dart")` is false (no prefix match
        // against the leading `package:` literal).
        let raw_uri = node_text(&uri_node, src).trim_matches(|ch: char| matches!(ch, '\'' | '"'));
        let module = raw_uri.strip_prefix("package:").unwrap_or(raw_uri).to_string();
        // The optional `as x` alias appears as the first identifier
        // child of the import specification.
        let mut spec_cursor = import_spec.walk();
        let alias = import_spec
            .named_children(&mut spec_cursor)
            .find(|child| child.kind() == "identifier")
            .map(|alias_node| node_text(&alias_node, src).to_string());
        // Dart's `show A, B` combinators bind specific symbols from
        // the imported library to the file scope. Each becomes its own
        // member-style ImportSpec so the rule matcher can chase
        // `A` / `B` back through the alias map to the package.
        let mut combinator_names: Vec<String> = Vec::new();
        let mut combinator_cursor = import_spec.walk();
        for child in import_spec.named_children(&mut combinator_cursor) {
            if child.kind() != "combinator" {
                continue;
            }
            // `show` and `hide` both appear as `combinator` nodes;
            // only `show` introduces a binding (hide *removes* names),
            // so skip non-`show` keywords. Match on the first
            // whitespace-delimited token to avoid catching identifiers
            // that incidentally start with `show` characters.
            let combinator_text = node_text(&child, src);
            if combinator_text.split_whitespace().next() != Some("show") {
                continue;
            }
            let mut child_cursor = child.walk();
            for ident in child.named_children(&mut child_cursor) {
                if ident.kind() == "identifier" {
                    let name = node_text(&ident, src).to_string();
                    if !name.is_empty() {
                        combinator_names.push(name);
                    }
                }
            }
        }
        let exposes_unqualified_library = alias.is_none() && combinator_names.is_empty();
        imports.push(ImportSpec {
            span: span_of(file, &import_node),
            module: module.clone(),
            alias,
            is_wildcard: exposes_unqualified_library,
            original_name: None,
            scope: ImportScope::Module,
        });
        for name in combinator_names {
            imports.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module.clone(),
                alias: None,
                is_wildcard: false,
                original_name: Some(name),
                scope: ImportScope::Module,
            });
        }
    }
    imports
}

/// Walk every Dart function/method body once and record the
/// parameter type-alias bindings. Tree-sitter-dart names function
/// declarations as `function_signature` / `getter_signature` /
/// `setter_signature` / `method_signature` and class constructors
/// as `constructor_signature`; each carries a `formal_parameter_list`
/// with `formal_parameter` / `normal_formal_parameter` /
/// `simple_formal_parameter` children.
fn collect_dart_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut aliases_per_signature = Vec::new();
    for signature_node in collect_kinds(
        tree,
        &[
            "function_signature",
            "getter_signature",
            "setter_signature",
            "method_signature",
            "constructor_signature",
            "factory_constructor_signature",
        ],
    ) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut signature_cursor = signature_node.walk();
        for child in signature_node.named_children(&mut signature_cursor) {
            if child.kind() == "formal_parameter_list" {
                collect_dart_parameter_aliases(child, src, &mut aliases);
            }
        }
        dedup_dart_type_aliases(&mut aliases);
        if !aliases.is_empty() {
            aliases_per_signature.push((span_of(file, &signature_node), aliases));
        }
    }
    aliases_per_signature
}

/// Recurse through a Dart `formal_parameter_list` and emit a type-alias
/// binding for each typed parameter we can identify.
fn collect_dart_parameter_aliases(
    parameter_list_node: Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    let mut cursor = parameter_list_node.walk();
    for child in parameter_list_node.named_children(&mut cursor) {
        match child.kind() {
            "formal_parameter"
            | "normal_formal_parameter"
            | "simple_formal_parameter"
            | "default_formal_parameter"
            | "default_named_parameter" => {
                dart_typed_parameter_alias(child, src, aliases);
            }
            // Recurse for grouped parameter lists (`{a, b}`, `[a, b]`).
            _ => collect_dart_parameter_aliases(child, src, aliases),
        }
    }
}

/// Pull the `(binding, declared type)` pair out of a single Dart formal
/// parameter node. Best-effort: many parameter shapes lack a `type`
/// field, in which case we scan unnamed children.
fn dart_typed_parameter_alias(parameter_node: Node<'_>, src: &[u8], aliases: &mut Vec<TypeAliasBinding>) {
    // tree-sitter-dart's `formal_parameter` exposes the binding
    // identifier under the `name` field but the type is an
    // unnamed `type_identifier` / `type` child preceding the
    // identifier. `simple_formal_parameter` may not expose `name`
    // as a field at all — fall back to scanning named children
    // for an identifier-like leaf.
    let binding_name = if let Some(name_node) = parameter_node.child_by_field_name("name") {
        node_text(&name_node, src).trim().to_string()
    } else {
        let mut last_identifier: Option<Node<'_>> = None;
        let mut param_cursor = parameter_node.walk();
        for child in parameter_node.named_children(&mut param_cursor) {
            if child.kind() == "identifier" {
                last_identifier = Some(child);
            }
        }
        match last_identifier {
            Some(identifier_node) => node_text(&identifier_node, src).trim().to_string(),
            None => return,
        }
    };
    if binding_name.is_empty() {
        return;
    }
    // Preferred path: parameter exposes `type:` field directly.
    if let Some(type_node) = parameter_node.child_by_field_name("type") {
        if let Some(canonical) = canonical_dart_type_name(node_text(&type_node, src)) {
            push_dart_type_alias(aliases, &binding_name, &canonical);
        }
        return;
    }
    // Fallback path: type is an unnamed child (`type_identifier`,
    // `type`, `function_type`, `type_name`). Pick the first match.
    let mut param_cursor = parameter_node.walk();
    for child in parameter_node.named_children(&mut param_cursor) {
        if matches!(
            child.kind(),
            "type_identifier" | "type" | "function_type" | "type_name"
        ) {
            if let Some(canonical) = canonical_dart_type_name(node_text(&child, src)) {
                push_dart_type_alias(aliases, &binding_name, &canonical);
                return;
            }
        }
    }
}

/// Strip generics / nullable markers / function-type tail down to
/// the leftmost type identifier. `List<String>` → `List`,
/// `String?` → `String`, `Future<HttpClient>` → `Future`.
fn canonical_dart_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('?').trim();
    // Drop generics: keep everything up to the first `<`.
    let without_generics = trimmed.split('<').next().unwrap_or(trimmed).trim();
    // Drop module prefixes: `prefix.Type` → `Type`.
    let bare = without_generics
        .rsplit('.')
        .next()
        .unwrap_or(without_generics)
        .trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Append a `(name, type_name)` alias unless either side is empty or
/// they collapse to the same identifier (which would be a no-op alias).
fn push_dart_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    if name.is_empty() || type_name.is_empty() || name == type_name {
        return;
    }
    aliases.push(TypeAliasBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
    });
}

/// Drop duplicate `(name, type_name)` pairs in place, preserving order.
fn dedup_dart_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut seen = std::collections::HashSet::new();
    aliases.retain(|alias| seen.insert((alias.name.clone(), alias.type_name.clone())));
}

/// `true` when `kind` is a Dart class-shaped declaration eligible for
/// `bases:` enrichment (extends / implements / mixins).
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Dart class / mixin / extension definitions and collect bare
/// base type names. Grammar shape (verified):
///
///   `class Echo extends WebSocketHandler with M1 implements I1`
///     → (class_definition name: (identifier)
///          superclass: (superclass (type_identifier)
///                                  (mixins (type_identifier)))
///          interfaces: (interfaces (type_identifier)))
///
/// The `superclass:` field wraps the `extends` parent and any
/// `with` mixins. `interfaces:` carries `implements` types.
/// Generic / qualified bases collapse to the bare tail.
fn collect_dart_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_per_class = Vec::new();
    let class_kinds = &["class_definition", "mixin_declaration", "extension_declaration"];
    for class_node in collect_kinds(tree, class_kinds) {
        // Prefer the named `name:` field; older grammars expose only an
        // unnamed `identifier` child.
        let Some(name_node) = class_node
            .child_by_field_name("name")
            .or_else(|| first_named_child_of_kind(&class_node, "identifier"))
        else {
            continue;
        };
        let class_name = node_text(&name_node, src).trim();
        if class_name.is_empty() {
            continue;
        }
        let mut bases: Vec<String> = Vec::new();
        // `superclass:` carries `extends` plus any embedded `with` mixins.
        if let Some(superclass_node) = class_node.child_by_field_name("superclass") {
            collect_dart_base_names(superclass_node, src, &mut bases);
        }
        // `interfaces:` carries `implements` types.
        if let Some(interfaces_node) = class_node.child_by_field_name("interfaces") {
            collect_dart_base_names(interfaces_node, src, &mut bases);
        }
        if !bases.is_empty() {
            bases_per_class.push((span_of(file, &class_node), class_name.to_string(), bases));
        }
    }
    bases_per_class
}

/// Walk a Dart parent-clause wrapper (`superclass`, `interfaces`,
/// `mixins`) and pick out every type identifier. Skip
/// `type_arguments` so generic params (e.g. `<String, int>`) don't
/// leak into the bases list.
fn collect_dart_base_names(parent_clause: Node<'_>, src: &[u8], bases: &mut Vec<String>) {
    let mut stack = vec![parent_clause];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "type_arguments" => {
                // Skip generics — these are type params of the base,
                // not bases of their own.
                continue;
            }
            "type_identifier" => {
                if let Some(name) = canonical_dart_type_name(node_text(&node, src)) {
                    // De-dup: a class can list the same name twice via
                    // mixins + implements clauses.
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
    }
}
