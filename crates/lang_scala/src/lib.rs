//! Scala language adapter.
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{
        call_arg_from_node_with_handler, call_arg_from_nodes_with_handler, collect_kinds,
        collect_receiver_field_writes, first_named_child_of_kind, language_from_pack,
        looks_like_bare_identifier, node_at_span, node_text, normalize_call_name_whitespace,
        package_module_segments_with_workspace_prefix, parse_with, span_of, walk_flow_events,
    },
    AdapterContext, AdapterError, CallArg, CallKind, Decl, DeclIndex, DeclKind, FieldWrite, FlowEvent,
    GrammarHandler, ImplicitMemberReadCall, ImportIndex, ImportScope, ImportSpec, LanguageAdapter,
    LanguageCapabilities, LanguageId, TypeAliasBinding, TypeAliasVocabulary, Visibility, EMPTY_HANDLER,
};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

const SCALA_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &["function_definition", "function_declaration"],
    // `val_definition` / `var_definition` capture typed locals
    // (`val c: Foo = make()`) so cast / factory-typed receivers resolve
    // `receiver_type_in`; the binding name sits in the `pattern` field.
    param_kinds: &["parameter", "class_parameter", "val_definition", "var_definition"],
    name_field: "name",
    type_field: "type",
};

const SCALA_DECL_KINDS: &[&str] = &[
    "function_definition",
    "function_declaration",
    "class_definition",
    "object_definition",
    "trait_definition",
    "type_definition",
    "val_definition",
    "var_definition",
];
use tree_sitter::{Language, Tree};
// (`Node` brought into scope above so class-scoped helpers can pass nodes around.)

pub const LANG_ID: LanguageId = LanguageId::new("scala");
const PACK_NAME: &str = "scala";

fn extract_scala_syntax_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() != "throw_expression" {
        return None;
    }
    let value = node.named_child(0)?;
    let flow = bonsai_lang_api::kit::expression_flow_from_node_with_handler(value, file, src, handler);
    let value_name = {
        let mut sources = bonsai_lang_api::kit::expression_operand_names_with_handler(&value, src, handler);
        sources.extend(flow.source_names);
        sources.sort();
        sources.dedup();
        if sources.len() == 1 {
            Some(sources.remove(0))
        } else if sources.is_empty() {
            flow.place
        } else {
            None
        }
    };
    Some(FlowEvent::Throw {
        span: span_of(file, &node),
        value_name,
        thrown_type: None,
    })
}

const HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &["function_definition", "function_declaration"],
    class_kinds: &[
        "class_definition",
        "object_definition",
        "trait_definition",
        "enum_definition",
    ],
    class_decl_kinds: &[
        ("class_definition", DeclKind::Class),
        ("object_definition", DeclKind::Class),
        ("trait_definition", DeclKind::Trait),
        ("enum_definition", DeclKind::Enum),
    ],
    method_context_kinds: &[
        "class_definition",
        "object_definition",
        "trait_definition",
        "enum_definition",
    ],
    if_kinds: &["if_expression", "match_expression"],
    for_kinds: &["for_expression"],
    while_kinds: &["while_expression"],
    call_kinds: &["call_expression", "generic_function", "instance_expression"],
    pseudo_call_extractor: Some(extract_scala_pseudo_call),
    syntax_event_extractor: Some(extract_scala_syntax_event),
    pseudo_call_receiver_extractor: Some(extract_scala_pseudo_call_receiver),
    argument_passing_mode_extractor: None,
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    call_ref_kinds: &["call_expression", "generic_function", "instance_expression"],
    member_expression_kinds: &["field_expression"],
    assignment_kinds: &[
        "assignment_expression",
        "val_definition",
        "var_definition",
        "var_declaration",
    ],
    return_kinds: &["return_expression"],
    throw_kinds: &[],
    lambda_kinds: &["lambda_expression"],
    try_kinds: &["try_expression"],
    catch_kinds: &["catch_clause"],
    finally_kinds: &["finally_clause"],
    // Scala block-bodied `def f() = { …; tailExpr }` returns its tail
    // expression. The body node kind is `block` (never descended by
    // implicit-return synthesis), so — like Rust and Ruby — the tail
    // Return is emitted by the tail-expression path. Without this the
    // dominant Scala function shape emits NO Return, breaking
    // interprocedural return-taint. Expression-bodied `def f = expr`
    // keeps its existing direct-body Return (the caller prefers that
    // path and both emitters dedupe on span).
    tail_expression_returns: true,
    // A `def f(...): Unit = { …; log(x) }` returns no value; its tail is a
    // side-effecting call that consumes `x`, not one that returns it.
    // Suppress the synthetic tail Return so the argument isn't tokenised
    // into an over-tainted return that leaks to the caller.
    void_return_type_names: &["Unit"],
    implicit_receiver_names: &["this", "super"],
    ..EMPTY_HANDLER
};

fn extract_scala_pseudo_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if node.kind() == "field_expression" && scala_postfix_operator_call(node) {
        let receiver = node
            .child_by_field_name("value")
            .or_else(|| node.named_child(0))?;
        let name = normalize_call_name_whitespace(node_text(&node, src));
        return (!name.is_empty()).then(|| FlowEvent::Call {
            span: span_of(file, &node),
            receiver: Some(normalize_call_name_whitespace(node_text(&receiver, src))),
            receiver_types: Vec::new(),
            name,
            call_kind: CallKind::Method,
            args: Vec::new(),
        });
    }
    if node.kind() != "infix_expression" {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let operator = node.child_by_field_name("operator")?;
    let name = node_text(&operator, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let mut args = Vec::new();
    let (receiver, call_kind) = if looks_like_bare_identifier(&name) {
        args.push(call_arg_from_node_with_handler(right, file, src, None, handler)?);
        (
            Some(normalize_call_name_whitespace(node_text(&left, src))),
            CallKind::Method,
        )
    } else {
        args.push(call_arg_from_node_with_handler(left, file, src, None, handler)?);
        args.push(call_arg_from_node_with_handler(right, file, src, None, handler)?);
        (None, CallKind::Operator)
    };
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver,
        receiver_types: Vec::new(),
        name,
        call_kind,
        args,
    })
}

fn scala_postfix_operator_call(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    let is_postfix = node
        .named_children(&mut cursor)
        .any(|child| child.kind() == "operator_identifier");
    is_postfix
}

fn extract_scala_pseudo_call_receiver<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    match node.kind() {
        "field_expression" if scala_postfix_operator_call(node) => {
            node.child_by_field_name("value").or_else(|| node.named_child(0))
        }
        "infix_expression" => {
            let operator = node.child_by_field_name("operator")?;
            looks_like_bare_identifier(node_text(&operator, src).trim())
                .then(|| node.child_by_field_name("left"))
                .flatten()
        }
        _ => None,
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct ScalaAdapter;

impl ScalaAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ScalaAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Scala"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["scala", "sc"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Pattern matching: the adapter post-processes flat `Branch`
        // events emitted for `match_expression`s into nested `Branch`
        // chains so the engine forks state per arm. Each arm's body
        // sees a fresh copy of the pre-match taint state, runs in
        // isolation, and unions back at the merge — yielding
        // path-disjoint precision instead of the over-approximate
        // "any arm's taint reaches every other arm's body."
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["Any", "AnyRef", "Object"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            pattern_matching: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            receiver_type_syntax: bonsai_lang_api::ReceiverTypeSyntax {
                wrapper_calls: &[],
                class_object_suffixes: &[".class"],
            },
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `def f(): T = ...` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            let arm_spans = collect_scala_match_arm_spans(&tree, src, file);
            for decl in &mut idx.defs {
                bonsai_lang_api::kit::split_match_arms_in_branch_events(&mut decl.flow_events, &arm_spans);
                annotate_scala_named_call_args(&mut decl.flow_events, tree.root_node(), file, src);
            }
        }
        let pkg_segments = parse_with(PACK_NAME, file, ctx)
            .and_then(|(snapshot, tree)| extract_scala_package(tree.root_node(), snapshot.text.as_bytes()));
        if let Some(segments) = pkg_segments {
            let segments = package_module_segments_with_workspace_prefix(file, ctx, segments);
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_scala_visibility(tree.root_node(), file, src);
            let alias_map = collect_param_type_aliases(&tree, file, src, &SCALA_TYPE_ALIASES);
            let method_owners = collect_scala_method_owners(&tree, file);
            let class_symbols: Vec<(Span, SymbolId)> = idx
                .defs
                .iter()
                .filter(|decl| is_class_like(decl.kind))
                .map(|decl| (decl.span, decl.symbol))
                .collect();
            // Class-level field type bindings — `private val
            // authService = new AuthService()` makes
            // `authService: AuthService` visible inside every method
            // of the enclosing class. Without this, the engine cannot
            // dispatch `authService.runAdminCommand(...)` to the real
            // `AuthService` decl.
            let class_field_aliases = collect_scala_class_field_aliases(&tree, file, src);
            // WS2: method-local `val c = make().asInstanceOf[Foo]` casts,
            // keyed by the enclosing method span (the class-field walk
            // skips method bodies, and the kit vocabulary only types
            // explicitly-annotated locals).
            let local_cast_aliases = collect_scala_local_cast_aliases(&tree, file, src);
            synthesize_scala_constructor_decls(&mut idx, file, &tree, src);
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                let mut aliases = alias_map.get(&decl.span).cloned().unwrap_or_default();
                if let Some(casts) = local_cast_aliases
                    .iter()
                    .find_map(|(span, list)| (*span == decl.span).then_some(list))
                {
                    for alias in casts {
                        if !aliases.contains(alias) {
                            aliases.push(alias.clone());
                        }
                    }
                }
                if let Some((_, owner_span, owner_kind)) =
                    method_owners.iter().find(|(span, _, _)| *span == decl.span)
                {
                    if let Some((_, owner_symbol)) = class_symbols.iter().find(|(span, _)| span == owner_span)
                    {
                        decl.parent = Some(*owner_symbol);
                        decl.kind = DeclKind::Method;
                        if *owner_kind != "object_definition" && decl.implicit_receiver_names.is_empty() {
                            decl.implicit_receiver_names = vec!["this".to_string(), "super".to_string()];
                        }
                    }
                    if let Some(field_aliases) = class_field_aliases
                        .iter()
                        .find_map(|(span, list)| (*span == *owner_span).then_some(list))
                    {
                        for alias in field_aliases {
                            if !aliases.contains(alias) {
                                aliases.push(alias.clone());
                            }
                        }
                    }
                }
                if !aliases.is_empty() {
                    decl.type_aliases = aliases;
                }
            }
            // Per-class `bases`: `class C extends Base with Mixin` →
            // ["Base", "Mixin"]. Scala wraps every parent (extends +
            // with) under a single `extends_clause` whose `type:`
            // fields list each parent.
            let bases_by_span = collect_scala_class_bases(&tree, file, src);
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
        }
        // Recognised Scala lifecycle transitions — same call names as
        // Java since the JVM library surface is shared.
        const SCALA_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "shutdown",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "unlock",
                transition: "unlocked",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "release",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "dispose",
                transition: "freed",
                arg_index: 0,
            },
        ];
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, SCALA_LIFECYCLE_TRANSITIONS);
        }
        // Mirror the lang_csharp / lang_dart synthesis passes: convert a method
        // body that's a simple dotted receiver field read
        // (`def cmd: String = data.cmd`) into a `Call+Return` chain
        // (lets the 1-level receiver-field bridge resolve it through
        // a record/case-class component accessor instead of staying
        // as a 2-level field read); qualify bare reads of sibling
        // zero-arg members (`val c = cmd`) by inserting an explicit
        // `Call` event so `walk_call`'s args-empty fallback creates
        // a `CallArg{idx=0}` recv-slot for the receiver bridge.
        rewrite_scala_member_access_accessors(&mut idx);
        qualify_scala_implicit_member_reads(&mut idx);
        // Synthesize case-class component accessors. Scala
        // `case class Envelope(kind, cmd, user, length, extras)` —
        // tree-sitter node `class_definition` with `case_class_*`
        // modifiers — produces no per-component accessor decl, so
        // `envelope.cmd` field-projection never connects to a Method
        // body. Mirror the Java/C# record synthesis: one zero-arg
        // `Method` per class_parameter whose `Return` is `this.<param>`.
        synthesize_scala_case_class_accessors(&mut idx, file, ctx);
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`val c = new Foo()`
        // / `Foo()` → `c: Foo`) so `c.method(...)` carries a resolved
        // receiver type for `receiver_type_in` / `[Type, method]` rules.
        // Scala class names are PascalCase; the heuristic is reliable.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        // Scala adds constructor-property aliases and rewrites property
        // selections after the generic declaration pass. Re-run the shared
        // AST/type-fact projection once those facts exist so synthesized
        // `data.cmd` calls carry `data: Envelope` and resolve the case-class
        // accessor without any member-name inventory.
        bonsai_lang_api::apply_call_receiver_types_with_super_tokens(&mut idx, &["super"]);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

#[derive(Clone, Debug)]
struct ScalaBaseConstructorCall {
    base_name: String,
    args: Vec<String>,
    event: FlowEvent,
}

#[derive(Clone, Debug)]
struct ScalaConstructorDraft {
    class_span: Span,
    class_symbol: SymbolId,
    class_name: String,
    class_name_span: Span,
    module_path: bonsai_lang_api::ModulePath,
    body_span: Span,
    params: Vec<String>,
    flow_events: Vec<FlowEvent>,
    direct_receiver_field_writes: Vec<FieldWrite>,
    base_call: Option<ScalaBaseConstructorCall>,
}

fn synthesize_scala_constructor_decls(idx: &mut DeclIndex, file: FileId, tree: &Tree, src: &[u8]) {
    let class_names = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| decl.name.clone())
        .collect::<Vec<_>>();
    let classes = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| {
            (
                decl.span,
                decl.symbol,
                decl.name.clone(),
                decl.name_span,
                decl.module_path.clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut next = idx
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    let mut drafts = Vec::new();
    for class_node in collect_kinds(tree, &["class_definition"]) {
        let class_span = span_of(file, &class_node);
        let Some((_, class_symbol, class_name, class_name_span, module_path)) =
            classes.iter().find(|(span, _, _, _, _)| *span == class_span)
        else {
            continue;
        };
        // Case classes (`case class Envelope(...)`) and other
        // parameterised classes without an explicit body block still
        // declare a primary constructor whose `class_parameters`
        // become field-initializing writes — so don't skip when
        // `template_body` is absent. Body-less ctors get an empty
        // `flow_events` vec but real `receiver_field_writes` from
        // the param list, which is what drives the IDG's
        // `ConstructorReturnStitch` field-projection onto the
        // caller's allocation target.
        let body = first_named_child_of_kind(&class_node, "template_body");
        let flow_events = body
            .map(|b| walk_flow_events(b, file, src, &HANDLER, &class_names))
            .unwrap_or_default();
        let body_span = body.map_or(class_span, |b| span_of(file, &b));
        let class_params = first_named_child_of_kind(&class_node, "class_parameters");
        let params = class_params.map_or_else(Vec::new, |params| constructor_param_names(params, src));
        let is_case = scala_class_is_case(class_node, src);
        let mut receiver_field_writes = class_params.map_or_else(Vec::new, |params_node| {
            scala_constructor_param_field_writes_with_mode(params_node, file, src, &params, is_case)
        });
        let mut body_writes =
            collect_receiver_field_writes(&flow_events, &params, None, &["this", "super"], &[]);
        receiver_field_writes.append(&mut body_writes);
        let base_call = scala_primary_base_constructor_call(class_node, file, src);
        let mut constructor_flow_events = Vec::new();
        if let Some(call) = &base_call {
            constructor_flow_events.push(call.event.clone());
        }
        constructor_flow_events.extend(flow_events);
        drafts.push(ScalaConstructorDraft {
            class_span,
            class_symbol: *class_symbol,
            class_name: class_name.clone(),
            class_name_span: *class_name_span,
            module_path: module_path.clone(),
            body_span,
            params,
            flow_events: constructor_flow_events,
            direct_receiver_field_writes: receiver_field_writes,
            base_call,
        });
    }

    let mut draft_by_name = HashMap::new();
    for (idx, draft) in drafts.iter().enumerate() {
        draft_by_name.insert(draft.class_name.clone(), idx);
    }
    let mut memo: HashMap<String, Vec<FieldWrite>> = HashMap::new();
    let mut visiting: HashSet<String> = HashSet::new();
    for draft in &drafts {
        let receiver_field_writes = scala_constructor_receiver_field_writes(
            &draft.class_name,
            &drafts,
            &draft_by_name,
            &mut memo,
            &mut visiting,
        );
        if draft.flow_events.is_empty() && receiver_field_writes.is_empty() {
            continue;
        }
        idx.defs.push(scala_constructor_decl(
            bonsai_common::SymbolId::new(next),
            draft.class_symbol,
            &draft.class_name,
            draft.class_name_span,
            draft.class_span,
            draft.body_span,
            draft.params.clone(),
            draft.flow_events.clone(),
            receiver_field_writes,
            draft.module_path.clone(),
        ));
        next = next.saturating_add(1);
    }
}

fn scala_constructor_receiver_field_writes(
    class_name: &str,
    drafts: &[ScalaConstructorDraft],
    draft_by_name: &HashMap<String, usize>,
    memo: &mut HashMap<String, Vec<FieldWrite>>,
    visiting: &mut HashSet<String>,
) -> Vec<FieldWrite> {
    if let Some(cached) = memo.get(class_name) {
        return cached.clone();
    }
    let Some(&idx) = draft_by_name.get(class_name) else {
        return Vec::new();
    };
    if !visiting.insert(class_name.to_string()) {
        return Vec::new();
    }
    let draft = &drafts[idx];
    let mut writes = draft.direct_receiver_field_writes.clone();
    if let Some(base_call) = &draft.base_call {
        if base_call.base_name != draft.class_name {
            let base_writes = scala_constructor_receiver_field_writes(
                &base_call.base_name,
                drafts,
                draft_by_name,
                memo,
                visiting,
            );
            for write in base_writes {
                let Some(source_param_indices) =
                    remap_constructor_field_write_sources(&write, &base_call.args, &draft.params)
                else {
                    continue;
                };
                writes.push(FieldWrite {
                    span: write.span,
                    target: write.target,
                    source_param_indices,
                });
            }
        }
    }
    writes.sort_by_key(|write| {
        (
            write.span.file.raw(),
            write.span.start,
            write.target.clone(),
            write.source_param_indices.clone(),
        )
    });
    writes.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
    memo.insert(class_name.to_string(), writes.clone());
    visiting.remove(class_name);
    writes
}

fn remap_constructor_field_write_sources(
    write: &FieldWrite,
    base_args: &[String],
    subclass_params: &[String],
) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    for source_idx in &write.source_param_indices {
        let arg = base_args.get(*source_idx)?.trim();
        if arg.is_empty() {
            return None;
        }
        let subclass_idx = subclass_params.iter().position(|param| param == arg)?;
        out.push(subclass_idx);
    }
    Some(out)
}

fn scala_primary_base_constructor_call(
    class_node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<ScalaBaseConstructorCall> {
    let extend = class_node.child_by_field_name("extend")?;
    let mut cursor = extend.walk();
    let mut base_node = None;
    let mut args_node = None;
    for child in extend.named_children(&mut cursor) {
        if base_node.is_none() {
            let raw = node_text(&child, src);
            if canonical_scala_base_name(raw).is_some() {
                base_node = Some(child);
            }
            continue;
        }
        if child.kind() == "arguments" {
            args_node = Some(child);
        }
        break;
    }
    let base_node = base_node?;
    let base_name = canonical_scala_base_name(node_text(&base_node, src))?;
    let args = args_node.map_or_else(Vec::new, |node| scala_constructor_argument_texts(node, src));
    let event_args = args_node.map_or_else(Vec::new, |node| scala_constructor_call_args(node, file, src));
    let event = FlowEvent::Call {
        span: span_of(file, &extend),
        name: base_name.clone(),
        receiver: None,
        receiver_types: vec![base_name.clone()],
        call_kind: CallKind::Constructor,
        args: event_args,
    };
    Some(ScalaBaseConstructorCall {
        base_name,
        args,
        event,
    })
}

fn scala_constructor_argument_texts(args_node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let text = node_text(&child, src).trim();
        if !text.is_empty() {
            out.push(text.to_string());
        }
    }
    out
}

fn scala_constructor_call_args(args_node: Node<'_>, file: FileId, src: &[u8]) -> Vec<CallArg> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        let named_value = (child.kind() == "assignment_expression")
            .then(|| {
                let label = child.child_by_field_name("left")?;
                let value = child.child_by_field_name("right")?;
                (label.kind() == "identifier").then(|| {
                    let name = node_text(&label, src).trim().to_string();
                    (value, (!name.is_empty()).then_some(name))
                })
            })
            .flatten();
        let argument = if let Some((value, name)) = named_value {
            call_arg_from_nodes_with_handler(child, value, file, src, name, &HANDLER)
        } else {
            call_arg_from_node_with_handler(child, file, src, None, &HANDLER)
        };
        if let Some(argument) = argument {
            out.push(argument);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn scala_constructor_decl(
    symbol: bonsai_common::SymbolId,
    parent: bonsai_common::SymbolId,
    class_name: &str,
    name_span: Span,
    span: Span,
    body_span: Span,
    params: Vec<String>,
    flow_events: Vec<bonsai_lang_api::FlowEvent>,
    receiver_field_writes: Vec<FieldWrite>,
    module_path: bonsai_lang_api::ModulePath,
) -> Decl {
    Decl {
        symbol,
        kind: DeclKind::Constructor,
        name: class_name.to_string(),
        qualified_name: None,
        module_path,
        span,
        name_span,
        visibility: Visibility::Public,
        parent: Some(parent),
        body_span: Some(body_span),
        flow_events,
        has_implicit_returns: false,
        params,
        param_annotations: Vec::new(),
        param_default_calls: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes,
        implicit_receiver_names: vec!["this".to_string(), "super".to_string()],
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn constructor_param_names(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|param| matches!(param.kind(), "class_parameter" | "parameter"))
        .filter_map(|param| parameter_binding_name(param, src))
        .collect()
}

/// `is_case_class` forces every class-parameter to count as a field-
/// initializing write, regardless of `val`/`var` modifier — Scala
/// case classes promote every positional parameter to a public `val`
/// implicitly, so without this flag the synthesized ctor would emit
/// no `receiver_field_writes` for `case class Envelope(kind, cmd,
/// user, ...)` and the constructor-return field stitch couldn't
/// project `envelope.cmd ← raw` onto the caller's allocation.
fn scala_constructor_param_field_writes_with_mode(
    params_node: Node<'_>,
    file: FileId,
    src: &[u8],
    params: &[String],
    is_case_class: bool,
) -> Vec<FieldWrite> {
    let mut writes = Vec::new();
    let mut cursor = params_node.walk();
    for param in params_node
        .named_children(&mut cursor)
        .filter(|param| param.kind() == "class_parameter")
    {
        if !is_case_class && !scala_class_parameter_declares_property(param, src) {
            continue;
        }
        let Some(name) = parameter_binding_name(param, src) else {
            continue;
        };
        let Some(source_idx) = params.iter().position(|param| param == &name) else {
            continue;
        };
        writes.push(FieldWrite {
            span: span_of(file, &param),
            target: format!("this.{name}"),
            source_param_indices: vec![source_idx],
        });
    }
    writes
}

fn annotate_scala_named_call_args(events: &mut [FlowEvent], root: Node<'_>, file: FileId, src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    if arg.name.is_some() {
                        continue;
                    }
                    let Some(argument_node) = node_at_span(root, arg.span, &["assignment_expression"]) else {
                        continue;
                    };
                    // `node_at_span` deliberately falls back to an exact node
                    // of another kind when no requested kind exists. Named
                    // arguments require an actual assignment-expression AST;
                    // an infix `input + "x"` also has left/right fields but is
                    // value syntax, not `name = value`.
                    if argument_node.kind() != "assignment_expression" {
                        continue;
                    }
                    let Some(label_node) = argument_node.child_by_field_name("left") else {
                        continue;
                    };
                    let Some(value_node) = argument_node.child_by_field_name("right") else {
                        continue;
                    };
                    if label_node.kind() != "identifier" {
                        continue;
                    }
                    let label = node_text(&label_node, src).trim().to_string();
                    if label.is_empty() {
                        continue;
                    }
                    if let Some(ast_arg) = call_arg_from_nodes_with_handler(
                        argument_node,
                        value_node,
                        file,
                        src,
                        Some(label),
                        &HANDLER,
                    ) {
                        *arg = ast_arg;
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                annotate_scala_named_call_args(then_events, root, file, src);
                annotate_scala_named_call_args(else_events, root, file, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                annotate_scala_named_call_args(body, root, file, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                annotate_scala_named_call_args(body, root, file, src);
                annotate_scala_named_call_args(catch_events, root, file, src);
                annotate_scala_named_call_args(finally_events, root, file, src);
            }
            _ => {}
        }
    }
}

fn scala_class_parameter_declares_property(param: Node<'_>, src: &[u8]) -> bool {
    node_text(&param, src)
        .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .any(|token| matches!(token, "val" | "var"))
}

/// Detect a Scala `case class` (modifier `case` on a `class_definition`).
fn scala_class_is_case(class_node: Node<'_>, src: &[u8]) -> bool {
    let mut cw = class_node.walk();
    for child in class_node.children(&mut cw) {
        if matches!(child.kind(), "case" | "case_class_modifier") {
            return true;
        }
        if child.kind() == "modifiers" {
            let mut mw = child.walk();
            for m in child.children(&mut mw) {
                if matches!(m.kind(), "case" | "case_class_modifier") {
                    return true;
                }
                if node_text(&m, src).trim() == "case" {
                    return true;
                }
            }
        }
    }
    // Fallback: scan the prefix text before `class` for the `case` keyword.
    let text = node_text(&class_node, src);
    if let Some(idx) = text.find("class") {
        let prefix = &text[..idx];
        if prefix
            .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
            .any(|t| t == "case")
        {
            return true;
        }
    }
    false
}

fn parameter_binding_name(param: Node<'_>, src: &[u8]) -> Option<String> {
    let mut names = Vec::new();
    collect_binding_identifiers(param, src, &mut names);
    names.into_iter().find(|name| name != "_")
}

fn collect_binding_identifiers(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if node.kind() == "identifier" {
        let name = node_text(&node, src).trim();
        if !name.is_empty() {
            out.push(name.to_string());
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "type_identifier" {
            continue;
        }
        collect_binding_identifiers(child, src, out);
    }
}

/// Walk every Scala class-like declaration and pull `(name, type)`
/// bindings from `val_definition` / `var_definition` children and from
/// property-declaring constructor parameters (`val data: Envelope`, plus
/// every case-class parameter). Returns `(class_span, [TypeAliasBinding])` so the
/// per-method merge can attach a class's bindings to every method
/// nested inside it.
fn collect_scala_class_field_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<TypeAliasBinding>)> {
    let class_kinds = &["class_definition", "trait_definition", "object_definition"];
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let is_case_class = scala_class_is_case(class_node, src);
        let mut work = vec![class_node];
        while let Some(node) = work.pop() {
            // Don't descend into nested classes; their methods get
            // their own scope.
            if node != class_node && class_kinds.contains(&node.kind()) {
                continue;
            }
            // Don't descend into method bodies — local vals are
            // covered by the per-method `collect_param_type_aliases`
            // pass and would pollute the class-scope set.
            if node != class_node && matches!(node.kind(), "function_definition" | "function_declaration") {
                continue;
            }
            if matches!(node.kind(), "val_definition" | "var_definition") {
                if let Some(binding) = scala_field_alias(node, src) {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            if node.kind() == "class_parameter"
                && (is_case_class || scala_class_parameter_declares_property(node, src))
            {
                if let Some(binding) = scala_field_alias(node, src) {
                    if !aliases.contains(&binding) {
                        aliases.push(binding);
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                work.push(child);
            }
        }
        if !aliases.is_empty() {
            out.push((span_of(file, &class_node), aliases));
        }
    }
    out
}

/// Extract a `name: Type` binding from one Scala field or class-parameter
/// node. Handles both explicit annotations
/// (`val x: Foo = ...`) and constructor-shaped initializers
/// (`val x = new Foo()`), since Scala source frequently relies on
/// type inference for class fields.
fn scala_field_alias(node: Node<'_>, src: &[u8]) -> Option<TypeAliasBinding> {
    let pattern = node
        .child_by_field_name("pattern")
        .or_else(|| node.child_by_field_name("name"))?;
    let name = node_text(&pattern, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let type_short = node
        .child_by_field_name("type")
        .map(|t| node_text(&t, src).to_string())
        .and_then(|t| canonical_simple_type_name(&t))
        .or_else(|| scala_value_constructor_type(node, src))
        .or_else(|| scala_value_cast_type(node, src))?;
    if type_short.is_empty() || name == type_short {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: type_short,
    })
}

/// WS2: collect method-LOCAL `asInstanceOf` cast type bindings, keyed by
/// the enclosing function span. The class-field walk skips method bodies
/// and the kit vocabulary only types explicitly-annotated locals, so an
/// inferred local typed by a cast (`val c = make().asInstanceOf[Foo]`)
/// would otherwise lose its receiver type.
fn collect_scala_local_cast_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, Vec<TypeAliasBinding>)> {
    let fn_kinds = &["function_definition", "function_declaration"];
    let mut out = Vec::new();
    for fn_node in collect_kinds(tree, fn_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![fn_node];
        while let Some(node) = work.pop() {
            if node != fn_node && fn_kinds.contains(&node.kind()) {
                continue;
            }
            if matches!(node.kind(), "val_definition" | "var_definition")
                && node.child_by_field_name("type").is_none()
            {
                if let Some(ty) = scala_value_cast_type(node, src) {
                    if let Some(pattern) = node
                        .child_by_field_name("pattern")
                        .or_else(|| node.child_by_field_name("name"))
                    {
                        let name = node_text(&pattern, src).trim().to_string();
                        if !name.is_empty() && !ty.is_empty() && name != ty {
                            let binding = TypeAliasBinding { name, type_name: ty };
                            if !aliases.contains(&binding) {
                                aliases.push(binding);
                            }
                        }
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                work.push(child);
            }
        }
        if !aliases.is_empty() {
            out.push((span_of(file, &fn_node), aliases));
        }
    }
    out
}

/// WS2: `val c = make().asInstanceOf[Foo]` — Scala's `asInstanceOf[T]`
/// cast. The initializer is a `call_expression` whose `field` is the
/// `asInstanceOf` identifier and which carries the target type as a
/// `type_identifier` / `generic_type` argument. Returns that type so a
/// cast-typed receiver resolves `receiver_type_in`.
fn scala_value_cast_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let value = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))?;
    if value.kind() != "call_expression" {
        return None;
    }
    let field = value.child_by_field_name("field")?;
    if node_text(&field, src).trim() != "asInstanceOf" {
        return None;
    }
    let mut cursor = value.walk();
    for child in value.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "type_identifier" | "generic_type" | "simple_type" | "user_type"
        ) {
            return canonical_simple_type_name(node_text(&child, src));
        }
    }
    None
}

fn scala_value_constructor_type(node: Node<'_>, src: &[u8]) -> Option<String> {
    let value = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))?;
    let candidate = match value.kind() {
        // `new Foo(...)` shape across grammar versions.
        "instance_expression" | "creator" | "new_expression" => {
            let mut found = None;
            let mut cursor = value.walk();
            for child in value.named_children(&mut cursor) {
                if matches!(child.kind(), "type_identifier" | "simple_type" | "user_type") {
                    found = Some(node_text(&child, src).to_string());
                    break;
                }
                if child.kind() == "call_expression" {
                    let mut inner = child.walk();
                    for sub in child.named_children(&mut inner) {
                        if matches!(sub.kind(), "type_identifier" | "simple_type" | "identifier") {
                            found = Some(node_text(&sub, src).to_string());
                            break;
                        }
                    }
                    if found.is_some() {
                        break;
                    }
                }
            }
            found?
        }
        // `val x = Foo()` (apply method) — Scala convention treats
        // PascalCase callees as constructor-shaped.
        "call_expression" => {
            let func = value.child_by_field_name("function").or_else(|| {
                let mut cursor = value.walk();
                let mut found = None;
                for child in value.named_children(&mut cursor) {
                    if matches!(child.kind(), "identifier" | "type_identifier") {
                        found = Some(child);
                        break;
                    }
                }
                found
            })?;
            node_text(&func, src).to_string()
        }
        _ => return None,
    };
    let canonical = canonical_simple_type_name(&candidate)?;
    canonical
        .chars()
        .next()
        .filter(|first| first.is_ascii_uppercase())?;
    Some(canonical)
}

fn canonical_simple_type_name(raw: &str) -> Option<String> {
    let no_generics = raw.split('[').next().unwrap_or(raw);
    let no_generics = no_generics.split('<').next().unwrap_or(no_generics);
    let trimmed = no_generics
        .trim()
        .trim_start_matches("new ")
        .trim()
        .trim_end_matches('?');
    let short = trimmed.rsplit('.').next().unwrap_or(trimmed).trim();
    if short.is_empty()
        || !short
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return None;
    }
    Some(short.to_string())
}

fn collect_scala_method_owners(tree: &Tree, file: FileId) -> Vec<(Span, Span, &'static str)> {
    let mut out = Vec::new();
    for method in collect_kinds(tree, &["function_definition", "function_declaration"]) {
        let Some(owner) = nearest_scala_owner(method) else {
            continue;
        };
        out.push((span_of(file, &method), span_of(file, &owner), owner.kind()));
    }
    out
}

fn nearest_scala_owner(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        match candidate.kind() {
            "class_definition" | "trait_definition" | "object_definition" => return Some(candidate),
            "function_definition" | "function_declaration" => return None,
            _ => parent = candidate.parent(),
        }
    }
    None
}

/// Parse `import_declaration` nodes into `ImportSpec`s, one per surfaced symbol.
///
/// Scala shapes:
///   `import x.y.Z`            — straight
///   `import x.y.{A, B}`       — braced selector list
///   `import x.y.{A => B}`     — renaming alias (Scala 2)
///   `import x.y.{A as B}`     — renaming alias (Scala 3)
///   `import x.y._` / `x.y.*`  — wildcard (Scala 2 / Scala 3)
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    for import_node in collect_kinds(tree, &["import_declaration"]) {
        let path = scala_import_path(&import_node, src);
        if path.is_empty() {
            continue;
        }
        let span = span_of(file, &import_node);
        let mut cursor = import_node.walk();
        let children: Vec<Node<'_>> = import_node.named_children(&mut cursor).collect();

        if let Some(selectors) = children
            .iter()
            .find(|child| child.kind() == "namespace_selectors")
        {
            append_scala_selectors(*selectors, &path, span, src, &mut imports);
            continue;
        }

        if let Some(rename) = children
            .iter()
            .find(|child| matches!(child.kind(), "as_renamed_identifier" | "arrow_renamed_identifier"))
        {
            append_scala_renamed_selector(*rename, &path, span, src, &mut imports);
            continue;
        }

        let is_wildcard = children.iter().any(|child| child.kind() == "namespace_wildcard");
        imports.push(ImportSpec {
            span,
            module: path,
            alias: None,
            is_wildcard,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn scala_import_path(import_node: &Node<'_>, src: &[u8]) -> String {
    let mut segments = Vec::new();
    for index in 0..import_node.child_count() {
        let Ok(field_index) = u32::try_from(index) else {
            continue;
        };
        if import_node.field_name_for_child(field_index) != Some("path") {
            continue;
        }
        let Some(child) = import_node.child(field_index) else {
            continue;
        };
        if !child.is_named() {
            continue;
        }
        let segment = node_text(&child, src).trim();
        if !segment.is_empty() {
            segments.push(segment);
        }
    }
    segments.join(".")
}

fn append_scala_selectors(
    selectors: Node<'_>,
    module: &str,
    span: Span,
    src: &[u8],
    imports: &mut Vec<ImportSpec>,
) {
    let mut cursor = selectors.walk();
    for selector in selectors.named_children(&mut cursor) {
        match selector.kind() {
            "namespace_wildcard" => imports.push(ImportSpec {
                span,
                module: module.to_string(),
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Module,
            }),
            "as_renamed_identifier" | "arrow_renamed_identifier" => {
                append_scala_renamed_selector(selector, module, span, src, imports);
            }
            _ => {
                let original = node_text(&selector, src).trim();
                if !original.is_empty() {
                    imports.push(ImportSpec {
                        span,
                        module: module.to_string(),
                        alias: None,
                        is_wildcard: false,
                        original_name: Some(original.to_string()),
                        scope: ImportScope::Module,
                    });
                }
            }
        }
    }
}

fn append_scala_renamed_selector(
    selector: Node<'_>,
    module: &str,
    span: Span,
    src: &[u8],
    imports: &mut Vec<ImportSpec>,
) {
    let (Some(name_node), Some(alias_node)) = (
        selector.child_by_field_name("name"),
        selector.child_by_field_name("alias"),
    ) else {
        return;
    };
    if alias_node.kind() == "wildcard" {
        return;
    }
    let original = node_text(&name_node, src).trim();
    let alias = node_text(&alias_node, src).trim();
    if original.is_empty() || alias.is_empty() {
        return;
    }
    imports.push(ImportSpec {
        span,
        module: module.to_string(),
        alias: Some(alias.to_string()),
        is_wildcard: false,
        original_name: Some(original.to_string()),
        scope: ImportScope::Module,
    });
}

/// Scala-aware visibility collector that recognises scoped forms:
/// `private[X]` / `protected[X]` / `private[this]`. Maps to the
/// four-level lattice as follows:
///
/// - `private[this]` → `Private` (instance-only is the strictest)
/// - `private` (bare) → `Private`
/// - `private[X]` → `Crate` (broader scope within the same compilation unit)
/// - `protected[X]` → `Protected` (we don't have a tighter level)
/// - `protected` → `Protected`
/// - default → `Public`
///
/// Visibility comes from real syntax markers; per-language scoping
/// handling lives in the adapter.
fn collect_scala_visibility(
    root: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut visibility_by_span = std::collections::HashMap::new();
    // Iterative DFS — tree-sitter trees can be deep enough that recursion
    // would risk blowing the stack on pathological inputs.
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if SCALA_DECL_KINDS.contains(&node.kind()) {
            visibility_by_span.insert(span_of(file, &node), scala_node_visibility(node, src));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    visibility_by_span
}

/// Map a single Scala decl's `modifiers` block to the four-level visibility
/// lattice. See `collect_scala_visibility`'s doc comment for the rules.
fn scala_node_visibility(node: tree_sitter::Node<'_>, src: &[u8]) -> Visibility {
    let mut found_private = false;
    let mut found_protected = false;
    let mut scope_marker: Option<String> = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        // Walk modifier keywords; tree-sitter-scala emits keyword
        // tokens directly as children. The optional `[X]` access
        // qualifier lives next to the keyword as an `access_qualifier`
        // node (or as a bracketed identifier).
        let mut modifiers_cursor = child.walk();
        for modifier in child.children(&mut modifiers_cursor) {
            let text = node_text(&modifier, src);
            if text == "private" {
                found_private = true;
            } else if text == "protected" {
                found_protected = true;
            } else if matches!(modifier.kind(), "access_qualifier") {
                // Strip the surrounding `[ ]` to get the bare scope name.
                let qualifier_text = node_text(&modifier, src);
                let inside = qualifier_text
                    .trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .trim();
                if !inside.is_empty() {
                    scope_marker = Some(inside.to_string());
                }
            } else if text.starts_with('[') && text.ends_with(']') {
                // Older grammars emit the qualifier as a literal bracketed
                // token rather than an `access_qualifier` node.
                let inside = text.trim_start_matches('[').trim_end_matches(']').trim();
                if !inside.is_empty() {
                    scope_marker = Some(inside.to_string());
                }
            }
        }
    }
    match (found_private, found_protected, scope_marker.as_deref()) {
        // `private[this]` is the strictest form — instance-only.
        (true, _, Some("this")) => Visibility::Private,
        // `private[X]` widens to package-level within the same compilation unit.
        (true, _, Some(_)) => Visibility::Crate,
        (true, _, None) => Visibility::Private,
        (_, true, _) => Visibility::Protected,
        _ => Visibility::Public,
    }
}

/// True when the decl is a type-defining container that can carry `bases`.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Scala class / object / trait definitions and collect the
/// type names listed in `extends_clause`. Grammar shape (verified):
///
///   `class Echo extends WebSocketHandler with Mixin` →
///     (class_definition name: (identifier)
///        extend: (extends_clause type: (type_identifier) type: (type_identifier)))
///
/// `extends_clause` carries every parent (the initial `extends` plus
/// every `with` mixin) under repeating `type:` fields. Scala doesn't
/// distinguish "the super-class" vs "mixin traits" syntactically.
fn collect_scala_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_by_class = Vec::new();
    let class_kinds = &["class_definition", "object_definition", "trait_definition"];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        // `extend:` field holds the entire `extends_clause` (extends + every with-mixin).
        let extend_node = class_node.child_by_field_name("extend");
        if let Some(extend) = extend_node {
            let mut extend_cursor = extend.walk();
            for child in extend.named_children(&mut extend_cursor) {
                let raw = node_text(&child, src);
                if let Some(name) = canonical_scala_base_name(raw) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_by_class.push((span_of(file, &class_node), bases));
        }
    }
    bases_by_class
}

/// Canonicalize a Scala base reference to a bare type name.
///
/// Strips type parameter brackets (`Foo[T]` → `Foo`) and any qualifying
/// path (`pkg.Foo` → `Foo`). Lowercase-leading names are rejected because
/// they're values (e.g. constructor-arg lists) not type references.
fn canonical_scala_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Strip type parameter brackets: `Foo[T]` → `Foo`.
    let head = trimmed.split('[').next().unwrap_or(trimmed).trim();
    // Strip qualifying path: `pkg.Foo` → `Foo`.
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    // Type names are conventionally upper-cased; reject lower-case leads
    // so we don't pick up arg expressions in `extends Foo(arg)`.
    if bare.is_empty() || !bare.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    Some(bare.to_string())
}

/// Per-arm body spans collected from every `match_expression` in the
/// file. The kit emits a single `Branch { then_events: [arm1_body...,
/// arm2_body..., ...] }` for the whole match, lumping arm bodies
/// together. We use these spans in `split_match_arms_in_branch_events`
/// to peel each arm into its own nested `Branch` so the engine forks
/// state per arm.
fn collect_scala_match_arm_spans(tree: &Tree, _src: &[u8], file: FileId) -> Vec<Vec<bonsai_common::Span>> {
    let mut spans_per_match: Vec<Vec<bonsai_common::Span>> = Vec::new();
    for match_node in collect_kinds(tree, &["match_expression"]) {
        let mut arm_body_spans: Vec<bonsai_common::Span> = Vec::new();
        let mut match_cursor = match_node.walk();
        for child in match_node.named_children(&mut match_cursor) {
            if child.kind() != "case_block" {
                continue;
            }
            let mut block_cursor = child.walk();
            for case in child.named_children(&mut block_cursor) {
                if case.kind() != "case_clause" {
                    continue;
                }
                // Scala's case_clause exposes one `body:` field per
                // statement (multi-statement arms produce multiple
                // body children). Span the union from min start to
                // max end across every named child whose role is
                // `body` so we capture the full arm scope.
                let mut min_start: Option<u64> = None;
                let mut max_end: Option<u64> = None;
                let mut case_cursor = case.walk();
                for (field_idx, body_node) in case.named_children(&mut case_cursor).enumerate() {
                    if case.field_name_for_named_child(field_idx as u32) == Some("body") {
                        let body_start = body_node.start_byte() as u64;
                        let body_end = body_node.end_byte() as u64;
                        min_start = Some(min_start.map_or(body_start, |m| m.min(body_start)));
                        max_end = Some(max_end.map_or(body_end, |m| m.max(body_end)));
                    }
                }
                if let (Some(start), Some(end)) = (min_start, max_end) {
                    arm_body_spans.push(bonsai_common::Span::new(file, start, end));
                }
            }
        }
        if !arm_body_spans.is_empty() {
            spans_per_match.push(arm_body_spans);
        }
    }
    spans_per_match
}

/// Extract the dotted package path from a file's `package_clause`, if any.
///
/// Returns the path as a list of segments (e.g. `package com.acme` →
/// `["com", "acme"]`) so callers can feed it to
/// `apply_module_path_semantic_identity`. Returns `None` for files without
/// an explicit `package` declaration.
fn extract_scala_package(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        // Look for the dotted path child; grammars vary on which named
        // kind exposes it.
        let mut clause_cursor = child.walk();
        for subchild in child.children(&mut clause_cursor) {
            if matches!(
                subchild.kind(),
                "package_identifier" | "stable_identifier" | "identifier"
            ) {
                let text = node_text(&subchild, src);
                let segments: Vec<String> = text
                    .split('.')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if !segments.is_empty() {
                    return Some(segments);
                }
            }
        }
    }
    None
}

/// Convert a Scala accessor method whose single Return reads a dotted
/// receiver field (`def cmd: String = data.cmd`) into a `Call+Return`
/// chain so the call dispatches to the receiver-typed member (case-
/// class accessor / sibling getter) and threads taint through the
/// 1-level interprocedural receiver-field bridge. Mirrors the equivalent
/// lang_csharp / lang_dart conversion.
fn rewrite_scala_member_access_accessors(index: &mut DeclIndex) {
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
        let FlowEvent::Return { span, value_flow, .. } = &decl.flow_events[0] else {
            continue;
        };
        let Some(projection) = value_flow.projection.as_ref() else {
            continue;
        };
        let Some((call_receiver, call_name)) = scala_dotted_member_access_parts(projection) else {
            continue;
        };
        // A primary-constructor `val`/`var` is an instance field even when
        // Scala source refers to it without `this.`. Preserve that compiler
        // place explicitly so constructor state and later accessor reads use
        // the same IDG storage identity. The decision comes from the
        // adapter's typed class-field aliases, not from a field-name list.
        if !call_receiver.contains('.')
            && decl.implicit_receiver_names.iter().any(|name| name == "this")
            && decl.type_aliases.iter().any(|alias| alias.name == call_receiver)
        {
            // This is a field projection, not a method invocation. Keep it as
            // an exact compiler place so `this.data` written by the primary
            // constructor and `this.data.cmd` read here share the same IDG
            // storage prefix. Synthesizing a zero-argument call would make
            // the result depend on an accessor declaration and split the
            // projected field state at that artificial call boundary.
            let place = format!("this.{call_name}");
            let body_span = *span;
            decl.flow_events = vec![FlowEvent::Return {
                span: body_span,
                value_text: Some(place.clone()),
                value_name: Some(place.clone()),
                value_flow: bonsai_lang_api::ExpressionFlow::from_place(&place),
            }];
            continue;
        }
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
                value_flow: bonsai_lang_api::ExpressionFlow {
                    call_sites: vec![body_span],
                    ..Default::default()
                },
            },
        ];
    }
}

/// If `body` is a simple dotted member-access of identifiers
/// (`data.cmd`, optionally prefixed `this.`/`super.`), return
/// `(receiver, call_name)` so the synthesized accessor can model it
/// as a method call. Returns `None` for non-trivial bodies.
fn scala_dotted_member_access_parts(
    projection: &bonsai_lang_api::ExpressionProjection,
) -> Option<(String, String)> {
    let mut segments: Vec<&str> = std::iter::once(projection.base.as_str())
        .chain(projection.path.iter().map(String::as_str))
        .collect();
    if matches!(segments.first(), Some(&"this" | &"super")) {
        segments.remove(0);
    }
    if segments.len() < 2 {
        return None;
    }
    // Every segment must be a plain ASCII identifier.
    for seg in &segments {
        if seg.is_empty()
            || !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || !seg
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            return None;
        }
    }
    // Receiver = up-to-last-dot; call_name = full dotted form.
    let call_name = segments.join(".");
    let receiver = segments[..segments.len() - 1].join(".");
    Some((receiver, call_name))
}

/// Qualify a bare read `val c = cmd` of a sibling zero-arg member by
/// rewriting to `Assign{source_call:cmd}` plus an explicit `Call`
/// event so `walk_call`'s argless fallback synthesizes a recv-slot
/// for the interprocedural receiver-field bridge.
fn qualify_scala_implicit_member_reads(index: &mut DeclIndex) {
    bonsai_lang_api::qualify_implicit_member_reads_in_index(index, |name| ImplicitMemberReadCall {
        source_call: name.to_string(),
        call_name: name.to_string(),
        receiver: None,
        call_kind: CallKind::Function,
    });
}

/// Synthesize per-component accessor `Method` decls for each Scala
/// case class (`case class Envelope(kind, cmd, user, length, extras)`).
/// The kit's `synthesize_record_members` only matches the `record_
/// declaration` node kind — Scala case classes are `class_definition`
/// with `case_class_*` modifiers, so none of the components get
/// accessors and `envelope.cmd` resolves to nothing → taint stops.
/// Mirror the Java/C# record synthesis: one zero-arg Method per
/// class_parameter whose single Return is `this.<param>`.
fn synthesize_scala_case_class_accessors(idx: &mut DeclIndex, file: FileId, ctx: &AdapterContext<'_>) {
    let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
        return;
    };
    let src = snapshot.text.as_bytes();
    let mut next = idx.defs.iter().map(|d| d.symbol.raw()).max().map_or(1, |m| m + 1);
    let mut synthesized: Vec<Decl> = Vec::new();
    for class_node in collect_kinds(&tree, &["class_definition"]) {
        // Detect `case` modifier — Scala wraps it under a
        // `modifiers` child containing a `case_class_modifier` /
        // `case` token.
        let mut is_case = false;
        let mut cw = class_node.walk();
        for child in class_node.children(&mut cw) {
            if matches!(child.kind(), "modifiers") {
                let mut mw = child.walk();
                for m in child.children(&mut mw) {
                    if m.kind() == "case" || node_text(&m, src).contains("case") {
                        is_case = true;
                        break;
                    }
                }
            }
            if child.kind() == "case" {
                is_case = true;
            }
        }
        if !is_case {
            continue;
        }
        let class_span = span_of(file, &class_node);
        let Some(parent_decl) = idx
            .defs
            .iter()
            .find(|d| is_class_like(d.kind) && d.span == class_span)
        else {
            continue;
        };
        let parent_sym = parent_decl.symbol;
        let module_path = parent_decl.module_path.clone();
        let visibility = parent_decl.visibility;
        // Pull case-class params from the `class_parameters` child.
        let Some(params_node) = first_named_child_of_kind(&class_node, "class_parameters") else {
            continue;
        };
        let mut comps: Vec<(String, Span)> = Vec::new();
        let mut pw = params_node.walk();
        for child in params_node.children(&mut pw) {
            if child.kind() != "class_parameter" {
                continue;
            }
            let mut found_name: Option<tree_sitter::Node<'_>> = None;
            let mut subw = child.walk();
            for sub in child.children(&mut subw) {
                if sub.kind() == "identifier" {
                    found_name = Some(sub);
                    break;
                }
            }
            if let Some(name_node) = found_name {
                let name = node_text(&name_node, src).trim().to_string();
                if !name.is_empty() {
                    comps.push((name, span_of(file, &name_node)));
                }
            }
        }
        if comps.is_empty() {
            continue;
        }
        for (comp, comp_span) in &comps {
            let already = idx.defs.iter().chain(synthesized.iter()).any(|d| {
                d.parent == Some(parent_sym)
                    && d.name == *comp
                    && d.params.is_empty()
                    && matches!(d.kind, DeclKind::Method | DeclKind::Function)
            });
            if already {
                continue;
            }
            let field = format!("this.{comp}");
            synthesized.push(Decl {
                symbol: SymbolId::new(next),
                kind: DeclKind::Method,
                name: comp.clone(),
                qualified_name: None,
                module_path: module_path.clone(),
                span: *comp_span,
                name_span: *comp_span,
                visibility,
                parent: Some(parent_sym),
                body_span: Some(*comp_span),
                flow_events: vec![FlowEvent::Return {
                    span: *comp_span,
                    value_text: Some(field.clone()),
                    value_name: Some(field.clone()),
                    value_flow: bonsai_lang_api::ExpressionFlow::from_place(field.clone()),
                }],
                has_implicit_returns: false,
                params: Vec::new(),
                param_annotations: Vec::new(),
                param_default_calls: Vec::new(),
                type_aliases: Vec::new(),
                bases: Vec::new(),
                receiver_param_index: None,
                receiver_field_writes: Vec::new(),
                implicit_receiver_names: vec!["this".to_string(), "super".to_string()],
                receiver_state_sources: vec![field],
                return_type: None,
                is_variadic: false,
            });
            next += 1;
        }
    }
    idx.defs.extend(synthesized);
}

#[cfg(test)]
mod import_tests {
    use super::*;

    fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
        let language = language_from_pack(PACK_NAME).expect("scala grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set scala grammar");
        let tree = parser.parse(src.as_bytes(), None).expect("parse scala source");
        parse_imports(&tree, src.as_bytes(), FileId::new(0))
    }

    #[test]
    fn selectors_are_lowered_from_cst_nodes() {
        let imports = parse_import_specs(
            "import a.b.{A, B => BB, C as CC, *, given, given Foo}\n\
             import a.b.Item as Renamed\n",
        );

        assert!(
            imports.iter().any(|spec| {
                spec.module == "a.b" && spec.original_name.as_deref() == Some("A") && spec.alias.is_none()
            }),
            "{imports:#?}"
        );
        assert!(imports.iter().any(|spec| {
            spec.module == "a.b"
                && spec.original_name.as_deref() == Some("B")
                && spec.alias.as_deref() == Some("BB")
        }));
        assert!(imports
            .iter()
            .any(|spec| spec.module == "a.b" && spec.is_wildcard));
        assert!(imports.iter().any(|spec| {
            spec.module == "a.b" && spec.original_name.as_deref() == Some("Foo") && spec.alias.is_none()
        }));
        assert!(imports.iter().any(|spec| {
            spec.module == "a.b"
                && spec.original_name.as_deref() == Some("Item")
                && spec.alias.as_deref() == Some("Renamed")
        }));
    }
}
