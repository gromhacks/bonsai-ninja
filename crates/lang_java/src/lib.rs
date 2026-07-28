//! Java language adapter.
mod parse_recovery;

use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    decl_index_with_handler,
    kit::{
        collect_kinds, language_from_pack, node_text, package_module_segments_with_workspace_prefix,
        parse_with, span_of, with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, AssignValueKind, ConditionEquality, ConditionExpressionFact,
    ConditionOperandFact, DeclIndex, DeclKind, FileSnapshot, FlowEvent, GrammarHandler, ImportIndex,
    ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ParseRecoveryEdit,
    StaticScalarValue, SyntaxTree, TypeAliasBinding, Vfs, Visibility,
};
use parse_recovery::java_parse_recovery_edits;
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("java");
const PACK_NAME: &str = "java";

/// Java lifecycle transitions: Closeable / Future / Lock / Disposable.
const JAVA_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
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
    bonsai_lang_api::LifecycleTransition {
        call_match: "destroy",
        transition: "freed",
        arg_index: 0,
    },
];

const HANDLER: GrammarHandler = GrammarHandler {
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    // Java try-with-resources binds `try (T r = expr) { .. }` as a
    // `resource` node, which exposes the same `name`/`value` fields the
    // generic assignment branch reads. Marking it an assignment emits the
    // `r = expr` Assign so the call-RHS summary can carry return-value
    // taint into `r`. `is_assignment` ORs this with GENERIC_HANDLER, so the
    // generic kinds (variable_declarator, etc.) still resolve.
    assignment_kinds: &["resource"],
    ..with_fn_kinds_and_implicit_receivers(
        &["method_declaration", "constructor_declaration"],
        &["this", "super"],
        &[],
    )
};

#[derive(Debug, Default, Copy, Clone)]
pub struct JavaAdapter;

impl JavaAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for JavaAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Java"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["java"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn parse_recovery_edits(
        &self,
        snapshot: &FileSnapshot,
        _vfs: &Vfs,
        tree: &SyntaxTree,
    ) -> Vec<ParseRecoveryEdit> {
        java_parse_recovery_edits(snapshot, tree)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Exceptions: the adapter populates `Throw::thrown_type` from
        // `throw new IOException(...)` and `Try::catch_types` from
        // `catch (IOException e)` (including multi-catch
        // `catch (A | B e)`). The engine seeds the catch param only
        // when at least one body throw is type-assignable; this lifts
        // the `Partial` claim to `Exact` for typed-exception flow on
        // Java code.
        // Reflection: the adapter rewrites the constant-string
        // `Class.forName("X").getMethod("Y").invoke(target, args)`
        // chain into a synthesized direct call `X.Y(args)`. Dynamic
        // forms remain unrewritten and the rule-load gate still
        // rejects rules anchored on the reflective shape.
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &["Object"],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            exceptions: bonsai_lang_api::CapabilityLevel::Exact,
            reflection: bonsai_lang_api::CapabilityLevel::Partial,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            field_places_complete: true,
            // Java constructors are class-named, so the kind-based
            // `DeclKind::Constructor` lookup is authoritative; the
            // name-list fallback is intentionally empty.
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["this"],
            call_text_prefilter: bonsai_lang_api::CallTextPrefilter::Parenthesized,
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
            return index;
        };
        let src = snapshot.text.as_bytes();
        populate_java_condition_expressions(&mut index.branch_conditions, &tree, file, src);
        populate_java_static_scalar_facts(&mut index, &tree, file, src);
        // Phase-6 return-type extraction: `T method() {}` populates
        // `Decl.return_type` for `apply_assign_call_result_types`.
        bonsai_lang_api::populate_decl_return_types(&mut index, &tree, src, &HANDLER);
        // Populate Throw::thrown_type and Try::catch_types from the
        // parse tree before downstream resolution. Done first so the
        // type info propagates through every later mutation.
        for decl in &mut index.defs {
            populate_java_exception_types(&mut decl.flow_events, &tree, src);
            rewrite_java_reflection_chain(&mut decl.flow_events);
        }
        let field_aliases = collect_java_type_aliases(tree.root_node(), src, &["field_declaration"]);
        let mut method_aliases = collect_java_method_type_aliases(&tree, file, src, &field_aliases);
        method_aliases.extend(collect_java_graphql_datafetcher_lambda_aliases(
            &tree,
            file,
            src,
            &field_aliases,
        ));
        for decl in &mut index.defs {
            if let Some(aliases) = method_aliases
                .iter()
                .find_map(|(span, aliases)| (*span == decl.span).then_some(aliases))
            {
                decl.type_aliases = aliases.clone();
            }
        }
        // Resolve generic type variables from their Tree-sitter type bounds.
        // `T data` in `class Box<T extends App.Envelope>` carries both the
        // declared `T` identity and the compiler-proven `App.Envelope` upper
        // bound, so receiver dispatch on `data.method()` can resolve against
        // the bound without any method-name inventory.
        let class_type_bounds = collect_java_class_type_parameter_bounds(&tree, file, src);
        let bounds_by_parent: std::collections::HashMap<_, _> = index
            .defs
            .iter()
            .filter(|decl| is_class_like(decl.kind))
            .filter_map(|decl| {
                class_type_bounds
                    .iter()
                    .find_map(|(span, bounds)| (*span == decl.span).then(|| (decl.symbol, bounds.clone())))
            })
            .collect();
        for decl in &mut index.defs {
            if let Some(bounds) = decl.parent.and_then(|parent| bounds_by_parent.get(&parent)) {
                expand_java_type_parameter_aliases(&mut decl.type_aliases, bounds);
            }
        }
        // Per-class `bases`: `class C extends B implements I, J` →
        // ["B", "I", "J"]. Lets `kind: param` rules require an
        // ancestor type (`in_class: [WebSocketHandler]` matching a
        // user `class Echo extends WebSocketHandler { ... }`).
        let bases_by_span = collect_java_class_bases(&tree, file, src);
        for decl in &mut index.defs {
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
        rewrite_java_explicit_constructor_invocations(&mut index);
        let constants_by_class = collect_java_class_string_constants(&tree, file, src);
        attach_java_class_string_constants(&mut index, &constants_by_class);
        // Java visibility from real syntax — `public`/`private`/
        // `protected` modifiers, and absence-of-modifier = package-private.
        let visibility_by_span = collect_java_visibility(tree.root_node(), file, src);
        for decl in &mut index.defs {
            if let Some(vis) = visibility_by_span.get(&decl.span).copied() {
                decl.visibility = vis;
            }
        }
        // Module path from `package com.foo.bar;` declaration.
        // When absent (default package), fall back to file-stem.
        if let Some(segments) = extract_java_package(tree.root_node(), src) {
            let segments = package_module_segments_with_workspace_prefix(file, ctx, segments);
            bonsai_lang_api::apply_module_path_semantic_identity(&mut index, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut index, ctx);
        }
        // Append `FlowEvent::Lifecycle` for recognised Java
        // resource transitions (`Closeable.close`, `Future.cancel`,
        // `Lock.unlock`).
        for decl in &mut index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, JAVA_LIFECYCLE_TRANSITIONS);
        }
        // Synthesize the implicit members of `record` declarations —
        // Java auto-generates a canonical constructor (`this.<comp> =
        // <comp>` for each component) and a zero-arg accessor per
        // component (`<comp>()` returns `this.<comp>`). The grammar has
        // no nodes for these, so without synthesis `new R(..)` and
        // `r.comp()` are opaque and taint can't thread through a record.
        bonsai_lang_api::kit::synthesize_record_members(&mut index, &tree, src, file);
        bonsai_lang_api::kit::qualify_bare_hierarchy_member_calls(&mut index);
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing (`Foo c = new Foo()`
        // → `c: Foo`) so `c.method(...)` carries a resolved receiver type
        // for `receiver_type_in` / `[Type, method]` rules. Java class
        // names are PascalCase and methods camelCase, so the constructor
        // heuristic is reliable (unlike Go's uppercase exported functions).
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut index);
        index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) else {
            return ImportIndex {
                file,
                ..Default::default()
            };
        };
        ImportIndex {
            file,
            imports: collect_java_imports(&tree, file, snapshot.text.as_bytes()),
        }
    }
}

fn populate_java_condition_expressions(
    facts: &mut [bonsai_lang_api::BranchConditionFact],
    tree: &Tree,
    file: FileId,
    src: &[u8],
) {
    for branch in collect_kinds(tree, &["if_statement"]) {
        let branch_span = span_of(file, &branch);
        let Some(condition) = branch.child_by_field_name("condition") else {
            continue;
        };
        let Some(fact) = facts.iter_mut().find(|fact| fact.branch_span == branch_span) else {
            continue;
        };
        fact.expression = Some(lower_java_condition_expression(condition, file, src));
    }
}

fn lower_java_condition_expression(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionExpressionFact {
    if node.kind() == "parenthesized_expression" {
        if let Some(inner) = node.named_child(0) {
            return lower_java_condition_expression(inner, file, src);
        }
    }
    let span = span_of(file, &node);
    if node.kind() == "unary_expression" {
        if let Some(operand) = node
            .child_by_field_name("operand")
            .or_else(|| node.named_child(0))
        {
            let operator = src
                .get(node.start_byte()..operand.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            if operator == Some("!") {
                return ConditionExpressionFact::Not {
                    span,
                    operand: Box::new(lower_java_condition_expression(operand, file, src)),
                };
            }
        }
    }
    if node.kind() == "binary_expression" {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let operator = src
                .get(left.end_byte()..right.start_byte())
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim);
            match operator {
                Some("||") => {
                    return merge_java_condition_junction(
                        span,
                        lower_java_condition_expression(left, file, src),
                        lower_java_condition_expression(right, file, src),
                        false,
                    );
                }
                Some("&&") => {
                    return merge_java_condition_junction(
                        span,
                        lower_java_condition_expression(left, file, src),
                        lower_java_condition_expression(right, file, src),
                        true,
                    );
                }
                Some("==" | "!=") => {
                    return ConditionExpressionFact::Equality {
                        span,
                        relation: if operator == Some("==") {
                            ConditionEquality::Equal
                        } else {
                            ConditionEquality::NotEqual
                        },
                        left: java_condition_operand(left, file, src),
                        right: java_condition_operand(right, file, src),
                    };
                }
                _ => {}
            }
        }
    }
    if node.kind() == "instanceof_expression" {
        if let (Some(subject), Some(type_node)) = (
            node.child_by_field_name("left")
                .or_else(|| node.child_by_field_name("expression"))
                .or_else(|| node.named_child(0)),
            node.child_by_field_name("right")
                .or_else(|| node.child_by_field_name("type"))
                .or_else(|| node.named_child(1)),
        ) {
            let type_name = node_text(&type_node, src).trim().to_string();
            if !type_name.is_empty() {
                return ConditionExpressionFact::TypeTest {
                    span,
                    subject: java_condition_operand(subject, file, src),
                    type_name,
                };
            }
        }
    }
    ConditionExpressionFact::Atom { span }
}

fn merge_java_condition_junction(
    span: Span,
    left: ConditionExpressionFact,
    right: ConditionExpressionFact,
    all: bool,
) -> ConditionExpressionFact {
    let mut operands = Vec::new();
    let mut push = |operand: ConditionExpressionFact| match (all, operand) {
        (true, ConditionExpressionFact::All { operands: nested, .. })
        | (false, ConditionExpressionFact::Any { operands: nested, .. }) => operands.extend(nested),
        (_, operand) => operands.push(operand),
    };
    push(left);
    push(right);
    if all {
        ConditionExpressionFact::All { span, operands }
    } else {
        ConditionExpressionFact::Any { span, operands }
    }
}

fn java_condition_operand(node: Node<'_>, file: FileId, src: &[u8]) -> ConditionOperandFact {
    ConditionOperandFact {
        span: span_of(file, &node),
        value_flow: bonsai_lang_api::kit::expression_flow_from_node(node, file, src),
        static_string: java_static_string_literal(node, src),
    }
}

fn java_static_string_literal(node: Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "string_literal" {
        return None;
    }
    let text = node_text(&node, src);
    let inner = text.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains('\\')).then(|| inner.to_string())
}

fn java_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    match node.kind() {
        "string_literal" => Some(StaticScalarValue::String(java_static_string_literal(node, src)?)),
        "true" => Some(StaticScalarValue::Boolean(true)),
        "false" => Some(StaticScalarValue::Boolean(false)),
        "null_literal" => Some(StaticScalarValue::Null),
        _ => None,
    }
}

fn populate_java_static_scalar_facts(index: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let static_values: std::collections::HashMap<_, _> =
        collect_kinds(tree, &["string_literal", "true", "false", "null_literal"])
            .into_iter()
            .filter_map(|node| {
                let value = java_static_scalar(node, src)?;
                let span = span_of(file, &node);
                Some(((span.start, span.end), value))
            })
            .collect();
    let call_values: std::collections::HashMap<_, _> =
        collect_kinds(tree, &["method_invocation", "object_creation_expression"])
            .into_iter()
            .map(|node| {
                let span = span_of(file, &node);
                ((span.start, span.end), node)
            })
            .collect();
    for fact in &mut index.assignment_values {
        if fact.direct_call_name.is_none() {
            continue;
        }
        let Some(call) = call_values.get(&(fact.value_span.start, fact.value_span.end)) else {
            continue;
        };
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        let argument_nodes: Vec<_> = arguments.named_children(&mut cursor).collect();
        if argument_nodes.is_empty() {
            continue;
        }
        let values: Option<Vec<_>> = argument_nodes
            .into_iter()
            .map(|argument| java_static_scalar(argument, src))
            .collect();
        fact.exact_static_call_args = values;
    }
    for fact in &mut index.call_receivers {
        fact.static_value = static_values
            .get(&(fact.receiver_span.start, fact.receiver_span.end))
            .cloned();
    }
    bonsai_lang_api::kit::populate_call_argument_static_values(index, tree, file, src, java_static_scalar);
}

/// Build per-method type-alias bindings (`Foo bar` → `bar : Foo`) by
/// merging file-level field aliases with each method's local declarations.
fn collect_java_method_type_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    field_aliases: &[TypeAliasBinding],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut aliases_by_method = Vec::new();
    for method_node in collect_kinds(tree, &["method_declaration", "constructor_declaration"]) {
        // Start every method with the file's field aliases — fields are
        // visible throughout the method body.
        let mut method_aliases = field_aliases.to_vec();
        method_aliases.extend(collect_java_type_aliases(
            method_node,
            src,
            &[
                "formal_parameter",
                "local_variable_declaration",
                "enhanced_for_statement",
                // Try-with-resources binding `try (T r = expr)` — the
                // `resource` node exposes the same `type`/`name` fields,
                // so a JDBC `try (Statement s = ...)` yields `s: Statement`
                // and the receiver-type SQLi rule resolves.
                "resource",
            ],
        ));
        method_aliases.extend(collect_java_vertx_route_handler_aliases(method_node, src));
        method_aliases.extend(collect_java_webflux_route_handler_aliases(method_node, src));
        method_aliases.extend(collect_java_graphql_datafetcher_aliases(method_node, src));
        let method_type_bounds = java_type_parameter_bounds(method_node, src);
        expand_java_type_parameter_aliases(&mut method_aliases, &method_type_bounds);
        dedup_type_aliases(&mut method_aliases);
        aliases_by_method.push((span_of(file, &method_node), method_aliases));
    }
    aliases_by_method
}

type JavaTypeParameterBounds = Vec<(String, Vec<String>)>;

fn collect_java_class_type_parameter_bounds(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(Span, JavaTypeParameterBounds)> {
    collect_kinds(
        tree,
        &[
            "class_declaration",
            "interface_declaration",
            "record_declaration",
            "enum_declaration",
            "annotation_type_declaration",
        ],
    )
    .into_iter()
    .filter_map(|node| {
        let bounds = java_type_parameter_bounds(node, src);
        (!bounds.is_empty()).then(|| (span_of(file, &node), bounds))
    })
    .collect()
}

fn java_type_parameter_bounds(node: Node<'_>, src: &[u8]) -> JavaTypeParameterBounds {
    let Some(parameters) = node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut parameter_cursor = parameters.walk();
    for parameter in parameters.named_children(&mut parameter_cursor) {
        if parameter.kind() != "type_parameter" {
            continue;
        }
        let mut child_cursor = parameter.walk();
        let children = parameter.named_children(&mut child_cursor).collect::<Vec<_>>();
        let Some(name) = children
            .iter()
            .find(|child| child.kind() == "type_identifier")
            .map(|child| node_text(child, src).trim().to_string())
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let mut bounds = Vec::new();
        for bound in children.iter().filter(|child| child.kind() == "type_bound") {
            let mut bound_cursor = bound.walk();
            for bound_type in bound.named_children(&mut bound_cursor) {
                let text = node_text(&bound_type, src).trim();
                if !text.is_empty() && !bounds.iter().any(|existing| existing == text) {
                    bounds.push(text.to_string());
                }
            }
        }
        if !bounds.is_empty() {
            out.push((name, bounds));
        }
    }
    out
}

fn expand_java_type_parameter_aliases(aliases: &mut Vec<TypeAliasBinding>, bounds: &JavaTypeParameterBounds) {
    if aliases.is_empty() || bounds.is_empty() {
        return;
    }
    loop {
        let before = aliases.len();
        let current = aliases.clone();
        for alias in current {
            let alias_type = canonical_java_type_name(&alias.type_name)
                .unwrap_or_else(|| alias.type_name.trim().to_string());
            for (_, upper_bounds) in bounds.iter().filter(|(parameter, _)| parameter == &alias_type) {
                for upper_bound in upper_bounds {
                    if let Some(canonical) = canonical_java_type_name(upper_bound) {
                        let qualified = qualified_java_type_name(upper_bound);
                        push_java_type_alias(aliases, &alias.name, &canonical, qualified.as_deref());
                    }
                }
            }
        }
        dedup_type_aliases(aliases);
        if aliases.len() == before {
            break;
        }
    }
}

/// Vert.x route handlers commonly omit the lambda parameter type:
/// `router.get("/").handler(ctx -> ctx.request().getParam("q"))`.
/// The route API fixes that parameter to `RoutingContext`, so surface the
/// semantic alias for receiver-typed source/sink rules without loosening them
/// to every `.request().getParam(...)` chain in a Vert.x-importing file.
fn collect_java_vertx_route_handler_aliases(root: Node<'_>, src: &[u8]) -> Vec<TypeAliasBinding> {
    let mut aliases = Vec::new();
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        if node.kind() == "method_invocation" && java_is_vertx_route_handler_call(node, src) {
            if let Some(lambda) = java_first_lambda_argument(node) {
                if let Some(param) = java_first_lambda_param_name(lambda, src) {
                    push_type_alias(&mut aliases, &param, "io.vertx.ext.web.RoutingContext");
                    push_type_alias(&mut aliases, &param, "RoutingContext");
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            work_stack.push(child);
        }
    }
    aliases
}

fn java_is_vertx_route_handler_call(node: Node<'_>, src: &[u8]) -> bool {
    if node.child_by_field_name("name").map(|n| node_text(&n, src)) != Some("handler") {
        return false;
    }
    let Some(receiver) = node.child_by_field_name("object") else {
        return false;
    };
    if receiver.kind() != "method_invocation" {
        return false;
    }
    let Some(route_method) = receiver.child_by_field_name("name").map(|n| node_text(&n, src)) else {
        return false;
    };
    matches!(
        route_method,
        "route" | "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "connect" | "trace"
    )
}

/// Spring WebFlux functional routes also omit the request lambda type:
/// `route(GET("/"), req -> req.queryParam("q"))`. The handler parameter is a
/// `ServerRequest`, so make receiver-typed source rules precise without
/// matching arbitrary `.queryParam` helpers.
fn collect_java_webflux_route_handler_aliases(root: Node<'_>, src: &[u8]) -> Vec<TypeAliasBinding> {
    let mut aliases = Vec::new();
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        if node.kind() == "method_invocation"
            && node.child_by_field_name("name").map(|n| node_text(&n, src)) == Some("route")
        {
            if let Some(lambda) = java_first_lambda_argument(node) {
                if let Some(param) = java_first_lambda_param_name(lambda, src) {
                    push_type_alias(
                        &mut aliases,
                        &param,
                        "org.springframework.web.reactive.function.server.ServerRequest",
                    );
                    push_type_alias(&mut aliases, &param, "ServerRequest");
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            work_stack.push(child);
        }
    }
    aliases
}

fn java_first_lambda_argument(node: Node<'_>) -> Option<Node<'_>> {
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let lambda = args
        .named_children(&mut cursor)
        .find(|child| child.kind() == "lambda_expression");
    lambda
}

fn java_first_lambda_param_name(lambda: Node<'_>, src: &[u8]) -> Option<String> {
    let params = lambda.child_by_field_name("parameters")?;
    if params.kind() == "identifier" {
        let name = node_text(&params, src).trim();
        return (!name.is_empty()).then(|| name.to_string());
    }
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                let name = node_text(&child, src).trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
            "formal_parameter" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(&name_node, src).trim();
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// graphql-java `DataFetcher<T>` lambdas receive a
/// `DataFetchingEnvironment` parameter. The Java syntax often omits the
/// lambda parameter type, so infer it from the local declaration:
/// `DataFetcher<User> f = env -> env.getArgument("id")`.
fn collect_java_graphql_datafetcher_aliases(root: Node<'_>, src: &[u8]) -> Vec<TypeAliasBinding> {
    let mut aliases = Vec::new();
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        if node.kind() == "local_variable_declaration" {
            let declared_type = node
                .child_by_field_name("type")
                .map(|type_node| node_text(&type_node, src))
                .unwrap_or_default();
            if canonical_java_type_name(declared_type).as_deref() == Some("DataFetcher") {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() != "variable_declarator" {
                        continue;
                    }
                    let Some(value) = child.child_by_field_name("value") else {
                        continue;
                    };
                    if value.kind() == "lambda_expression" {
                        if let Some(param) = java_first_lambda_param_name(value, src) {
                            push_type_alias(&mut aliases, &param, "graphql.schema.DataFetchingEnvironment");
                            push_type_alias(&mut aliases, &param, "DataFetchingEnvironment");
                        }
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            work_stack.push(child);
        }
    }
    aliases
}

fn collect_java_graphql_datafetcher_lambda_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
    field_aliases: &[TypeAliasBinding],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let mut out = Vec::new();
    for decl in collect_kinds(tree, &["local_variable_declaration"]) {
        let declared_type = decl
            .child_by_field_name("type")
            .map(|type_node| node_text(&type_node, src))
            .unwrap_or_default();
        if canonical_java_type_name(declared_type).as_deref() != Some("DataFetcher") {
            continue;
        }
        let mut cursor = decl.walk();
        for child in decl.named_children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(value) = child.child_by_field_name("value") else {
                continue;
            };
            if value.kind() != "lambda_expression" {
                continue;
            }
            let Some(param) = java_first_lambda_param_name(value, src) else {
                continue;
            };
            let mut aliases = field_aliases.to_vec();
            push_type_alias(&mut aliases, &param, "graphql.schema.DataFetchingEnvironment");
            push_type_alias(&mut aliases, &param, "DataFetchingEnvironment");
            dedup_type_aliases(&mut aliases);
            out.push((span_of(file, &value), aliases));
        }
    }
    out
}

/// Walk `root` collecting `(name, type)` aliases from every declaration
/// node whose kind matches `kinds`. The result is deduplicated.
fn collect_java_type_aliases(root: Node<'_>, src: &[u8], kinds: &[&str]) -> Vec<TypeAliasBinding> {
    let mut aliases = Vec::new();
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        if kinds.contains(&node.kind()) {
            aliases.extend(java_type_aliases_from_decl(node, src));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            work_stack.push(child);
        }
    }
    expand_java_platform_supertypes(&mut aliases);
    dedup_type_aliases(&mut aliases);
    aliases
}

/// Pull every `(name, type)` binding out of a single declaration node —
/// handles both `Foo bar` (single name field) and `Foo a, b, c`
/// (multiple `variable_declarator` children).
fn java_type_aliases_from_decl(node: Node<'_>, src: &[u8]) -> Vec<TypeAliasBinding> {
    let Some(type_node) = node.child_by_field_name("type") else {
        return Vec::new();
    };
    let type_text = node_text(&type_node, src);
    let mut aliases = Vec::new();
    if let Some(canonical_type) = canonical_java_type_name(type_text) {
        let qualified_type = qualified_java_type_name(type_text);
        // Single-name declarations (most parameter shapes).
        if let Some(name_node) = node.child_by_field_name("name") {
            push_java_type_alias(
                &mut aliases,
                node_text(&name_node, src),
                &canonical_type,
                qualified_type.as_deref(),
            );
            return aliases;
        }
        // Multi-name `Foo a, b, c;` — one `variable_declarator` per name.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            if let Some(name_node) = child.child_by_field_name("name") {
                let name = node_text(&name_node, src);
                push_java_type_alias(&mut aliases, name, &canonical_type, qualified_type.as_deref());
                if let Some(value) = child.child_by_field_name("value") {
                    if java_secure_random_factory_init(value, src) {
                        push_java_type_alias(
                            &mut aliases,
                            name,
                            "SecureRandom",
                            Some("java.security.SecureRandom"),
                        );
                    }
                }
            }
        }
        return aliases;
    }
    // WS2: `var c = (Foo) make()` — the inferred (`var`) LHS carries no
    // class, so the type lives only on the cast initializer. Read the
    // declarator's `value` field directly (a cast nested in a call
    // argument must NOT mistype the local) and type the binding by it.
    if type_text.trim() == "var" {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let Some(value) = child.child_by_field_name("value") else {
                continue;
            };
            if let Some(cast_raw) = java_cast_type_of_init(value, src) {
                if let Some(canonical) = canonical_java_type_name(&cast_raw) {
                    let qualified = qualified_java_type_name(&cast_raw);
                    push_java_type_alias(
                        &mut aliases,
                        node_text(&name_node, src),
                        &canonical,
                        qualified.as_deref(),
                    );
                }
            }
        }
    }
    aliases
}

/// The cast type of a direct initializer (`(Foo) x` → `Foo`), unwrapping
/// redundant parentheses. Java has no `as`-cast, so only `cast_expression`
/// counts. Returns `None` for any other initializer shape so only a cast
/// that IS the initializer types the local.
fn java_cast_type_of_init(init: Node<'_>, src: &[u8]) -> Option<String> {
    let mut n = init;
    while n.kind() == "parenthesized_expression" {
        let mut cursor = n.walk();
        n = n.named_children(&mut cursor).next()?;
    }
    if n.kind() == "cast_expression" {
        return n
            .child_by_field_name("type")
            .map(|t| node_text(&t, src).to_string());
    }
    None
}

fn java_secure_random_factory_init(init: Node<'_>, src: &[u8]) -> bool {
    let text = node_text(&init, src);
    text.contains("SecureRandom.getInstance")
}

/// Canonicalize a Java type expression to its short, generics/array-free
/// form: `List<String>` → `List`, `int[]` → `int`, `java.util.Map` →
/// `Map`. Rejects names whose canonical form doesn't start with an
/// uppercase letter — primitives like `int` survive the strip but we
/// still want them out of the alias set.
fn canonical_java_type_name(raw: &str) -> Option<String> {
    // Strip generics and array brackets — they don't change the receiver type.
    let without_generics = raw.split('<').next().unwrap_or(raw);
    let without_arrays = without_generics.split('[').next().unwrap_or(without_generics);
    // Take the rightmost path segment as the bare type name.
    let bare_type = without_arrays
        .trim()
        .rsplit('.')
        .next()
        .unwrap_or(without_arrays)
        .trim();
    // Reject primitives and empty results — only class-like types qualify.
    if bare_type.is_empty() || !bare_type.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    Some(bare_type.to_string())
}

/// Preserve Java source-level fully-qualified class names as additional
/// receiver evidence for package-gated rules (`javax.naming.Foo x; x.bar()`).
/// Nested classes like `Outer.Inner` are intentionally ignored unless at least
/// one qualifier segment looks package-like.
fn qualified_java_type_name(raw: &str) -> Option<String> {
    let without_generics = raw.split('<').next().unwrap_or(raw);
    let without_arrays = without_generics.split('[').next().unwrap_or(without_generics);
    let qualified = without_arrays.trim();
    let mut parts = qualified.split('.').filter(|part| !part.is_empty()).peekable();
    parts.peek()?;
    let segments: Vec<&str> = parts.collect();
    if segments.len() < 2 {
        return None;
    }
    let tail = segments.last()?.trim();
    if tail.is_empty() || !tail.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let has_package_segment = segments[..segments.len() - 1]
        .iter()
        .any(|segment| segment.chars().next().is_some_and(|c| c.is_ascii_lowercase()));
    if !has_package_segment {
        return None;
    }
    Some(qualified.to_string())
}

fn push_java_type_alias(
    aliases: &mut Vec<TypeAliasBinding>,
    name: &str,
    canonical_type: &str,
    qualified_type: Option<&str>,
) {
    if let Some(qualified_type) = qualified_type.filter(|qualified| *qualified != canonical_type) {
        push_type_alias(aliases, name, qualified_type);
    }
    push_type_alias(aliases, name, canonical_type);
}

/// Append a type-alias binding to `aliases`, skipping empty names and
/// self-aliases (`Foo Foo`).
fn push_type_alias(aliases: &mut Vec<TypeAliasBinding>, name: &str, type_name: &str) {
    let bare_name = name.trim();
    if bare_name.is_empty() || bare_name == type_name {
        return;
    }
    aliases.push(TypeAliasBinding {
        name: bare_name.to_string(),
        type_name: type_name.to_string(),
    });
}

fn expand_java_platform_supertypes(aliases: &mut Vec<TypeAliasBinding>) {
    let original = aliases.clone();
    for alias in original {
        for supertype in java_platform_supertypes(&alias.type_name) {
            push_type_alias(aliases, &alias.name, supertype);
        }
    }
}

fn java_platform_supertypes(type_name: &str) -> &'static [&'static str] {
    match type_name {
        "CallableStatement" => &["PreparedStatement", "Statement"],
        "PreparedStatement" => &["Statement"],
        "Statement" => &[],
        "ArrayList" | "LinkedList" | "Vector" => &["List", "Collection", "Iterable"],
        "HashSet" | "LinkedHashSet" | "TreeSet" => &["Set", "Collection", "Iterable"],
        "HashMap" | "LinkedHashMap" | "TreeMap" => &["Map"],
        "List" | "Set" => &["Collection", "Iterable"],
        "Collection" => &["Iterable"],
        _ => &[],
    }
}

/// Drop duplicate `TypeAliasBinding` entries while preserving source-order.
fn dedup_type_aliases(aliases: &mut Vec<TypeAliasBinding>) {
    let mut deduped = Vec::new();
    for alias in aliases.drain(..) {
        if !deduped.contains(&alias) {
            deduped.push(alias);
        }
    }
    *aliases = deduped;
}

fn collect_java_imports(tree: &Tree, file: FileId, src: &[u8]) -> Vec<ImportSpec> {
    let mut imports: Vec<_> = collect_kinds(tree, &["import_declaration"])
        .into_iter()
        .filter_map(|import| java_import_spec(import, file, src))
        .collect();
    imports.sort_by_key(|import| import.span.start);
    imports
}

fn java_import_spec(import: Node<'_>, file: FileId, src: &[u8]) -> Option<ImportSpec> {
    let is_static = import
        .children(&mut import.walk())
        .any(|child| child.kind() == "static");
    let mut named_cursor = import.walk();
    let named_children: Vec<_> = import.named_children(&mut named_cursor).collect();
    let is_wildcard = named_children.iter().any(|child| child.kind() == "asterisk");
    let path_node = named_children
        .iter()
        .find(|child| matches!(child.kind(), "identifier" | "scoped_identifier"))?;
    let full_path = node_text(path_node, src).trim();
    if full_path.is_empty() {
        return None;
    }
    let (module, alias, original_name) = if is_static && !is_wildcard {
        let (owner, member) = full_path.rsplit_once('.')?;
        (
            owner.to_string(),
            Some(member.to_string()),
            Some(member.to_string()),
        )
    } else {
        (
            full_path.to_string(),
            (!is_wildcard).then(|| import_tail_binding(full_path)).flatten(),
            None,
        )
    };
    Some(ImportSpec {
        span: span_of(file, &import),
        module,
        alias,
        is_wildcard,
        original_name,
        scope: ImportScope::Module,
    })
}

fn import_tail_binding(module: &str) -> Option<String> {
    let tail = module
        .rsplit_once('.')
        .map(|(_, tail)| tail)
        .unwrap_or(module)
        .trim();
    (!tail.is_empty() && tail != module).then(|| tail.to_string())
}

/// Walk the Java tree and map each function/class/method/constructor
/// span to its real Visibility from `modifiers` siblings. Java
/// privacy rules:
///   - `public` → Public
///   - `private` → Private
///   - `protected` → Protected
///   - no modifier → package-private (Visibility::Module)
fn collect_java_visibility(
    root: Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<bonsai_common::Span, Visibility> {
    let mut visibility_by_span = std::collections::HashMap::new();
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        let kind = node.kind();
        let is_class_or_member_decl = matches!(
            kind,
            "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "annotation_type_declaration"
                | "record_declaration"
        );
        if is_class_or_member_decl {
            visibility_by_span.insert(span_of(file, &node), java_node_visibility(&node, src));
        }
        // Walk every child, named or not — modifiers are usually named but
        // `public`/`private` keyword tokens are anonymous.
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            work_stack.push(child);
        }
    }
    visibility_by_span
}

/// Read the `modifiers` child of a Java declaration to determine its
/// declared `Visibility`. No modifier means package-private (Module).
fn java_node_visibility(node: &Node<'_>, src: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        let mut modifier_cursor = child.walk();
        for modifier in child.children(&mut modifier_cursor) {
            match node_text(&modifier, src) {
                "public" => return Visibility::Public,
                "private" => return Visibility::Private,
                "protected" => return Visibility::Protected,
                _ => {}
            }
        }
    }
    // Java's default access is package-private — represented as Module
    // in the bonsai visibility lattice.
    Visibility::Module
}

/// Find the `package com.foo.bar;` declaration at the top of the
/// file and return its segments. Returns None for files in the
/// default (unnamed) package.
/// True for class-like decls whose `bases:` we should populate.
/// Java emits `interface_declaration`, `enum_declaration`,
/// `record_declaration`, `class_declaration`,
/// `annotation_type_declaration` — all surface as `DeclKind::Class`
/// at the kit's pass-3 (no separate Interface/Enum/Record kinds in
/// the kit's classification). See `kit.rs::class_nodes` pass 3.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

fn rewrite_java_explicit_constructor_invocations(index: &mut DeclIndex) {
    use std::collections::HashMap;

    let class_info: HashMap<bonsai_common::SymbolId, (String, Vec<String>)> = index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.symbol, (decl.name.clone(), decl.bases.clone())))
        .collect();

    for decl in &mut index.defs {
        if !matches!(decl.kind, DeclKind::Constructor) {
            continue;
        }
        let Some(parent) = decl.parent else {
            continue;
        };
        let Some((class_name, bases)) = class_info.get(&parent) else {
            continue;
        };
        let this_ctor = class_name.as_str();
        let super_ctor = bases.first().map(String::as_str);
        rewrite_java_explicit_constructor_invocations_in_events(&mut decl.flow_events, this_ctor, super_ctor);
    }
}

fn rewrite_java_explicit_constructor_invocations_in_events(
    events: &mut [FlowEvent],
    this_ctor: &str,
    super_ctor: Option<&str>,
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
                let replacement = match name.trim() {
                    "this" => Some((this_ctor, "this")),
                    "super" => super_ctor.map(|ctor| (ctor, "super")),
                    _ => None,
                };
                if let Some((replacement, replacement_receiver)) =
                    replacement.filter(|(replacement, _)| !replacement.is_empty())
                {
                    name.clear();
                    name.push_str(replacement);
                    *receiver = Some(replacement_receiver.to_string());
                    receiver_types.clear();
                    // Tree-sitter classifies `this(...)` / `super(...)` as
                    // `explicit_constructor_invocation`. Preserve that AST
                    // fact through HIR instead of disguising the edge as an
                    // ordinary receiver method call. Constructor identity is
                    // what lets the semantic resolver select the class-named
                    // declaration and lets the IDG carry receiver state
                    // through an inheritance chain.
                    *call_kind = bonsai_lang_api::CallKind::Constructor;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_java_explicit_constructor_invocations_in_events(then_events, this_ctor, super_ctor);
                rewrite_java_explicit_constructor_invocations_in_events(else_events, this_ctor, super_ctor);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_java_explicit_constructor_invocations_in_events(body, this_ctor, super_ctor);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_java_explicit_constructor_invocations_in_events(body, this_ctor, super_ctor);
                rewrite_java_explicit_constructor_invocations_in_events(catch_events, this_ctor, super_ctor);
                rewrite_java_explicit_constructor_invocations_in_events(
                    finally_events,
                    this_ctor,
                    super_ctor,
                );
            }
            FlowEvent::Assign { .. }
            | FlowEvent::AggregateAssign { .. }
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

/// Walk every Java class-like declaration and collect the
/// superclass + super_interfaces names. Java grammar:
///
///   `class C extends B implements I, J { ... }` →
///     superclass: (superclass (type_identifier))
///     interfaces: (super_interfaces (type_list (type_identifier) (type_identifier)))
///
/// `interface_declaration` uses `extends_interfaces` instead of
/// `superclass`. `record_declaration` only has `interfaces`.
fn collect_java_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut out = Vec::new();
    let class_kinds = &[
        "class_declaration",
        "interface_declaration",
        "record_declaration",
        "enum_declaration",
        "annotation_type_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        // `superclass` field — single parent.
        if let Some(sc) = class_node.child_by_field_name("superclass") {
            collect_java_base_names(sc, src, &mut bases);
        }
        // `interfaces` field — `super_interfaces` wrapping `type_list`.
        if let Some(ifaces) = class_node.child_by_field_name("interfaces") {
            collect_java_base_names(ifaces, src, &mut bases);
        }
        // `interface_declaration` carries `extends_interfaces`.
        if let Some(extends) = class_node.child_by_field_name("extends_interfaces") {
            collect_java_base_names(extends, src, &mut bases);
        }
        // `permits` clause from sealed classes. The matcher consults
        // Decl.bases for hierarchy resolution (e.g. `kind: param` rules
        // with `in_class:` constraints). For sealed types both
        // directions of the relationship are useful: the parent
        // declares which subtypes inherit, so emitting the permits
        // members lets cross-file rules that key on the ancestor
        // type still resolve through the sealed parent's permitted
        // subclass list.
        if let Some(permits) = class_node.child_by_field_name("permits") {
            collect_java_base_names(permits, src, &mut bases);
        }
        if !bases.is_empty() {
            out.push((span_of(file, &class_node), bases));
        }
    }
    out
}

fn collect_java_class_string_constants(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<FlowEvent>)> {
    let class_kinds = &[
        "class_declaration",
        "interface_declaration",
        "record_declaration",
        "enum_declaration",
        "annotation_type_declaration",
    ];
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let Some(body) = class_node.child_by_field_name("body") else {
            continue;
        };
        let mut events = Vec::new();
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            if child.kind() == "field_declaration" {
                collect_java_final_string_field_assigns(child, file, src, &mut events);
            }
        }
        if !events.is_empty() {
            out.push((span_of(file, &class_node), events));
        }
    }
    out
}

fn collect_java_final_string_field_assigns(
    field: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<FlowEvent>,
) {
    if !java_field_has_modifier(field, src, "final") || !java_field_type_is_string(field, src) {
        return;
    }
    let mut cursor = field.walk();
    for child in field.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let Some(value_node) = child.child_by_field_name("value") else {
            continue;
        };
        if value_node.kind() != "string_literal" {
            continue;
        }
        out.push(FlowEvent::Assign {
            span: span_of(file, &child),
            target: node_text(&name_node, src).trim().to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(AssignValueKind::Literal),
        });
    }
}

fn java_field_has_modifier(field: Node<'_>, src: &[u8], wanted: &str) -> bool {
    let mut cursor = field.walk();
    for child in field.named_children(&mut cursor) {
        if child.kind() != "modifiers" {
            continue;
        }
        if node_text(&child, src)
            .split_ascii_whitespace()
            .any(|modifier| modifier == wanted)
        {
            return true;
        }
    }
    false
}

fn java_field_type_is_string(field: Node<'_>, src: &[u8]) -> bool {
    let Some(type_node) = field.child_by_field_name("type") else {
        return false;
    };
    matches!(
        canonical_java_type_name(node_text(&type_node, src)).as_deref(),
        Some("String")
    )
}

fn attach_java_class_string_constants(
    index: &mut DeclIndex,
    constants_by_class: &[(bonsai_common::Span, Vec<FlowEvent>)],
) {
    if constants_by_class.is_empty() {
        return;
    }
    let parent_by_symbol: std::collections::HashMap<_, _> = index
        .defs
        .iter()
        .filter_map(|decl| Some((decl.symbol, decl.parent?)))
        .collect();
    let class_symbol_by_span: std::collections::HashMap<_, _> = index
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.symbol))
        .collect();
    let constants_by_symbol: std::collections::HashMap<_, _> = constants_by_class
        .iter()
        .filter_map(|(span, events)| {
            class_symbol_by_span
                .get(span)
                .copied()
                .map(|symbol| (symbol, events))
        })
        .collect();

    for decl in &mut index.defs {
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let mut ancestors = Vec::new();
        let mut parent = decl.parent;
        while let Some(symbol) = parent {
            ancestors.push(symbol);
            parent = parent_by_symbol.get(&symbol).copied();
        }
        if ancestors.is_empty() {
            continue;
        }

        let mut visible_constants = Vec::new();
        for symbol in ancestors.into_iter().rev() {
            if let Some(events) = constants_by_symbol.get(&symbol) {
                visible_constants.extend((*events).iter().cloned());
            }
        }
        visible_constants.retain(|event| {
            let FlowEvent::Assign { target, .. } = event else {
                return false;
            };
            !decl.params.iter().any(|param| param == target)
                && !decl
                    .flow_events
                    .iter()
                    .any(|event| flow_event_assigns_target(event, target))
        });
        if !visible_constants.is_empty() {
            visible_constants.extend(std::mem::take(&mut decl.flow_events));
            decl.flow_events = visible_constants;
        }
    }
}

fn flow_event_assigns_target(event: &FlowEvent, wanted: &str) -> bool {
    match event {
        FlowEvent::Assign { target, .. } => target == wanted,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            then_events
                .iter()
                .any(|event| flow_event_assigns_target(event, wanted))
                || else_events
                    .iter()
                    .any(|event| flow_event_assigns_target(event, wanted))
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            body.iter().any(|event| flow_event_assigns_target(event, wanted))
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            body.iter().any(|event| flow_event_assigns_target(event, wanted))
                || catch_events
                    .iter()
                    .any(|event| flow_event_assigns_target(event, wanted))
                || finally_events
                    .iter()
                    .any(|event| flow_event_assigns_target(event, wanted))
        }
        _ => false,
    }
}

/// Pull every `type_identifier` / `scoped_type_identifier` /
/// `generic_type` descendant of a Java parent-clause node and push
/// the canonical short name into `out`. Skips internal punctuation
/// nodes.
fn collect_java_base_names(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "type_identifier" | "scoped_type_identifier" | "generic_type" => {
                if let Some(name) = canonical_java_type_name(node_text(&n, src)) {
                    if !out.iter().any(|b| b == &name) {
                        out.push(name);
                    }
                }
            }
            _ => {}
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Walk `decl.flow_events` recursively and populate
/// `Throw::thrown_type` / `Try::catch_types` from the Java parse
/// tree by span lookup. Java syntax:
///   throw new IOException("...")  → thrown_type: "IOException"
///   throw err                     → thrown_type: None (need data-flow)
///   `try { } catch (IOException e) { } catch (A | B e) { }`
///                                 → `catch_types = vec!["IOException", "A", "B"]`
fn populate_java_exception_types(events: &mut [bonsai_lang_api::FlowEvent], tree: &Tree, src: &[u8]) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Throw {
                span, thrown_type, ..
            } => {
                if thrown_type.is_some() {
                    continue;
                }
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["throw_statement"])
                {
                    if let Some(name) = java_thrown_type_for_node(node, src) {
                        *thrown_type = Some(name);
                    }
                }
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_types,
                catch_param,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if catch_types.is_empty() {
                        *catch_types = collect_java_catch_types(node, src);
                    }
                    // The kit's generic catch_param extractor sometimes
                    // picks the type identifier instead of the variable
                    // name on Java's `catch (T name)` shape. Fix in the
                    // adapter where we have the structural context.
                    if let Some(name) = collect_java_catch_param_name(node, src) {
                        *catch_param = Some(name);
                    }
                }
                populate_java_exception_types(body, tree, src);
                populate_java_exception_types(catch_events, tree, src);
                populate_java_exception_types(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                populate_java_exception_types(then_events, tree, src);
                populate_java_exception_types(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                populate_java_exception_types(body, tree, src);
            }
            _ => {}
        }
    }
}

fn java_thrown_type_for_node(throw_node: Node<'_>, src: &[u8]) -> Option<String> {
    // throw_statement > object_creation_expression > type_identifier (or generic_type)
    let mut cursor = throw_node.walk();
    for child in throw_node.named_children(&mut cursor) {
        if child.kind() == "object_creation_expression" {
            if let Some(t) = child.child_by_field_name("type") {
                return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                    &t, src,
                )));
            }
            // Fallback: walk for first type_identifier descendant.
            let mut tcur = child.walk();
            for descendant in child.named_children(&mut tcur) {
                if matches!(
                    descendant.kind(),
                    "type_identifier" | "generic_type" | "scoped_type_identifier"
                ) {
                    return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                        &descendant,
                        src,
                    )));
                }
            }
        }
    }
    None
}

fn collect_java_catch_param_name(try_node: Node<'_>, src: &[u8]) -> Option<String> {
    // Java's `catch (T name)` parses as:
    //   catch_clause
    //     catch_formal_parameter
    //       <modifiers>?
    //       catch_type
    //         type_identifier
    //       name: identifier
    // We want the `name` field of the catch_formal_parameter.
    let mut cursor = try_node.walk();
    for child in try_node.named_children(&mut cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        let mut ccur = child.walk();
        for sub in child.named_children(&mut ccur) {
            if sub.kind() != "catch_formal_parameter" {
                continue;
            }
            if let Some(n) = sub.child_by_field_name("name") {
                return Some(node_text(&n, src).trim().to_string());
            }
            // Fallback: rightmost `identifier` (after the type).
            let mut pcur = sub.walk();
            let mut last_ident: Option<Node<'_>> = None;
            for ptype in sub.named_children(&mut pcur) {
                if ptype.kind() == "identifier" {
                    last_ident = Some(ptype);
                }
            }
            if let Some(n) = last_ident {
                return Some(node_text(&n, src).trim().to_string());
            }
        }
    }
    None
}

fn collect_java_catch_types(try_node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cursor = try_node.walk();
    for child in try_node.named_children(&mut cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        // catch_clause > catch_formal_parameter > catch_type > type_identifier (one or more)
        let mut ccur = child.walk();
        for sub in child.named_children(&mut ccur) {
            if sub.kind() != "catch_formal_parameter" {
                continue;
            }
            let mut pcur = sub.walk();
            for ptype in sub.named_children(&mut pcur) {
                if ptype.kind() == "catch_type" {
                    let mut tcur = ptype.walk();
                    for t in ptype.named_children(&mut tcur) {
                        if matches!(
                            t.kind(),
                            "type_identifier" | "generic_type" | "scoped_type_identifier"
                        ) {
                            let name = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&t, src));
                            if !name.is_empty() && !out.iter().any(|x| x == &name) {
                                out.push(name);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Rewrite Java's reflection chain `Class.forName("X").getMethod("Y")
/// .invoke(target, args...)` into a synthesized direct call to
/// `X.Y(args...)` so the resolver narrows it like a normal method
/// dispatch. Walks `flow_events` in source order, building an alias
/// map of `var → "Class"` and `var → "Class.Method"` entries from
/// constant-string `forName` / `getMethod` calls. When it sees
/// `m.invoke(target, ...args)` where `m` resolves to a known
/// "Class.Method", rewrites the Call's `name` to that target and
/// drops the leading `target` (or `null`) arg so the remaining args
/// align with the real method's parameters.
///
/// Dynamic forms (computed string args) stay unrewritten and the
/// `reflection: Unsupported` rule continues to gate them at rulepack
/// load time. This is the Java analog of P2.1's Python rewrite.
fn rewrite_java_reflection_chain(events: &mut [bonsai_lang_api::FlowEvent]) {
    use bonsai_lang_api::FlowEvent;
    use std::collections::HashMap;
    // var name -> what it points at, accumulated across the walk:
    //   "c" -> "Sink"        (after `Class<?> c = Class.forName("Sink")`)
    //   "m" -> "Sink.run"    (after `Method m = c.getMethod("run", ...)`)
    let mut reflective_alias: HashMap<String, String> = HashMap::new();
    for event in events.iter_mut() {
        match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_call_args,
                ..
            } => {
                // Only the constant-string forms are usable; the second
                // arg / dynamic forms stay unrewritten.
                let Some(callee) = source_call else { continue };
                let Some(literal_arg) = source_call_args.first() else {
                    continue;
                };
                let Some(literal_text) = strip_java_string_quotes(literal_arg) else {
                    continue;
                };
                // `Class.forName("X")` — record `target -> "X"`.
                let is_for_name = callee == "Class.forName" || callee.ends_with(".forName");
                if is_for_name {
                    reflective_alias.insert(target.clone(), literal_text);
                    continue;
                }
                // `<receiver>.getMethod("Y")` — chain only if receiver
                // is itself a Class<?> we tracked. Result: `target ->
                // "<receiver-class>.Y"`.
                if let Some(get_method_receiver) = callee.strip_suffix(".getMethod") {
                    if let Some(class_name) = reflective_alias.get(get_method_receiver) {
                        let chained = format!("{class_name}.{literal_text}");
                        reflective_alias.insert(target.clone(), chained);
                    }
                }
            }
            FlowEvent::Call {
                name, receiver, args, ..
            } => {
                // `<receiver>.invoke(target_or_null, arg1, ..)` is the
                // Java reflection escape hatch. Rewrite when the
                // receiver was bound to a known Method handle.
                let Some(receiver_name) = receiver.as_deref() else {
                    continue;
                };
                if !name.ends_with(".invoke") {
                    continue;
                }
                let Some(target_class_method) = reflective_alias.get(receiver_name) else {
                    continue;
                };
                // Rewrite the call to point at the underlying method.
                name.clone_from(target_class_method);
                // `m.invoke(target, a, b)` ⇒ `Class.Method(a, b)`:
                // drop the first arg (the receiver / `null` static
                // target) so the remaining args line up with the real
                // method's parameter list.
                if !args.is_empty() {
                    args.remove(0);
                }
                // Update `receiver` to the class part of the qualified
                // name, e.g. "Sink.run" -> Some("Sink"). The resolver
                // uses this to anchor the dispatch.
                *receiver = target_class_method
                    .rsplit_once('.')
                    .map(|(class_part, _)| class_part.to_string());
            }
            // Reflection chains can hide inside any control-flow
            // container — keep walking.
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_java_reflection_chain(then_events);
                rewrite_java_reflection_chain(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_java_reflection_chain(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_java_reflection_chain(body);
                rewrite_java_reflection_chain(catch_events);
                rewrite_java_reflection_chain(finally_events);
            }
            _ => {}
        }
    }
}

/// Strip surrounding `"..."` quotes from a Java string-literal arg-text
/// representation, returning the inner content. Returns `None` for any
/// non-literal form (variable, expression, single-quoted char, etc.).
fn strip_java_string_quotes(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        return Some(trimmed[1..trimmed.len() - 1].to_string());
    }
    None
}

fn extract_java_package(root: Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "package_declaration" {
            continue;
        }
        // package_declaration's `name` child is a `scoped_identifier`
        // (or bare `identifier` for single-segment packages).
        let mut sub = child.walk();
        for subchild in child.children(&mut sub) {
            if matches!(subchild.kind(), "scoped_identifier" | "identifier") {
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
