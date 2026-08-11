//! Function-parameter extraction shared by every adapter.
//!
//! Adapters report a function's parameter list via `Decl.params` (a
//! `Vec<String>` of bare parameter names) and `Decl.param_annotations`
//! (parallel-indexed `Vec<Vec<String>>` of annotation/decorator names
//! per parameter). The kit's default extractors here cover the common
//! tree-sitter shapes:
//!
//! - typed_parameter / typed_default_parameter (Python)
//! - formal_parameter (Java/Kotlin/C#)
//! - parameter (JS/TS/Go/Swift)
//! - simple_parameter / variadic_parameter (PHP)
//! - parameters list traversal for languages with no `parameters` field
//!
//! Adapters with non-default parameter shapes (Perl `my ($a, $b) = @_;`
//! patterns; Erlang head-match patterns; Ruby/Elixir keyword args) do
//! the work in their own `decl_index` post-processing step rather than
//! extending the kit's default.
//!
//! Annotation extraction covers the Java/Kotlin/C# pattern of
//! `formal_parameter > modifiers > marker_annotation / annotation`.
//! Language-specific parameter forms are handled in the owning adapter's
//! post-processing and lowered as API-neutral facts. For example, Python
//! records a direct parameter-default call without interpreting its callee as
//! a framework binder.

use tree_sitter::Node;

use super::{extract_direct_call_info, node_text, short_name_of, GrammarHandler, SYNTHETIC_VARARGS_PARAM};

/// Locate the active grammar's parsed parameter container without carrying a
/// union of other languages' node kinds in shared lowering. Tree-sitter field
/// names are tried first; the bounded structural walk then selects only a kind
/// explicitly declared by the adapter and never enters a callable body.
pub(super) fn parameter_container<'tree>(
    fn_node: &Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    for field in ["parameters", "args", "parameter"] {
        if let Some(node) = fn_node.child_by_field_name(field) {
            return Some(node);
        }
    }
    let mut pending: Vec<(Node<'tree>, u8)> = Vec::new();
    let mut cursor = fn_node.walk();
    let mut direct_children: Vec<Node<'tree>> = fn_node.named_children(&mut cursor).collect();
    direct_children.reverse();
    pending.extend(direct_children.into_iter().map(|child| (child, 0_u8)));
    while let Some((node, depth)) = pending.pop() {
        if handler.parameter_container_kinds.contains(&node.kind()) {
            return Some(node);
        }
        if depth >= 4
            || handler.fn_kinds.contains(&node.kind())
            || handler.lambda_kinds.contains(&node.kind())
            // A parameter type may itself contain a callable signature
            // (Objective-C block pointers are one example). Its nested
            // parameter list belongs to the type, not to the enclosing
            // function, so it cannot be the outer declaration's container.
            || handler.parameter_kinds.contains(&node.kind())
            || handler.keyword_parameter_kinds.contains(&node.kind())
        {
            continue;
        }
        for index in (0..node.child_count()).rev() {
            let Ok(index) = u32::try_from(index) else {
                continue;
            };
            let Some(child) = node.child(index).filter(Node::is_named) else {
                continue;
            };
            if matches!(node.field_name_for_child(index), Some("body" | "block")) {
                continue;
            }
            pending.push((child, depth + 1));
        }
    }
    None
}

/// Per-parameter annotation/decorator names, parallel-indexed with
/// `extract_param_names`.
///
/// Each inner `Vec<String>` is the list of annotation child names attached
/// to the corresponding parameter (Java `@RequestParam String x` →
/// `["RequestParam"]`). The inner vec is empty for params without
/// annotations and for grammars/adapters that don't surface the shape.
///
/// Default coverage: Java/Kotlin/C# `formal_parameter > modifiers >
/// marker_annotation / annotation`. ObjC selector pieces
/// (`openURL:options:`) are surfaced as pseudo-annotations so rules can
/// match by selector piece. Adapters that need custom shapes override.
pub fn extract_param_annotations(
    fn_node: &Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<Vec<String>> {
    let mut per_param_annotations: Vec<Vec<String>> = Vec::new();
    // Reusable per-param visitor: collects every annotation name into a
    // fresh inner vec, sorts/dedups, and appends.
    let visit_param = |param: Node<'_>, into: &mut Vec<Vec<String>>| {
        let mut annotation_names: Vec<String> = Vec::new();
        // Annotations may live under a wrapper node (Java `modifiers`,
        // Kotlin `annotation_list`, C# `attribute_list`) or directly on
        // the param.
        let mut annotation_search_roots: Vec<Node<'_>> = Vec::new();
        let mut cursor = param.walk();
        for child in param.named_children(&mut cursor) {
            if handler.parameter_modifier_kinds.contains(&child.kind()) {
                annotation_search_roots.push(child);
            } else if handler.parameter_annotation_kinds.contains(&child.kind()) {
                // TypeScript and several C-family grammars place parameter
                // decorators directly beside the name/type rather than in a
                // wrapper. Keep those exact syntax nodes while still
                // excluding unrelated default-value expressions.
                annotation_search_roots.push(child);
            }
        }
        // Typed parameters may carry annotation metadata directly inside the
        // grammar's `type` field (for example Python
        // `Annotated[Payload, Body()]`). Search that field rather than the
        // whole parameter so a default expression such as `q = Query(...)`
        // is not duplicated into `param_annotations`; direct default calls
        // have their own parallel compiler fact.
        if annotation_search_roots.is_empty() {
            if let Some(type_node) = param.child_by_field_name("type") {
                annotation_search_roots.push(type_node);
            }
        }
        // Fall back to scanning the param itself when no wrapper exists.
        if annotation_search_roots.is_empty() {
            annotation_search_roots.push(param);
        }
        for root in annotation_search_roots {
            collect_param_annotation_names(root, src, handler, &mut annotation_names);
        }
        annotation_names.sort();
        annotation_names.dedup();
        into.push(annotation_names);
    };
    // Some grammars (Go method receivers) put one parameter under a
    // `receiver` field instead of in the main parameter list — visit it
    // first so its annotation slot lines up with index 0.
    if let Some(receiver) = fn_node.child_by_field_name("receiver") {
        let mut cursor = receiver.walk();
        let mut visited_named_child = false;
        for param in receiver.named_children(&mut cursor) {
            visited_named_child = true;
            visit_param(param, &mut per_param_annotations);
        }
        // Receiver itself is the param when no nested children exist.
        if !visited_named_child {
            visit_param(receiver, &mut per_param_annotations);
        }
    }
    // Locate the parameter container — every grammar uses a different
    // field/kind name, so we try them in the order most likely to match.
    let parameters_container = parameter_container(fn_node, handler);
    if let Some(parameters_container) = parameters_container {
        let mut cursor = parameters_container.walk();
        let mut pending_annotations: Vec<String> = Vec::new();
        for param in parameters_container.named_children(&mut cursor) {
            if handler.parameter_modifier_kinds.contains(&param.kind()) {
                collect_param_annotation_names(param, src, handler, &mut pending_annotations);
                continue;
            }
            visit_param(param, &mut per_param_annotations);
            if let Some(annotations) = per_param_annotations.last_mut() {
                annotations.append(&mut pending_annotations);
                annotations.sort();
                annotations.dedup();
            }
        }
    }
    // Objective-C's flat declaration shape puts each parameter directly
    // under the function. Track the previously-seen
    // identifier so ObjC method_parameter siblings inherit their
    // selector piece as a pseudo-annotation.
    if parameters_container.is_none() {
        let mut cursor = fn_node.walk();
        let mut previous_identifier_text: Option<String> = None;
        for child in fn_node.named_children(&mut cursor) {
            if handler.parameter_kinds.contains(&child.kind()) {
                if handler.last_identifier_parameter_kinds.contains(&child.kind()) {
                    // ObjC method param — its selector piece is the
                    // identifier immediately preceding it (`openURL` →
                    // applies to the next method_parameter).
                    let mut selector_annotations = Vec::new();
                    if let Some(selector_piece) = previous_identifier_text.clone() {
                        selector_annotations.push(selector_piece);
                    }
                    per_param_annotations.push(selector_annotations);
                } else {
                    visit_param(child, &mut per_param_annotations);
                }
            }
            if handler.parameter_selector_kinds.contains(&child.kind()) {
                let identifier_text = node_text(&child, src).trim().trim_end_matches(':').to_string();
                if !identifier_text.is_empty() {
                    previous_identifier_text = Some(identifier_text);
                }
            }
        }
    }
    // ObjC: `application:openURL:options:` parses as a sequence of
    // `keyword_argument` siblings under the method_definition. Record the
    // selector piece (`openURL`) as an annotation so rules can match by
    // selector piece.
    let mut cursor = fn_node.walk();
    for child in fn_node.named_children(&mut cursor) {
        if !handler.keyword_parameter_kinds.contains(&child.kind()) {
            continue;
        }
        let mut selector_piece: Option<String> = None;
        let mut piece_cursor = child.walk();
        for piece_child in child.named_children(&mut piece_cursor) {
            if handler.parameter_selector_kinds.contains(&piece_child.kind()) {
                let piece_text = node_text(&piece_child, src)
                    .trim()
                    .trim_end_matches(':')
                    .to_string();
                if !piece_text.is_empty() {
                    selector_piece = Some(piece_text);
                    break;
                }
            }
        }
        let mut piece_annotations: Vec<String> = Vec::new();
        if let Some(piece) = selector_piece {
            piece_annotations.push(piece);
        }
        per_param_annotations.push(piece_annotations);
    }
    per_param_annotations
}

/// Walk `root` collecting annotation/decorator/attribute names. Stops
/// recursing into a matched annotation node so we don't double-count nested
/// arguments (e.g. `@MyAnn(@Other)`).
fn collect_param_annotation_names(
    root: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
    collected_names: &mut Vec<String>,
) {
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        // Recognized annotation node — pull out its name and stop recursing.
        if handler.parameter_annotation_kinds.contains(&node.kind()) {
            let direct_name = handler
                .parameter_annotation_name_extractor
                .and_then(|extract| extract(node, src))
                .or_else(|| {
                    node.child_by_field_name("name")
                        .or_else(|| first_identifier_descendant_for_handler(node, handler))
                        .map(|name_node| node_text(&name_node, src).trim().to_string())
                        .filter(|name| !name.is_empty())
                });
            let constructor_name = direct_name.or_else(|| {
                // Some grammars wrap annotation syntax around a constructor
                // call whose type identifier is intentionally not a value
                // identifier (Kotlin is one example). Follow only the first
                // adapter-classified call below the annotation and let the
                // adapter's call-target extractor identify its parsed name.
                let mut pending = Vec::new();
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                pending.extend(children);
                while let Some(candidate) = pending.pop() {
                    if handler.is_call(candidate.kind()) {
                        return extract_direct_call_info(&candidate, src, handler)
                            .and_then(|(callee, _)| callee)
                            .map(|callee| short_name_of(&callee).to_string());
                    }
                    if handler.parameter_annotation_kinds.contains(&candidate.kind()) {
                        continue;
                    }
                    let mut cursor = candidate.walk();
                    let mut children = candidate.named_children(&mut cursor).collect::<Vec<_>>();
                    children.reverse();
                    pending.extend(children);
                }
                None
            });
            if let Some(annotation_name) = constructor_name {
                collected_names.push(annotation_name);
            }
            continue;
        }
        // Some grammars (Python decorators) emit annotations as call expressions
        // like `@RequestParam(...)`. Pull the leading callee name.
        if handler.is_call(node.kind()) {
            if let Some((Some(callee_path), _)) = extract_direct_call_info(&node, src, handler) {
                let bare_callee = short_name_of(&callee_path).trim_start_matches('@').to_string();
                if !bare_callee.is_empty() {
                    collected_names.push(bare_callee);
                }
            }
            // The call itself is the annotation metadata. Its receiver path
            // and arguments are ordinary expressions, not additional
            // annotations (`Annotated[T, framework.Metadata(...)]` must emit
            // `Metadata`, not `framework` or nested argument call names).
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            work_stack.push(child);
        }
    }
}

/// Extract the bare parameter names of a function/method declaration in
/// source order. Output indices are aligned with `extract_param_annotations`.
///
/// Walks three structurally-distinct shapes:
///   1. Receiver-as-field (Go: `func (r *T) m()`).
///   2. Parameter container (Python `parameters`, Java `formal_parameters`, ...).
///   3. Flat siblings of the function node (Objective-C selectors).
pub(super) fn extract_param_names(fn_node: &Node<'_>, src: &[u8], handler: &GrammarHandler) -> Vec<String> {
    let mut param_names = Vec::new();
    // Receivers come first so their slot is index 0.
    if let Some(receiver) = fn_node.child_by_field_name("receiver") {
        let mut cursor = receiver.walk();
        let mut visited_named_child = false;
        for param in receiver.named_children(&mut cursor) {
            visited_named_child = true;
            push_param_name(param, src, handler, &mut param_names);
        }
        // Receiver itself is the param when no nested children exist.
        if !visited_named_child {
            push_param_name(receiver, src, handler, &mut param_names);
        }
    }
    // Most languages wrap params in a single container node; the lookup
    // tries every known field/kind name, falling back to a declarator
    // chain for C-family grammars and an `arguments` child for Elixir.
    let parameters_container = parameter_container(fn_node, handler);
    if let Some(parameters_container) = parameters_container {
        // C# implicit single-parameter lambda `x => body`: the
        // `parameters` field is a lone `implicit_parameter` leaf whose
        // TEXT is the name, not a list and not an `identifier`-kind node
        // that `push_param_name` recognises — take its text directly.
        if handler
            .implicit_parameter_kinds
            .contains(&parameters_container.kind())
        {
            let text = node_text(&parameters_container, src).trim();
            if !text.is_empty() {
                param_names.push(text.to_string());
            }
        } else if handler.identifier_kinds.contains(&parameters_container.kind()) {
            push_param_name(parameters_container, src, handler, &mut param_names);
        } else {
            let mut cursor = parameters_container.walk();
            for param in parameters_container.named_children(&mut cursor) {
                if handler.parameter_modifier_kinds.contains(&param.kind()) {
                    continue;
                }
                push_param_name(param, src, handler, &mut param_names);
            }
        }
        // C/C++ represent a bare variadic collector as the anonymous `...`
        // terminal of `parameter_list`. Read that direct grammar token;
        // never scan or split the surrounding source declaration.
        let mut cursor = parameters_container.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if !child.is_named()
                    && handler
                        .anonymous_variadic_token
                        .is_some_and(|token| node_text(&child, src).trim() == token)
                {
                    if !param_names.iter().any(|name| name == SYNTHETIC_VARARGS_PARAM) {
                        param_names.push(SYNTHETIC_VARARGS_PARAM.to_string());
                    }
                    break;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    // Flat-shape grammars such as Objective-C emit parameter nodes as direct
    // siblings of the function and have no parameter container. Once a
    // container exists it is the exact syntax boundary: scanning its sibling
    // declaration name as though it were a bare parameter corrupts positional
    // identity in grammars where both nodes share an identifier kind.
    if parameters_container.is_none() {
        let mut cursor = fn_node.walk();
        for child in fn_node.named_children(&mut cursor) {
            if handler.parameter_kinds.contains(&child.kind()) {
                push_param_name(child, src, handler, &mut param_names);
            }
        }
    }
    // ObjC: each `keyword_argument` sibling holds the bound parameter
    // identifier (`(NSURL *)url` after `openURL:`). Mirror the walk done
    // in extract_param_annotations so params + param_annotations stay
    // parallel-indexed.
    let mut cursor = fn_node.walk();
    for child in fn_node.named_children(&mut cursor) {
        if !handler.keyword_parameter_kinds.contains(&child.kind()) {
            continue;
        }
        let mut bound_name: Option<String> = None;
        let mut piece_cursor = child.walk();
        for piece_child in child.named_children(&mut piece_cursor) {
            if handler.parameter_kinds.contains(&piece_child.kind()) {
                if let Some(name_node) = piece_child
                    .child_by_field_name("name")
                    .or_else(|| first_identifier_descendant_for_handler(piece_child, handler))
                {
                    let name_text = node_text(&name_node, src).trim().to_string();
                    if !name_text.is_empty() {
                        bound_name = Some(name_text);
                        break;
                    }
                }
            }
        }
        // Push even when no bound name found — we need the empty slot to
        // keep parameter-index alignment with annotations.
        param_names.push(bound_name.unwrap_or_default());
    }
    param_names
}

/// Push a single parameter's name onto `out`, handling:
///   * bare identifier params (Python `def f(x):`)
///   * typed params with `name` field (C#/Go/Swift/...)
///   * C-style `parameter_declaration > declarator > ... > identifier`
///     (C, C++, Objective-C type+pointer declarators)
///   * params with an identifier-like child (fallback)
///
/// Filters out sigil-only entries that are syntax noise rather than
/// meaningful parameter bindings. Receiver parameters stay in the
/// vector and are identified separately via adapter metadata.
/// Append a single parameter's bare name to `into`, handling the four
/// shapes the kit's default extractor sees:
///   * bare identifier params (Python `def f(x):`)
///   * typed params with a `name` field (C#/Go/Swift/Kotlin/...)
///   * C-style `parameter_declaration > declarator > ... > identifier`
///     (C, C++, Objective-C type+pointer declarators)
///   * params whose only child is identifier-shaped (fallback)
///
/// Receiver parameters stay in the vector — they're identified separately
/// via `Decl.receiver_param_index`, not by string-matching `self`/`this`.
fn push_param_name(param: Node<'_>, src: &[u8], handler: &GrammarHandler, param_names: &mut Vec<String>) {
    if handler.self_parameter_kinds.contains(&param.kind()) {
        // Receiver modifiers (`&self`, `&mut self`) are type/borrowing
        // syntax, not part of the binding identity. The adapter has declared
        // this exact grammar kind as a self parameter, so select its parsed
        // binding identifier and use the whole node only for grammars that
        // expose no such child.
        let name_node = first_identifier_descendant_for_handler(param, handler).unwrap_or(param);
        let name = node_text(&name_node, src).trim();
        if !name.is_empty() {
            param_names.push(name.to_string());
        }
        return;
    }

    let repeated_field_names = repeated_named_field_values(param, src, "name", handler);
    if repeated_field_names.len() > 1 {
        param_names.extend(repeated_field_names);
        return;
    }

    // JS destructured params sit directly in the parameter list while TS
    // wraps them in a `required_parameter`. Walk the parsed pattern nodes;
    // property keys, default expressions, and type annotations are excluded
    // by CST fields rather than by tokenizing the pattern's source text.
    let mut pattern_node = param;
    if let Some(left) = pattern_node.child_by_field_name("left") {
        pattern_node = left;
    }
    if handler
        .destructured_parameter_kinds
        .contains(&pattern_node.kind())
    {
        let pattern_bindings = binding_names_from_pattern(pattern_node, src, handler);
        if !pattern_bindings.is_empty() {
            param_names.extend(pattern_bindings);
            return;
        }
    }

    // Bare identifier params: the param node itself carries the name.
    let bare_identifier_text = if handler.binding_identifier_kinds.contains(&param.kind()) {
        Some(node_text(&param, src).to_string())
    } else {
        None
    };
    // C-style declarator chain: `parameter_declaration.declarator` may
    // be a `pointer_declarator`/`array_declarator` wrapping the real
    // identifier. Walk every declarator field down to the innermost
    // identifier so we don't grab the type name (`NSString`) instead.
    let declarator_chain_name = {
        let mut current_declarator = param.child_by_field_name("declarator");
        let mut innermost_identifier: Option<Node<'_>> = None;
        while let Some(declarator_node) = current_declarator {
            if handler.binding_identifier_kinds.contains(&declarator_node.kind()) {
                innermost_identifier = Some(declarator_node);
                break;
            }
            if let Some(nested) = declarator_node.child_by_field_name("declarator") {
                current_declarator = Some(nested);
            } else {
                // Last declarator level — fall back to a DFS for any
                // identifier descendant.
                innermost_identifier = first_identifier_descendant_for_handler(declarator_node, handler);
                break;
            }
        }
        innermost_identifier
    };
    // ObjC method_parameter wraps `(Type)name` — the bound name is the
    // last identifier by source position, since the type identifier
    // appears earlier in the subtree.
    let method_param_bound_name = handler
        .last_identifier_parameter_kinds
        .contains(&param.kind())
        .then(|| last_identifier_descendant_by_position(param, handler))
        .flatten();
    let name_node = declarator_chain_name
        .or(method_param_bound_name)
        .or_else(|| param.child_by_field_name("pattern"))
        .or_else(|| param.child_by_field_name("name"))
        .or_else(|| direct_non_type_identifier_child(param, handler))
        // For parameter-shaped nodes without a name field, take the last
        // identifier-shaped descendant — usually the bound name in
        // `Type<Generic> name` shapes.
        .or_else(|| {
            if handler.parameter_kinds.contains(&param.kind())
                || handler.variadic_parameter_kinds.contains(&param.kind())
            {
                last_identifier_descendant_by_position(param, handler)
            } else {
                None
            }
        })
        .or_else(|| first_identifier_descendant_for_handler(param, handler));
    if let Some(name_node) = name_node {
        if handler.destructured_parameter_kinds.contains(&name_node.kind()) {
            let pattern_bindings = binding_names_from_pattern(name_node, src, handler);
            if !pattern_bindings.is_empty() {
                param_names.extend(pattern_bindings);
                return;
            }
        }
    }
    let raw_name_text = match (bare_identifier_text, name_node) {
        (Some(text), _) => text,
        (None, Some(node)) => node_text(&node, src).trim().to_string(),
        _ if handler.variadic_parameter_kinds.contains(&param.kind()) => {
            param_names.push(SYNTHETIC_VARARGS_PARAM.to_string());
            return;
        }
        _ => return,
    };
    let trimmed_name = raw_name_text.trim();
    // Filter out sigil-only entries (`*`, `&`) that are syntax noise
    // rather than meaningful parameter bindings.
    if !trimmed_name.is_empty() && trimmed_name != "*" && trimmed_name != "&" {
        param_names.push(trimmed_name.to_string());
    }
}

fn binding_names_from_pattern(pattern: Node<'_>, src: &[u8], handler: &GrammarHandler) -> Vec<String> {
    let mut bindings = Vec::new();
    collect_binding_names(pattern, src, handler, &mut bindings);
    bindings
}

fn collect_binding_names(node: Node<'_>, src: &[u8], handler: &GrammarHandler, bindings: &mut Vec<String>) {
    if handler.binding_identifier_kinds.contains(&node.kind()) {
        let name = node_text(&node, src).trim();
        if !name.is_empty() && !bindings.iter().any(|existing| existing == name) {
            bindings.push(name.to_string());
        }
        return;
    }

    let structural_child = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("pattern"))
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.child_by_field_name("value"));
    if let Some(child) = structural_child {
        collect_binding_names(child, src, handler, bindings);
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
            Some("type" | "key" | "right" | "value" | "default" | "path" | "constructor")
        ) {
            continue;
        }
        collect_binding_names(child, src, handler, bindings);
    }
}

/// First direct identifier-like child that is not itself type syntax.
/// This covers grammars such as Kotlin where `parameter` is
/// `simple_identifier user_type`; grouped parameter wrappers fall
/// through to the descendant-by-position fallback below.
fn direct_non_type_identifier_child<'tree>(
    node: Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let child = cursor.node();
        if child.is_named()
            && handler.binding_identifier_kinds.contains(&child.kind())
            && cursor.field_name() != Some("type")
        {
            return Some(child);
        }
        if !cursor.goto_next_sibling() {
            return None;
        }
    }
}

fn first_identifier_descendant_for_handler<'tree>(
    node: Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current != node && handler.binding_identifier_kinds.contains(&current.kind()) {
            return Some(current);
        }
        for index in (0..current.child_count()).rev() {
            let Ok(index) = u32::try_from(index) else {
                continue;
            };
            let Some(child) = current.child(index).filter(Node::is_named) else {
                continue;
            };
            if current.field_name_for_child(index) == Some("type") {
                continue;
            }
            pending.push(child);
        }
    }
    None
}

fn repeated_named_field_values(
    node: Node<'_>,
    src: &[u8],
    field: &str,
    handler: &GrammarHandler,
) -> Vec<String> {
    let mut out = Vec::new();
    for idx in 0..node.child_count() {
        let Ok(idx) = u32::try_from(idx) else {
            continue;
        };
        let Some(child) = node.child(idx) else {
            continue;
        };
        if node.field_name_for_child(idx) != Some(field) {
            continue;
        }
        if !handler.binding_identifier_kinds.contains(&child.kind()) {
            continue;
        }
        let value = node_text(&child, src).trim();
        if !value.is_empty() {
            out.push(value.to_string());
        }
    }
    out
}

/// Last identifier-shaped descendant of `node` by source position
/// (largest start byte wins). Used for ObjC method_parameter where the
/// bound variable name appears textually after the type identifier.
fn last_identifier_descendant_by_position<'tree>(
    node: Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    let mut latest_by_position: Option<Node<'tree>> = None;
    let mut work_stack = vec![node];
    while let Some(current) = work_stack.pop() {
        if current != node
            && handler.binding_identifier_kinds.contains(&current.kind())
            && latest_by_position.is_none_or(|tracked| current.start_byte() > tracked.start_byte())
        {
            latest_by_position = Some(current);
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            work_stack.push(child);
        }
    }
    latest_by_position
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::{language_from_pack, GENERIC_HANDLER};

    fn params_for(pack: &str, function_kind: &str, src: &str) -> Vec<String> {
        let language = language_from_pack(pack).unwrap_or_else(|error| panic!("{pack}: {error}"));
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set language");
        let tree = parser.parse(src.as_bytes(), None).expect("parse source");
        let function = find_kind(tree.root_node(), function_kind).expect("function node");
        extract_param_names(&function, src.as_bytes(), &GENERIC_HANDLER)
    }

    fn find_kind<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if node.kind() == kind {
                return Some(node);
            }
            let mut cursor = node.walk();
            let mut children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
            children.reverse();
            pending.extend(children);
        }
        None
    }

    #[test]
    fn javascript_destructured_params_follow_pattern_nodes() {
        let params = params_for(
            "javascript",
            "function_declaration",
            "function run({ command: cmd, user, nested: { token }, ...rest }, [first, last] = []) {}",
        );

        assert_eq!(params, ["cmd", "user", "token", "rest", "first", "last"]);
    }

    #[test]
    fn typescript_typed_destructuring_excludes_keys_and_types() {
        let params = params_for(
            "typescript",
            "arrow_function",
            "const run = ({ command: cmd, user }: Input, ...rest: string[]) => {};",
        );

        assert_eq!(params, ["cmd", "user", "rest"]);
    }

    #[test]
    fn c_unnamed_variadic_param_comes_from_grammar_node() {
        let params = params_for("c", "function_definition", "void log(const char *fmt, ...) {}");

        assert_eq!(params, ["fmt", SYNTHETIC_VARARGS_PARAM]);
    }

    #[test]
    fn cpp_and_lua_variadics_come_from_parameter_nodes() {
        assert_eq!(
            params_for("cpp", "function_definition", "void log(const char *fmt, ...) {}"),
            ["fmt", SYNTHETIC_VARARGS_PARAM]
        );
        assert_eq!(
            params_for("lua", "function_declaration", "function log(...) end"),
            [SYNTHETIC_VARARGS_PARAM]
        );
    }

    #[test]
    fn lambda_parameters_follow_each_grammar_container() {
        for (pack, kind, source) in [
            ("javascript", "arrow_function", "const f = value => sink(value);"),
            (
                "kotlin",
                "lambda_literal",
                "val f = { value: String -> sink(value) }",
            ),
            (
                "swift",
                "lambda_literal",
                "let f = { (value: String) in sink(value) }",
            ),
            ("elixir", "anonymous_function", "f = fn value -> sink(value) end"),
        ] {
            assert_eq!(params_for(pack, kind, source), ["value"], "{pack}");
        }
    }
}
