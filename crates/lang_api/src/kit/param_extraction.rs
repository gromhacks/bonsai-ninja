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
//! FastAPI binder annotations and other Python decorator shapes are
//! handled in the `lang_python` adapter's post-processing.

use tree_sitter::Node;

use super::{
    extract_direct_call_info, first_identifier_descendant, first_identifier_like_child,
    first_named_child_of_kind, looks_like_identifier, node_text, short_name_of, COMMON_CALL_KINDS,
    SYNTHETIC_VARARGS_PARAM,
};

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
pub fn extract_param_annotations(fn_node: &Node<'_>, src: &[u8]) -> Vec<Vec<String>> {
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
            if matches!(child.kind(), "modifiers" | "annotation_list" | "attribute_list") {
                annotation_search_roots.push(child);
            }
        }
        // Fall back to scanning the param itself when no wrapper exists.
        if annotation_search_roots.is_empty() {
            annotation_search_roots.push(param);
        }
        for root in annotation_search_roots {
            collect_param_annotation_names(root, src, &mut annotation_names);
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
    let parameters_container = fn_node
        .child_by_field_name("parameters")
        .or_else(|| fn_node.child_by_field_name("args"))
        .or_else(|| first_named_child_of_kind(fn_node, "parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "formal_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "parameter_list"))
        .or_else(|| first_named_child_of_kind(fn_node, "function_value_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "expr_args"))
        .or_else(|| first_named_child_of_kind(fn_node, "formal_parameter_list"));
    if let Some(parameters_container) = parameters_container {
        let mut cursor = parameters_container.walk();
        let mut pending_annotations: Vec<String> = Vec::new();
        for param in parameters_container.named_children(&mut cursor) {
            if is_parameter_modifier_container(param.kind()) {
                collect_param_annotation_names(param, src, &mut pending_annotations);
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
    // Flat-shape grammars (Solidity, Objective-C) put each parameter as
    // a direct child of the function. Track the previously-seen
    // identifier so ObjC method_parameter siblings inherit their
    // selector piece as a pseudo-annotation.
    let mut cursor = fn_node.walk();
    let mut previous_identifier_text: Option<String> = None;
    for child in fn_node.named_children(&mut cursor) {
        let already_visited = parameters_container.is_some_and(|p| child_in(child, p));
        if matches!(
            child.kind(),
            "parameter" | "method_parameter" | "formal_parameter"
        ) && !already_visited
        {
            if child.kind() == "method_parameter" {
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
        if child.kind() == "identifier" {
            let identifier_text = node_text(&child, src).trim().trim_end_matches(':').to_string();
            if !identifier_text.is_empty() {
                previous_identifier_text = Some(identifier_text);
            }
        }
    }
    // ObjC: `application:openURL:options:` parses as a sequence of
    // `keyword_argument` siblings under the method_definition. Record the
    // selector piece (`openURL`) as an annotation so rules can match by
    // selector piece.
    let mut cursor = fn_node.walk();
    for child in fn_node.named_children(&mut cursor) {
        if !matches!(child.kind(), "keyword_argument" | "keyword_declarator") {
            continue;
        }
        let mut selector_piece: Option<String> = None;
        let mut piece_cursor = child.walk();
        for piece_child in child.named_children(&mut piece_cursor) {
            if matches!(piece_child.kind(), "keyword" | "selector_keyword" | "identifier") {
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

/// True when `child` is a direct named child of `container`.
fn child_in(child: Node<'_>, container: Node<'_>) -> bool {
    let mut cursor = container.walk();
    for candidate in container.named_children(&mut cursor) {
        if candidate == child {
            return true;
        }
    }
    false
}

/// Walk `root` collecting annotation/decorator/attribute names. Stops
/// recursing into a matched annotation node so we don't double-count nested
/// arguments (e.g. `@MyAnn(@Other)`).
fn collect_param_annotation_names(root: Node<'_>, src: &[u8], collected_names: &mut Vec<String>) {
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        // Recognized annotation node — pull out its name and stop recursing.
        if matches!(
            node.kind(),
            "marker_annotation" | "annotation" | "attribute" | "decorator"
        ) {
            if let Some(name_node) = node
                .child_by_field_name("name")
                .or_else(|| first_identifier_descendant(node))
            {
                let annotation_name = node_text(&name_node, src).trim().to_string();
                if !annotation_name.is_empty() {
                    collected_names.push(annotation_name);
                }
            }
            continue;
        }
        // Some grammars (Python decorators) emit annotations as call expressions
        // like `@RequestParam(...)`. Pull the leading callee name.
        if COMMON_CALL_KINDS.contains(&node.kind()) {
            if let Some((Some(callee_path), _)) = extract_direct_call_info(&node, src) {
                let bare_callee = short_name_of(&callee_path).trim_start_matches('@').to_string();
                if !bare_callee.is_empty() {
                    collected_names.push(bare_callee);
                }
            }
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
///   3. Flat siblings of the function node (Solidity, Objective-C selectors).
pub(super) fn extract_param_names(fn_node: &Node<'_>, src: &[u8]) -> Vec<String> {
    let mut param_names = Vec::new();
    // Receivers come first so their slot is index 0.
    if let Some(receiver) = fn_node.child_by_field_name("receiver") {
        let mut cursor = receiver.walk();
        let mut visited_named_child = false;
        for param in receiver.named_children(&mut cursor) {
            visited_named_child = true;
            push_param_name(param, src, &mut param_names);
        }
        // Receiver itself is the param when no nested children exist.
        if !visited_named_child {
            push_param_name(receiver, src, &mut param_names);
        }
    }
    // Most languages wrap params in a single container node; the lookup
    // tries every known field/kind name, falling back to a declarator
    // chain for C-family grammars and an `arguments` child for Elixir.
    let parameters_container = fn_node
        .child_by_field_name("parameters")
        .or_else(|| fn_node.child_by_field_name("args")) // Erlang: args: expr_args
        // JS permits an unparenthesized arrow parameter (`x => body`) and
        // exposes it through a singular `parameter` field.
        .or_else(|| {
            matches!(fn_node.kind(), "arrow_function" | "lambda_expression")
                .then(|| fn_node.child_by_field_name("parameter"))
                .flatten()
        })
        .or_else(|| first_named_child_of_kind(fn_node, "parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "formal_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "parameter_list"))
        .or_else(|| first_named_child_of_kind(fn_node, "function_value_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "lambda_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "lambda_function_type_parameters"))
        // Swift nests the parameter container under the lambda's parsed
        // function-type node. Follow that grammar edge explicitly instead
        // of scanning or splitting the closure text.
        .or_else(|| {
            first_named_child_of_kind(fn_node, "lambda_function_type").and_then(|function_type| {
                first_named_child_of_kind(&function_type, "lambda_function_type_parameters")
            })
        })
        .or_else(|| first_named_child_of_kind(fn_node, "expr_args")) // Erlang flat
        // Dart: `formal_parameter_list` wraps `formal_parameter` children.
        .or_else(|| first_named_child_of_kind(fn_node, "formal_parameter_list"))
        // C / C++ / Objective-C: walk the nested declarator chain
        // (`function_declarator > parameters > parameter_list`) until we
        // find a `parameters` field. Stop on the first hit so we don't
        // descend past it into the inner identifier.
        .or_else(|| {
            let mut declarator = fn_node.child_by_field_name("declarator");
            while let Some(decl_node) = declarator {
                if let Some(parameters) = decl_node
                    .child_by_field_name("parameters")
                    .or_else(|| first_named_child_of_kind(&decl_node, "parameter_list"))
                {
                    return Some(parameters);
                }
                declarator = decl_node.child_by_field_name("declarator");
            }
            None
        })
        // Elixir: `def foo(x, y) do ... end` parses as a `call` whose
        // child `arguments` holds the params as identifier siblings.
        .or_else(|| {
            if fn_node.kind() == "call" {
                first_named_child_of_kind(fn_node, "arguments")
            } else {
                None
            }
        })
        // Elixir anonymous functions place their parameters in the left
        // `arguments` child of the first parsed `stab_clause`.
        .or_else(|| {
            (fn_node.kind() == "anonymous_function")
                .then(|| {
                    first_named_child_of_kind(fn_node, "stab_clause")
                        .and_then(|clause| clause.child_by_field_name("left"))
                })
                .flatten()
        });
    if let Some(parameters_container) = parameters_container {
        // C# implicit single-parameter lambda `x => body`: the
        // `parameters` field is a lone `implicit_parameter` leaf whose
        // TEXT is the name, not a list and not an `identifier`-kind node
        // that `push_param_name` recognises — take its text directly.
        if parameters_container.kind() == "implicit_parameter" {
            let text = node_text(&parameters_container, src).trim();
            if !text.is_empty() {
                param_names.push(text.to_string());
            }
        } else if looks_like_identifier(parameters_container.kind()) {
            push_param_name(parameters_container, src, &mut param_names);
        } else {
            let mut cursor = parameters_container.walk();
            for param in parameters_container.named_children(&mut cursor) {
                if is_parameter_modifier_container(param.kind()) {
                    continue;
                }
                push_param_name(param, src, &mut param_names);
            }
        }
        // C/C++ represent a bare variadic collector as the anonymous `...`
        // terminal of `parameter_list`. Read that direct grammar token;
        // never scan or split the surrounding source declaration.
        let mut cursor = parameters_container.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if !child.is_named() && node_text(&child, src).trim() == "..." {
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
    // Flat-shape grammars (Solidity, ObjC) emit param nodes as direct
    // siblings of the function. Run the flat scan even after the
    // container scan succeeded — grammars rarely mix shapes, so usually
    // exactly one path fires. Skip params already counted inside the
    // container (mirrors `extract_param_annotations`'s guard) so a
    // grammar that exposes a param at both levels can't double-count and
    // desync the parallel `params` / `param_annotations` indexing.
    let mut cursor = fn_node.walk();
    for child in fn_node.named_children(&mut cursor) {
        let already_visited = parameters_container.is_some_and(|p| child_in(child, p));
        if matches!(
            child.kind(),
            "parameter" | "method_parameter" | "formal_parameter"
        ) && !already_visited
        {
            push_param_name(child, src, &mut param_names);
        }
    }
    // ObjC: each `keyword_argument` sibling holds the bound parameter
    // identifier (`(NSURL *)url` after `openURL:`). Mirror the walk done
    // in extract_param_annotations so params + param_annotations stay
    // parallel-indexed.
    let mut cursor = fn_node.walk();
    for child in fn_node.named_children(&mut cursor) {
        if !matches!(child.kind(), "keyword_argument" | "keyword_declarator") {
            continue;
        }
        let mut bound_name: Option<String> = None;
        let mut piece_cursor = child.walk();
        for piece_child in child.named_children(&mut piece_cursor) {
            if matches!(
                piece_child.kind(),
                "parameter" | "method_parameter" | "formal_parameter"
            ) {
                if let Some(name_node) = piece_child
                    .child_by_field_name("name")
                    .or_else(|| first_identifier_descendant(piece_child))
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

fn is_parameter_modifier_container(kind: &str) -> bool {
    matches!(
        kind,
        "parameter_modifiers" | "modifiers" | "annotation_list" | "attribute_list"
    )
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
fn push_param_name(param: Node<'_>, src: &[u8], param_names: &mut Vec<String>) {
    if param.kind() == "self_parameter" {
        param_names.push("self".to_string());
        return;
    }

    let repeated_field_names = repeated_named_field_values(param, src, "name");
    if repeated_field_names.len() > 1 {
        param_names.extend(repeated_field_names);
        return;
    }

    // JS destructured params sit directly in the parameter list while TS
    // wraps them in a `required_parameter`. Walk the parsed pattern nodes;
    // property keys, default expressions, and type annotations are excluded
    // by CST fields rather than by tokenizing the pattern's source text.
    let mut pattern_node = param;
    if matches!(
        pattern_node.kind(),
        "assignment_pattern" | "object_assignment_pattern"
    ) {
        if let Some(left) = pattern_node.child_by_field_name("left") {
            pattern_node = left;
        }
    }
    if matches!(pattern_node.kind(), "object_pattern" | "array_pattern") {
        let pattern_bindings = binding_names_from_pattern(pattern_node, src);
        if !pattern_bindings.is_empty() {
            param_names.extend(pattern_bindings);
            return;
        }
    }

    // Bare identifier params: the param node itself carries the name.
    let bare_identifier_text = if looks_like_identifier(param.kind()) {
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
            if looks_like_identifier(declarator_node.kind()) {
                innermost_identifier = Some(declarator_node);
                break;
            }
            if let Some(nested) = declarator_node.child_by_field_name("declarator") {
                current_declarator = Some(nested);
            } else {
                // Last declarator level — fall back to a DFS for any
                // identifier descendant.
                innermost_identifier = first_identifier_descendant(declarator_node);
                break;
            }
        }
        innermost_identifier
    };
    // ObjC method_parameter wraps `(Type)name` — the bound name is the
    // last identifier by source position, since the type identifier
    // appears earlier in the subtree.
    let method_param_bound_name = (param.kind() == "method_parameter")
        .then(|| last_identifier_descendant_by_position(param))
        .flatten();
    let name_node = declarator_chain_name
        .or(method_param_bound_name)
        .or_else(|| param.child_by_field_name("pattern"))
        .or_else(|| param.child_by_field_name("name"))
        .or_else(|| direct_non_type_identifier_child(param))
        // For parameter-shaped nodes without a name field, take the last
        // identifier-shaped descendant — usually the bound name in
        // `Type<Generic> name` shapes.
        .or_else(|| {
            if param.kind().contains("parameter") {
                last_identifier_descendant_by_position(param)
            } else {
                None
            }
        })
        .or_else(|| first_identifier_like_child(&param))
        .or_else(|| first_identifier_descendant(param));
    if let Some(name_node) = name_node {
        if is_binding_pattern_kind(name_node.kind()) {
            let pattern_bindings = binding_names_from_pattern(name_node, src);
            if !pattern_bindings.is_empty() {
                param_names.extend(pattern_bindings);
                return;
            }
        }
    }
    let raw_name_text = match (bare_identifier_text, name_node) {
        (Some(text), _) => text,
        (None, Some(node)) => node_text(&node, src).trim().to_string(),
        _ if is_unnamed_variadic_parameter(param.kind()) => {
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

fn is_unnamed_variadic_parameter(kind: &str) -> bool {
    matches!(
        kind,
        "variadic_parameter" | "variadic_declaration" | "variadic_placeholder" | "vararg_expression"
    )
}

fn is_binding_pattern_kind(kind: &str) -> bool {
    kind.contains("pattern") || matches!(kind, "tuple" | "list" | "parameters" | "destructuring_declarator")
}

fn binding_names_from_pattern(pattern: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut bindings = Vec::new();
    collect_binding_names(pattern, src, &mut bindings);
    bindings
}

fn collect_binding_names(node: Node<'_>, src: &[u8], bindings: &mut Vec<String>) {
    if binding_identifier_kind(node.kind()) {
        let name = node_text(&node, src).trim();
        if !name.is_empty() && !bindings.iter().any(|existing| existing == name) {
            bindings.push(name.to_string());
        }
        return;
    }

    let structural_child = match node.kind() {
        "pair_pattern" => node.child_by_field_name("value"),
        "assignment_pattern" | "object_assignment_pattern" => node.child_by_field_name("left"),
        _ => None,
    };
    if let Some(child) = structural_child {
        collect_binding_names(child, src, bindings);
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
        ) || child.kind().contains("type")
        {
            continue;
        }
        collect_binding_names(child, src, bindings);
    }
}

fn binding_identifier_kind(kind: &str) -> bool {
    kind == "shorthand_property_identifier_pattern"
        || (looks_like_identifier(kind)
            && !kind.contains("type")
            && !matches!(
                kind,
                "property_identifier" | "private_property_identifier" | "field_identifier"
            ))
}

/// First direct identifier-like child that is not itself type syntax.
/// This covers grammars such as Kotlin where `parameter` is
/// `simple_identifier user_type`; grouped parameter wrappers fall
/// through to the descendant-by-position fallback below.
fn direct_non_type_identifier_child<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let child = cursor.node();
        if child.is_named()
            && looks_like_identifier(child.kind())
            && !child.kind().contains("type")
            && cursor.field_name() != Some("type")
        {
            return Some(child);
        }
        if !cursor.goto_next_sibling() {
            return None;
        }
    }
}

fn repeated_named_field_values(node: Node<'_>, src: &[u8], field: &str) -> Vec<String> {
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
        if !looks_like_identifier(child.kind()) {
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
fn last_identifier_descendant_by_position<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut latest_by_position: Option<Node<'tree>> = None;
    let mut work_stack = vec![node];
    while let Some(current) = work_stack.pop() {
        if current != node
            && looks_like_identifier(current.kind())
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
    use crate::kit::language_from_pack;

    fn params_for(pack: &str, function_kind: &str, src: &str) -> Vec<String> {
        let language = language_from_pack(pack).unwrap_or_else(|error| panic!("{pack}: {error}"));
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("set language");
        let tree = parser.parse(src.as_bytes(), None).expect("parse source");
        let function = find_kind(tree.root_node(), function_kind).expect("function node");
        extract_param_names(&function, src.as_bytes())
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
