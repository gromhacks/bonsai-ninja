//! Pattern / match / foreach binding-assignment extraction.
//!
//! Synthesises `FlowEvent::Assign` bindings from `match`/`case`/`when`
//! arm patterns, Rust `if let`/`while let` conditions, `instanceof`/`is`
//! type-test bindings, comprehension `for`-clauses, and foreach headers,
//! so the taint engine sees pattern-bound names carry the subject's taint.

use bonsai_common::FileId;
use tree_sitter::Node;

use crate::FlowEvent;

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn extract_match_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    out.extend(extract_instanceof_pattern_binding_assigns(file, node, src));
    out.extend(extract_is_pattern_binding_assigns(file, node, src));
    out.extend(extract_kotlin_when_subject_binding_assigns(file, node, src));
    out.extend(extract_case_match_binding_assigns(file, node, src));
    out.extend(extract_case_pattern_binding_assigns(file, node, src));
    out.extend(extract_elixir_case_stab_clause_bindings(file, node, src));
    out.extend(extract_rust_let_condition_bindings(file, node, src));

    // Rust's grammar exposes `match_expression { value, body }` while
    // Python exposes `match_statement { subject, body }`. Both lower from
    // their parsed subject/pattern nodes; indentation and punctuation never
    // participate in binding discovery.
    if matches!(
        node.kind(),
        "match_expression" | "if_let_expression" | "while_let_expression"
    ) {
        out.extend(extract_rust_style_match_bindings(file, node, src));
        return out;
    }
    if node.kind() == "match_statement" {
        let Some(subject) = node.child_by_field_name("subject") else {
            return out;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return out;
        };
        let (source_name, mut source_names) = binding_source_facts(subject, src);
        // A canonical place already identifies the dependency exactly.
        // Avoid emitting the same bare place through both carriers: Python's
        // branch lowering treats `source_names` as additional operands, and
        // the duplicate edge can obscure the function-return summary built
        // from the branch result.
        if source_name.is_some() {
            source_names.clear();
        }
        let mut targets: Vec<String> = Vec::new();
        let mut cursor = body.walk();
        for case_clause in body.named_children(&mut cursor) {
            if case_clause.kind() != "case_clause" {
                continue;
            }
            let mut case_cursor = case_clause.walk();
            let Some(pattern) = case_clause
                .named_children(&mut case_cursor)
                .find(|child| child.kind() == "case_pattern")
            else {
                continue;
            };
            for target in binding_targets_from_pattern_node(&pattern, src) {
                if !targets.iter().any(|seen| same_identifier_name(seen, &target)) {
                    targets.push(target);
                }
            }
        }
        targets.sort();
        out.extend(targets.into_iter().filter_map(|target| {
            (source_name.is_some() || !source_names.is_empty()).then(|| FlowEvent::Assign {
                span: span_of(file, node),
                target,
                source_name: source_name.clone(),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: source_names.clone(),
                declares_new_binding: false,
                value_kind: None,
            })
        }));
    }
    out
}

/// Rust `if let PAT = EXPR { }` / `while let PAT = EXPR { }` parse (in
/// the current tree-sitter-rust grammar) as `if_expression` /
/// `while_expression` with a `let_condition` child (fields `pattern` +
/// `value`), NOT the older `if_let_expression` / `while_let_expression`
/// that [`extract_rust_style_match_bindings`] handles. Without binding
/// PAT's names to EXPR, subject taint never reaches the binding — e.g.
/// `if let Some(v) = tainted { sink(v) }` was a false negative. Bind
/// each lowercase (non-variant, non-`_`/`ref`/`mut`) pattern name to the
/// scrutinee's identifiers. Handles let-chains (`if let A(a) = x && let
/// B(b) = y`) by visiting every `let_condition` under the condition.
pub(super) fn extract_rust_let_condition_bindings(
    file: FileId,
    node: &Node<'_>,
    src: &[u8],
) -> Vec<FlowEvent> {
    if !matches!(node.kind(), "if_expression" | "while_expression") {
        return Vec::new();
    }
    let Some(condition) = node.child_by_field_name("condition") else {
        return Vec::new();
    };
    // Collect every `let_condition` in the condition subtree (a bare
    // `if let` is the condition itself; a let-chain nests them under
    // binary `&&` expressions).
    let mut let_conditions: Vec<Node<'_>> = Vec::new();
    let mut stack = vec![condition];
    while let Some(n) = stack.pop() {
        if n.kind() == "let_condition" {
            let_conditions.push(n);
            continue;
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    let mut out = Vec::new();
    for lc in let_conditions {
        let (Some(pat), Some(val)) = (lc.child_by_field_name("pattern"), lc.child_by_field_name("value"))
        else {
            continue;
        };
        let (source_name, source_names) = binding_source_facts(val, src);
        for ident in binding_targets_from_pattern_node(&pat, src) {
            // Skip variant constructors (`Some`, `Ok`, user `Variant`) —
            // uppercase-leading — and non-binding pattern keywords.
            if ident.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                || matches!(ident.as_str(), "_" | "ref" | "mut")
            {
                continue;
            }
            out.push(FlowEvent::Assign {
                span: span_of(file, &pat),
                target: ident,
                source_name: source_name.clone(),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: source_names.clone(),
                declares_new_binding: false,
                value_kind: None,
            });
        }
    }
    out
}

pub(super) fn extract_elixir_case_stab_clause_bindings(
    file: FileId,
    node: &Node<'_>,
    src: &[u8],
) -> Vec<FlowEvent> {
    if node.kind() != "call" {
        return Vec::new();
    }
    let target_is_case = node
        .child_by_field_name("target")
        .is_some_and(|target| node_text(&target, src).trim() == "case");
    if !target_is_case {
        return Vec::new();
    }
    let Some(subject) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "arguments"))
        .and_then(|arguments| first_named_child(&arguments).or(Some(arguments)))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "stab_clause" {
            if let Some(pattern) = current.child_by_field_name("left") {
                for target in binding_targets_from_pattern_node(&pattern, src) {
                    if target == "_" || target.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) {
                        continue;
                    }
                    if let Some(assign) = pattern_binding_assign(file, &pattern, &target, subject, src) {
                        out.push(assign);
                    }
                }
            }
        }
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    dedup_assign_events(out)
}

fn extract_instanceof_pattern_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "instanceof_expression" {
            if let (Some(source), Some(target)) = (
                current.child_by_field_name("left"),
                current.child_by_field_name("name"),
            ) {
                let target_text = node_text(&target, src).trim();
                if looks_like_bare_identifier(target_text) {
                    let (source_name, mut source_names) = binding_source_facts(source, src);
                    source_names.retain(|name| !same_identifier_name(name, target_text));
                    source_names.sort();
                    source_names.dedup();
                    out.push(FlowEvent::Assign {
                        span: span_of(file, &current),
                        target: target_text.to_string(),
                        source_name,
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names,
                        declares_new_binding: false,
                        value_kind: None,
                    });
                }
            }
        }
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn extract_is_pattern_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "is_pattern_expression" {
            if let (Some(source), Some(pattern)) = (
                current.child_by_field_name("expression"),
                current.child_by_field_name("pattern"),
            ) {
                for target in binding_targets_from_pattern_node(&pattern, src) {
                    if let Some(assign) = pattern_binding_assign(file, &current, &target, source, src) {
                        out.push(assign);
                    }
                }
            }
        }
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn extract_kotlin_when_subject_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "when_subject" {
            let Some(decl) = first_named_child_of_kind(&current, "variable_declaration") else {
                continue;
            };
            let Some(target_node) = first_identifier_descendant(decl) else {
                continue;
            };
            let target = node_text(&target_node, src);
            let mut subject_cursor = current.walk();
            let Some(source) = current
                .named_children(&mut subject_cursor)
                .find(|child| child.id() != decl.id() && !matches!(child.kind(), "annotation" | "type"))
            else {
                continue;
            };
            if let Some(assign) = pattern_binding_assign(file, &current, target, source, src) {
                out.push(assign);
            }
        }
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn extract_case_match_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    if node.kind() != "case_match" {
        return Vec::new();
    }
    let Some(subject) = node.child_by_field_name("value") else {
        return Vec::new();
    };
    let (source_name, source_names) = binding_source_facts(subject, src);

    let mut targets: Vec<String> = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "in_clause" {
            if let Some(pattern) = current
                .child_by_field_name("pattern")
                .or_else(|| first_named_child(&current))
            {
                // Ruby pin pattern `in ^expected` (`variable_reference_
                // pattern`) is an equality READ against an existing
                // variable, not a new binding — skip it.
                if !matches!(
                    pattern.kind(),
                    "variable_reference_pattern" | "reference_pattern" | "pin_pattern" | "pin"
                ) {
                    for target in binding_targets_from_pattern_node(&pattern, src) {
                        if !targets.iter().any(|seen| same_identifier_name(seen, &target)) {
                            targets.push(target);
                        }
                    }
                }
            }
        }
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    targets
        .into_iter()
        .filter(|target| {
            !source_names
                .iter()
                .any(|source| same_identifier_name(source, target))
        })
        .map(|target| FlowEvent::Assign {
            span: span_of(file, node),
            target,
            source_name: source_name.clone(),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: source_names.clone(),
            declares_new_binding: false,
            value_kind: None,
        })
        .collect()
}

fn extract_case_pattern_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    // These shapes have a dedicated lowering pass below. Running the
    // generic case-arm pass as well would duplicate bindings and treat a
    // unit variant such as Rust `None` as a capture.
    if matches!(
        node.kind(),
        "match_expression" | "if_let_expression" | "while_let_expression"
    ) {
        return Vec::new();
    }
    let Some(subject) = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("subject"))
        .or_else(|| node.child_by_field_name("expr"))
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.child_by_field_name("condition"))
        .or_else(|| node.child_by_field_name("discriminant"))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if matches!(
            current.kind(),
            "case_clause"
                | "switch_statement_case"
                | "switch_entry"
                | "cr_clause"
                | "match_arm"
                | "match_block_arm"
                | "match_expression_arm"
        ) {
            let mut patterns = Vec::new();
            for field in ["pattern", "pat"] {
                if let Some(pattern) = current.child_by_field_name(field) {
                    patterns.push(pattern);
                }
            }
            for kind in ["variable_pattern", "switch_pattern"] {
                if let Some(pattern) = first_named_child_of_kind(&current, kind) {
                    patterns.push(pattern);
                }
            }
            for pattern in patterns {
                for target in binding_targets_from_pattern_node(&pattern, src) {
                    if let Some(assign) = pattern_binding_assign(file, &pattern, &target, subject, src) {
                        out.push(assign);
                    }
                }
            }
            // Do NOT descend into this arm's body. A nested `match`/`case`
            // inside the arm binds its own arms to ITS subject (extracted
            // by its own call); walking into the body here would bind those
            // nested arm variables to the OUTER subject (false taint) and
            // grow work quadratically on deep nesting.
            continue;
        }
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    dedup_assign_events(out)
}

pub(super) fn binding_targets_from_pattern_node(pattern: &Node<'_>, src: &[u8]) -> Vec<String> {
    let mut targets = Vec::new();
    let mut stack = vec![*pattern];
    while let Some(current) = stack.pop() {
        // Ruby pin `in ^expected` (`variable_reference_pattern`) and
        // equivalent reference/pin patterns are equality READS against an
        // existing variable, not new bindings — don't capture their
        // identifier as an assignment target.
        if matches!(
            current.kind(),
            "variable_reference_pattern" | "reference_pattern" | "pin_pattern" | "pin"
        ) {
            continue;
        }

        // JavaScript/TypeScript defaulted destructuring uses an
        // `assignment_pattern`: `[binding = fallback]`. Only the parsed LHS
        // binds; the RHS is a value read. Descending through both children
        // would manufacture an assignment to `fallback` and could taint or
        // clean-overwrite an unrelated local.
        if current.kind() == "assignment_pattern" {
            if let Some(binding) = current
                .child_by_field_name("left")
                .or_else(|| current.child_by_field_name("name"))
                .or_else(|| first_named_child(&current))
            {
                stack.push(binding);
            }
            continue;
        }

        if matches!(
            current.kind(),
            "identifier"
                | "simple_identifier"
                | "variable_name"
                | "var"
                | "varname"
                // Rust struct-pattern shorthand is a binding position
                // (`let Boxed { value } = input`). The grammar gives it a
                // dedicated node so it cannot be confused with the struct
                // type or with an explicit field key.
                | "shorthand_field_identifier"
                | "shorthand_property_identifier_pattern"
        ) {
            push_binding_target(&mut targets, node_text(&current, src));
            continue;
        }

        // A dotted Python pattern is a capture only when it is a single
        // identifier. Multi-segment dotted names are value patterns. The
        // constructor name of a class pattern is likewise a value, while
        // all remaining children are nested binding patterns.
        if current.kind() == "dotted_name" && current.named_child_count() > 1 {
            continue;
        }
        if current.kind() == "class_pattern" {
            let mut cursor = current.walk();
            let children: Vec<Node<'_>> = current.named_children(&mut cursor).skip(1).collect();
            stack.extend(children.into_iter().rev());
            continue;
        }

        // Both Python and Ruby call these `keyword_pattern`, but expose
        // different field metadata. A fielded Ruby key with no value is a
        // shorthand capture (`value:`). A fielded value or Python's first
        // positional identifier is a property key, never a binding.
        if current.kind() == "keyword_pattern" {
            if let Some(value) = current.child_by_field_name("value") {
                stack.push(value);
            } else if let Some(key) = current.child_by_field_name("key") {
                push_binding_target(&mut targets, node_text(&key, src));
            } else {
                let mut cursor = current.walk();
                let children: Vec<Node<'_>> = current.named_children(&mut cursor).skip(1).collect();
                stack.extend(children.into_iter().rev());
            }
            continue;
        }

        // Map keys select data; only map values bind. Elixir, Ruby, and
        // JavaScript-family grammars all expose these roles as fields.
        if matches!(current.kind(), "pair" | "pair_pattern") {
            if let Some(value) = current.child_by_field_name("value") {
                stack.push(value);
                continue;
            }
        }

        let mut cursor = current.walk();
        let mut children = Vec::new();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                let field = cursor.field_name();
                if child.is_named()
                    && !matches!(
                        field,
                        Some(
                            "type"
                                | "key"
                                | "class"
                                | "path"
                                | "constructor"
                                | "guard"
                                | "function"
                                | "method"
                                | "operator"
                        )
                    )
                {
                    children.push(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        stack.extend(children.into_iter().rev());
    }
    targets
}

fn push_binding_target(out: &mut Vec<String>, raw: &str) {
    let target = raw.trim().trim_start_matches(&['$', '@', '%'][..]);
    if !target.is_empty()
        && target != "_"
        && looks_like_bare_identifier(target)
        && !out.iter().any(|seen| same_identifier_name(seen, target))
    {
        out.push(target.to_string());
    }
}

pub(super) fn pattern_binding_assign(
    file: FileId,
    span_node: &Node<'_>,
    target: &str,
    source: Node<'_>,
    src: &[u8],
) -> Option<FlowEvent> {
    if !looks_like_bare_identifier(target) {
        return None;
    }
    let (source_name, mut source_names) = binding_source_facts(source, src);
    source_names.retain(|name| !same_identifier_name(name, target));
    source_names.sort();
    source_names.dedup();
    if source_name.is_none() && source_names.is_empty() {
        return None;
    }
    Some(FlowEvent::Assign {
        span: span_of(file, span_node),
        target: target.to_string(),
        source_name,
        source_call: None,
        source_call_args: Vec::new(),
        source_names,
        declares_new_binding: false,
        value_kind: None,
    })
}

fn binding_source_facts(source: Node<'_>, src: &[u8]) -> (Option<String>, Vec<String>) {
    let source_name = argument_place(&source, src);
    let mut source_names = extract_rhs_expr_operands(&source, src);
    if source_names.is_empty() {
        source_names.extend(source_name.iter().cloned());
    }
    source_names.sort();
    source_names.dedup();
    (source_name, source_names)
}

pub(super) fn dedup_assign_events(events: Vec<FlowEvent>) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    for event in events {
        let duplicate = match &event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                ..
            } => out.iter().any(|seen| {
                matches!(
                    seen,
                    FlowEvent::Assign {
                        target: seen_target,
                        source_name: seen_source_name,
                        source_names: seen_source_names,
                        ..
                    } if same_identifier_name(seen_target, target)
                        && seen_source_name == source_name
                        && seen_source_names == source_names
                )
            }),
            _ => false,
        };
        if !duplicate {
            out.push(event);
        }
    }
    out
}

/// Walk a Rust-style `match_expression` / `if_let_expression` /
/// `while_let_expression` and emit Assigns for every binding pattern
/// across every arm. Each binding inherits the subject expression's
/// identifier(s) as `source_names` so taint on the subject reaches
/// the bindings without text-parsing the source.
fn extract_rust_style_match_bindings(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    let subject_node = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("subject"))
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.child_by_field_name("scrutinee"));
    let Some(subject) = subject_node else {
        return Vec::new();
    };
    let (source_name, source_names) = binding_source_facts(subject, src);
    let mut out: Vec<FlowEvent> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    let mut visit_pattern = |pat_node: &Node<'_>| {
        for ident in binding_targets_from_pattern_node(pat_node, src) {
            // Skip variant constructors: `Some`, `Err`, `Ok`,
            // user-defined `Variant(x)` — uppercase-leading
            // identifiers are constructors, not bindings, in Rust.
            if ident.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                continue;
            }
            if matches!(ident.as_str(), "_" | "ref" | "mut") {
                continue;
            }
            if !targets.iter().any(|t| t == &ident) {
                targets.push(ident);
            }
        }
    };
    let body_node = node
        .child_by_field_name("body")
        .or_else(|| node.child_by_field_name("block"));
    if let Some(body) = body_node {
        let mut cursor = body.walk();
        for arm in body.named_children(&mut cursor) {
            if !matches!(
                arm.kind(),
                "match_arm" | "match_block_arm" | "match_expression_arm" | "case_clause"
            ) {
                continue;
            }
            if let Some(pat) = arm.child_by_field_name("pattern") {
                visit_pattern(&pat);
            }
        }
    }
    if let Some(pat) = node.child_by_field_name("pattern") {
        // if_let / while_let direct pattern child.
        visit_pattern(&pat);
    }
    for target in targets {
        out.push(FlowEvent::Assign {
            span: span_of(file, node),
            target,
            source_name: source_name.clone(),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: source_names.clone(),
            declares_new_binding: false,
            value_kind: None,
        });
    }
    out
}

/// Synthesize loop-variable bindings for a comprehension's
/// `for_in_clause` / `comp_for` child. Tree-sitter exposes the
/// pattern (loop variable) in field `left` and the iterable in
/// `right` (Python) or as positional named children (JS). Either
/// shape produces an Assign with the iterable's identifiers as
/// source_names, mirroring what `extract_foreach_binding_assigns`
/// produces for full `for` statements.
pub(super) fn extract_comprehension_for_clause_assigns(
    file: FileId,
    clause: &Node<'_>,
    src: &[u8],
) -> Vec<FlowEvent> {
    // Python's tree-sitter grammar exposes the iterable as `left`
    // and the binding as the unfielded first named child. JS / TS
    // expose binding as `left` and iterable as `right`. Detect by
    // counting fielded children: when only one field is present
    // and it's `left`, treat its target as the iterable; when both
    // `left` and `right` are present, treat them as binding +
    // iterable per the JS shape.
    let left_field = clause.child_by_field_name("left");
    let right_field = clause.child_by_field_name("right");
    let (lhs_node, rhs_node) = match (left_field, right_field) {
        (Some(l), Some(r)) => (Some(l), Some(r)),
        (Some(rhs_via_left), None) => {
            // Python shape: `left` is the iterable. Binding is the
            // first named child that isn't `left`.
            let mut binding: Option<Node<'_>> = None;
            let mut cursor = clause.walk();
            for child in clause.named_children(&mut cursor) {
                if child.id() != rhs_via_left.id() {
                    binding = Some(child);
                    break;
                }
            }
            (binding, Some(rhs_via_left))
        }
        (None, _) => {
            // No field hints — use positional named children.
            (clause.named_child(0), clause.named_child(1))
        }
    };
    let (Some(lhs), Some(rhs)) = (lhs_node, rhs_node) else {
        return Vec::new();
    };
    let targets = binding_targets_from_pattern_node(&lhs, src);
    if targets.is_empty() {
        return Vec::new();
    }
    let (source_name, source_names) = binding_source_facts(rhs, src);
    targets
        .into_iter()
        .map(|target| FlowEvent::Assign {
            span: span_of(file, clause),
            target,
            source_name: source_name.clone(),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: source_names.clone(),
            declares_new_binding: false,
            value_kind: None,
        })
        .collect()
}

pub(super) fn extract_foreach_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    if let Some((binding, iterable)) = foreach_binding_nodes(node) {
        let targets = binding_targets_from_pattern_node(&binding, src);
        if !targets.is_empty() {
            let (source_name, source_names, source_call, source_call_args) =
                foreach_binding_source_facts(iterable, file, src);
            let value_kind = Some(if source_call.is_some() {
                crate::AssignValueKind::CallResult
            } else {
                crate::AssignValueKind::Compound
            });
            return targets
                .into_iter()
                .map(|target| FlowEvent::Assign {
                    span: span_of(file, node),
                    target,
                    source_name: source_name.clone(),
                    source_call: source_call.clone(),
                    source_call_args: source_call_args.clone(),
                    source_names: source_names.clone(),
                    declares_new_binding: false,
                    value_kind,
                })
                .collect();
        }
    }
    Vec::new()
}

fn foreach_binding_source_facts(
    iterable: Node<'_>,
    file: FileId,
    src: &[u8],
) -> (Option<String>, Vec<String>, Option<String>, Vec<String>) {
    // Dart represents `gen(args)` as sibling `identifier` + `selector`
    // nodes under `for_loop_parts`. Preserve that parsed call-result edge so
    // a yielded value reaches the loop binding through the callee summary.
    if iterable.kind() == "for_loop_parts" {
        if let Some((source_call, source_call_args)) = extract_dart_selector_call_info(iterable, file, src) {
            return (None, Vec::new(), source_call, source_call_args);
        }
    }
    let (source_name, source_names) = binding_source_facts(iterable, src);
    (source_name, source_names, None, Vec::new())
}

fn foreach_binding_nodes<'tree>(node: &Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    let binding = [
        "variable",
        "pattern",
        "left",
        "target",
        "name",
        "item",
        "declarator",
    ]
    .into_iter()
    .find_map(|field| node.child_by_field_name(field));
    let iterable = ["list", "iterable", "right", "source", "collection", "value"]
        .into_iter()
        .find_map(|field| node.child_by_field_name(field));
    if let (Some(binding), Some(iterable)) = (binding, iterable) {
        if binding.id() != iterable.id() {
            return Some((binding, iterable));
        }
    }

    // Several grammars wrap the compiler-known pair once: Go in a
    // `range_clause`, Lua in a `for_generic_clause`, and Scala in an
    // `enumerator`. Follow only these grammar nodes, never source text.
    for field in ["clause", "enumerators"] {
        if let Some(wrapper) = node.child_by_field_name(field) {
            if let Some(pair) = foreach_binding_nodes(&wrapper) {
                return Some(pair);
            }
        }
    }
    let mut cursor = node.walk();
    let named_children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
    for child in &named_children {
        if matches!(
            child.kind(),
            "range_clause" | "for_generic_clause" | "for_loop_parts" | "enumerators" | "enumerator"
        ) {
            if let Some(pair) = foreach_binding_nodes(child) {
                return Some(pair);
            }
        }
    }

    match node.kind() {
        // These wrappers define the first named child as the pattern and
        // the second as the iterable expression.
        "for_generic_clause" | "enumerator" | "range_clause" => {
            let [binding, iterable, ..] = named_children.as_slice() else {
                return None;
            };
            Some((*binding, *iterable))
        }
        // Dart puts the binding in `name` and the iterable in `value`.
        // A call-shaped iterable is split into `identifier` + `selector`
        // siblings, so return the wrapper itself and let the structured Dart
        // call extractor recover the exact call-result dependency.
        "for_loop_parts" => {
            let binding = node.child_by_field_name("name")?;
            let has_call_selector = named_children.iter().any(|child| {
                child.kind() == "selector" && first_named_child_of_kind(child, "argument_part").is_some()
            });
            let iterable = if has_call_selector {
                *node
            } else {
                node.child_by_field_name("value")?
            };
            Some((binding, iterable))
        }
        // PHP has no header fields. The first non-body child is the
        // iterable and the second is either one variable or a key/value
        // pair, both represented as parsed nodes.
        "foreach_statement" => {
            let body_id = node.child_by_field_name("body").map(|body| body.id());
            let mut header = named_children
                .into_iter()
                .filter(|child| Some(child.id()) != body_id);
            let iterable = header.next()?;
            let binding = header.next()?;
            Some((binding, iterable))
        }
        // Kotlin and Objective-C fast enumeration leave the header
        // unfielded. Classic C-style loops have explicit init/condition/
        // update fields and are deliberately rejected here.
        "for_statement"
            if [
                "initializer",
                "initialize",
                "init",
                "condition",
                "update",
                "increment",
            ]
            .into_iter()
            .all(|field| node.child_by_field_name(field).is_none()) =>
        {
            let body_id = node
                .child_by_field_name("body")
                .or_else(|| {
                    named_children.iter().rev().copied().find(|child| {
                        matches!(
                            child.kind(),
                            "block" | "compound_statement" | "statement" | "expression_statement"
                        )
                    })
                })
                .map(|body| body.id());
            let type_id = node.child_by_field_name("type").map(|ty| ty.id());
            let mut header = named_children.into_iter().filter(|child| {
                Some(child.id()) != body_id
                    && Some(child.id()) != type_id
                    && !matches!(child.kind(), "annotation" | "label" | "type")
            });
            Some((header.next()?, header.next()?))
        }
        _ => None,
    }
}
