//! Pattern / match / foreach binding-assignment extraction.
//!
//! Synthesises `FlowEvent::Assign` bindings from `match`/`case`/`when`
//! arm patterns, Rust `if let`/`while let` conditions, `instanceof`/`is`
//! type-test bindings, comprehension `for`-clauses, and foreach headers,
//! so the taint engine sees pattern-bound names carry the subject's taint.

use bonsai_common::{FileId, Span};
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

    // Two grammars to cover: Python `match SUBJECT: case PAT:` (text
    // path) and Rust / Scala / Kotlin / Swift / Dart `match SUBJECT
    // { PAT => BODY }` (AST path). Rust's tree-sitter grammar
    // exposes `match_expression { value, body: match_block }` and
    // each arm as `match_arm { pattern, value }`. Walk the AST when
    // the kind name reveals it; fall back to the line-based parser
    // for Python's whitespace-delimited match statement.
    if matches!(
        node.kind(),
        "match_expression" | "if_let_expression" | "while_let_expression"
    ) {
        out.extend(extract_rust_style_match_bindings(file, node, src));
        return out;
    }
    let text = node_text(node, src);
    let trimmed = text.trim_start();
    let Some(after_match) = trimmed.strip_prefix("match ") else {
        return out;
    };
    let Some((subject, rest)) = after_match.split_once(':') else {
        return out;
    };
    let subject = subject.trim();
    if !looks_like_bare_identifier(subject) {
        return out;
    }
    let mut targets: Vec<String> = Vec::new();
    for line in rest.lines() {
        let line = line.trim_start();
        let Some(pattern) = line.strip_prefix("case ") else {
            continue;
        };
        let pattern = pattern.split_once(':').map_or(pattern, |(p, _)| p);
        for ident in identifier_tokens_from_text(pattern) {
            if !matches!(
                ident.as_str(),
                "case" | "if" | "in" | "and" | "or" | "not" | "_" | "True" | "False" | "None"
            ) {
                targets.push(ident);
            }
        }
    }
    targets.sort();
    targets.dedup();
    out.extend(targets.into_iter().map(|target| FlowEvent::Assign {
        span: span_of(file, node),
        target,
        source_name: Some(subject.to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }));
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
        let val_text = node_text(&val, src);
        let source_name = looks_like_bare_identifier(val_text.trim()).then(|| val_text.trim().to_string());
        let source_names = identifier_tokens_from_text(val_text);
        let pat_text = node_text(&pat, src);
        for ident in binding_tokens_from_pattern(pat_text) {
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
    let subject_text = node_text(&subject, src).trim();
    if subject_text.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "stab_clause" {
            if let Some(pattern) = current.child_by_field_name("left") {
                let pattern_text = node_text(&pattern, src);
                for target in binding_targets_from_pattern_node(&pattern, src) {
                    if !elixir_pattern_target_is_binding(pattern_text, &target) {
                        continue;
                    }
                    if let Some(assign) = pattern_binding_assign(file, &pattern, &target, subject_text) {
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

fn elixir_pattern_target_is_binding(pattern: &str, target: &str) -> bool {
    let target = target.trim_start_matches(&['$', '@', '%'][..]);
    if target.is_empty() || target == "_" || target.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) {
        return false;
    }
    pattern.match_indices(target).any(|(start, _)| {
        let end = start + target.len();
        let before = pattern[..start].chars().next_back();
        let after = pattern[end..].chars().next();
        let boundary_before = before.is_none_or(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()));
        let boundary_after = after.is_none_or(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()));
        boundary_before && boundary_after && before != Some(':')
    })
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
                    let source_text = node_text(&source, src).trim();
                    let source_name =
                        looks_like_bare_identifier(source_text).then(|| source_text.to_string());
                    let mut source_names = identifier_tokens_from_text(source_text);
                    if source_names.is_empty() {
                        if let Some(source_name) = source_name.as_ref() {
                            source_names.push(source_name.clone());
                        }
                    }
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
                let source_text = node_text(&source, src).trim();
                for target in binding_targets_from_pattern_node(&pattern, src) {
                    if let Some(assign) = pattern_binding_assign(file, &current, &target, source_text) {
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
            let subject_text = node_text(&current, src);
            let source_text = subject_text
                .split_once('=')
                .map(|(_, rhs)| rhs.trim())
                .unwrap_or_default();
            if let Some(assign) = pattern_binding_assign(file, &current, target, source_text) {
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
    let subject_text = node_text(&subject, src).trim();
    let source_name = looks_like_bare_identifier(subject_text).then(|| subject_text.to_string());
    let mut source_names = identifier_tokens_from_text(subject_text);
    if source_names.is_empty() {
        if let Some(source_name) = source_name.as_ref() {
            source_names.push(source_name.clone());
        }
    }

    let mut targets: Vec<String> = Vec::new();
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "in_clause" {
            if let Some(pattern) = current
                .child_by_field_name("pattern")
                .or_else(|| first_named_child(&current))
            {
                let pattern_text = node_text(&pattern, src);
                for target in binding_tokens_from_pattern(pattern_text) {
                    if !targets.iter().any(|seen| same_identifier_name(seen, &target)) {
                        targets.push(target);
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
    let subject_text = node_text(&subject, src).trim();
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
                    if let Some(assign) = pattern_binding_assign(file, &pattern, &target, subject_text) {
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

pub(super) fn binding_targets_from_pattern_node(pattern: &Node<'_>, src: &[u8]) -> Vec<String> {
    let mut targets = Vec::new();
    let mut cursor = pattern.walk();
    let mut stack = vec![*pattern];
    while let Some(current) = stack.pop() {
        if current.kind() == "var" {
            push_binding_target(&mut targets, node_text(&current, src));
        }
        for field in ["name", "bound_identifier"] {
            if let Some(target) = current.child_by_field_name(field) {
                push_binding_target(&mut targets, node_text(&target, src));
            }
        }
        if current.kind() == "variable_pattern" {
            let mut child_cursor = current.walk();
            let mut last_identifier = None;
            for child in current.named_children(&mut child_cursor) {
                if matches!(
                    child.kind(),
                    "identifier"
                        | "simple_identifier"
                        | "field_identifier"
                        | "shorthand_property_identifier_pattern"
                ) {
                    last_identifier = Some(node_text(&child, src));
                }
            }
            if let Some(target) = last_identifier {
                push_binding_target(&mut targets, target);
            }
        }
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    if targets.is_empty() {
        for target in binding_tokens_from_pattern(node_text(pattern, src)) {
            push_binding_target(&mut targets, &target);
        }
    }
    targets.sort();
    targets.dedup_by(|left, right| same_identifier_name(left, right));
    targets
}

fn push_binding_target(out: &mut Vec<String>, raw: &str) {
    let target = raw.trim().trim_start_matches(&['$', '@', '%'][..]);
    if !target.is_empty()
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
    source_text: &str,
) -> Option<FlowEvent> {
    let source_text = source_text.trim();
    if source_text.is_empty() || !looks_like_bare_identifier(target) {
        return None;
    }
    let source_name = looks_like_bare_identifier(source_text).then(|| source_text.to_string());
    let mut source_names = identifier_tokens_from_text(source_text);
    if source_names.is_empty() {
        if let Some(source_name) = source_name.as_ref() {
            source_names.push(source_name.clone());
        }
    }
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
    let subject_text = node_text(&subject, src);
    let source_name = if looks_like_bare_identifier(subject_text.trim()) {
        Some(subject_text.trim().to_string())
    } else {
        None
    };
    let source_names = identifier_tokens_from_text(subject_text);
    let mut out: Vec<FlowEvent> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    let mut visit_pattern = |pat_node: &Node<'_>| {
        let pat_text = node_text(pat_node, src);
        for ident in binding_tokens_from_pattern(pat_text) {
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
                "match_arm" | "match_block_arm" | "match_expression_arm"
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
    let lhs_text = node_text(&lhs, src);
    let rhs_text = node_text(&rhs, src);
    let targets = binding_tokens_from_pattern(lhs_text);
    if targets.is_empty() {
        return Vec::new();
    }
    let source_name = if looks_like_bare_identifier(rhs_text.trim()) {
        Some(rhs_text.trim().to_string())
    } else {
        None
    };
    let source_names = identifier_tokens_from_text(rhs_text);
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
    let text = node_text(node, src);
    foreach_binding_assigns_from_text(span_of(file, node), text)
}

/// Synthesize loop-variable bindings from a source-level foreach
/// header. Adapters call this as a repair pass when their grammar
/// exposes a loop body but not a standard foreach node kind.
pub fn foreach_binding_assigns_from_text(span: Span, text: &str) -> Vec<FlowEvent> {
    let Some((lhs, rhs)) = split_foreach_header(text) else {
        return Vec::new();
    };
    let targets = binding_tokens_from_pattern(lhs);
    if targets.is_empty() {
        return Vec::new();
    }
    let source_name = if looks_like_bare_identifier(rhs.trim()) {
        Some(rhs.trim().to_string())
    } else {
        None
    };
    // Loop element bindings semantically derive from the iterable
    // expression, regardless of whether that iterable is a bare
    // collection (`for x in xs`) or a call (`for x in split(cmd)`).
    // Surface operand identifiers as source_names so the taint engine
    // can propagate through the binding without assuming anything
    // about an arbitrary callee's return value.
    let source_names = iterable_source_names_from_text(rhs);
    targets
        .into_iter()
        .map(|target| FlowEvent::Assign {
            span,
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
