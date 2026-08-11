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

pub(super) fn extract_match_binding_assigns(
    file: FileId,
    node: &Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    if let Some(extract) = handler.projected_pattern_binding_extractor {
        let out = extract(*node, src)
            .into_iter()
            .filter_map(|site| projected_pattern_binding_assign(file, site, src, handler))
            .collect();
        return dedup_assign_events(out);
    }
    let Some(extract) = handler.pattern_binding_extractor else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for site in extract(*node) {
        for target in binding_targets_from_pattern_node(&site.pattern, src, handler) {
            if let Some(assign) =
                pattern_binding_assign(file, &site.span_node, &target, site.source, src, handler)
            {
                out.push(assign);
            }
        }
    }
    dedup_assign_events(out)
}

fn projected_pattern_binding_assign(
    file: FileId,
    site: ProjectedPatternBindingSite<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    let mut targets = binding_targets_from_pattern_node(&site.target, src, handler);
    if targets.len() != 1 {
        return None;
    }
    let target = targets.pop()?;
    let (source_name, source_names) = binding_source_facts(site.source, src, handler);
    let carrier_name = source_name.clone();
    let carrier_names = source_names.clone();
    let source_name = source_name.map(|name| project_pattern_source(name, &site.projection));
    let mut source_names = if let Some(source_name) = &source_name {
        vec![source_name.clone()]
    } else {
        source_names
            .iter()
            .map(|name| project_pattern_source(name.clone(), &site.projection))
            .collect()
    };
    // A projected source preserves field-sensitive flows into the capture,
    // while the whole discriminant is also a semantic input to every value
    // destructured from it.  Retaining both relations means a source proven
    // only for `subject.field` does not taint sibling captures, but a source
    // proven for the complete `subject` does taint values extracted from it.
    // This is compiler-level pattern semantics; no language or API spelling
    // participates in the shared lowering.
    if !site.projection.is_empty() {
        source_names.extend(carrier_name.into_iter().chain(carrier_names));
    }
    source_names.retain(|name| !same_identifier_name(name, &target));
    source_names.sort();
    source_names.dedup();
    if source_name.is_none() && source_names.is_empty() {
        return None;
    }
    Some(FlowEvent::Assign {
        span: span_of(file, &site.span_node),
        target,
        source_name,
        source_call: None,
        source_call_args: Vec::new(),
        source_names,
        declares_new_binding: false,
        value_kind: Some(crate::AssignValueKind::Destructure),
    })
}

fn project_pattern_source(mut base: String, projection: &[PatternSourceProjection]) -> String {
    for segment in projection {
        match segment {
            PatternSourceProjection::Field(field) if !field.is_empty() => {
                base.push('.');
                base.push_str(field);
            }
            PatternSourceProjection::Element(index) => {
                base.push('.');
                base.push_str(&index.to_string());
            }
            PatternSourceProjection::Descendants => base.push_str(".*"),
            PatternSourceProjection::Field(_) => {}
        }
    }
    base
}

/// Collect exact `(pattern, discriminant)` relations from a parsed
/// match/switch construct. The owning adapter supplies every field and node
/// kind; shared lowering only packages the structural relation.
pub fn pattern_binding_sites_from_arms<'tree>(
    node: Node<'tree>,
    subject_fields: &[&str],
    arm_kinds: &[&str],
    pattern_fields: &[&str],
    direct_pattern_kinds: &[&str],
) -> Vec<crate::kit::PatternBindingSite<'tree>> {
    let Some(source) = subject_fields
        .iter()
        .find_map(|field| node.child_by_field_name(field))
    else {
        return Vec::new();
    };
    let mut sites = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if arm_kinds.contains(&current.kind()) {
            for pattern in pattern_fields
                .iter()
                .filter_map(|field| current.child_by_field_name(field))
            {
                sites.push(crate::kit::PatternBindingSite {
                    span_node: current,
                    pattern,
                    source,
                });
            }
            let mut cursor = current.walk();
            for pattern in current
                .named_children(&mut cursor)
                .filter(|child| direct_pattern_kinds.contains(&child.kind()))
            {
                sites.push(crate::kit::PatternBindingSite {
                    span_node: current,
                    pattern,
                    source,
                });
            }
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    sites
}

pub fn binding_targets_from_pattern_node(
    pattern: &Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<String> {
    let mut targets = Vec::new();
    let mut stack = vec![*pattern];
    while let Some(current) = stack.pop() {
        if handler.non_binding_pattern_kinds.contains(&current.kind()) {
            continue;
        }
        if handler.binding_lhs_pattern_kinds.contains(&current.kind()) {
            if let Some(binding) = handler
                .binding_pattern_field_names
                .iter()
                .find_map(|field| current.child_by_field_name(field))
                .or_else(|| first_named_child(&current))
            {
                stack.push(binding);
            }
            continue;
        }
        if handler.binding_identifier_kinds.contains(&current.kind()) {
            push_binding_target(&mut targets, current, src, handler);
            continue;
        }
        if handler
            .multi_segment_value_pattern_kinds
            .contains(&current.kind())
            && current.named_child_count() > 1
        {
            continue;
        }
        if handler.pattern_head_value_kinds.contains(&current.kind()) {
            let mut cursor = current.walk();
            let children = current.named_children(&mut cursor).skip(1).collect::<Vec<_>>();
            stack.extend(children.into_iter().rev());
            continue;
        }
        if handler.shorthand_field_kinds.contains(&current.kind()) {
            if let Some(value) = handler
                .aggregate_value_field_names
                .iter()
                .find_map(|field| current.child_by_field_name(field))
            {
                stack.push(value);
            } else if let Some(key) = handler
                .aggregate_key_field_names
                .iter()
                .find_map(|field| current.child_by_field_name(field))
            {
                push_binding_target(&mut targets, key, src, handler);
            } else if current.named_child_count() == 0 {
                // Rust struct shorthand and JavaScript object shorthand are
                // complete binding leaves: the same parsed node is both the
                // selected field and its local binding. No source-text key
                // inference is involved; the adapter explicitly admitted
                // this grammar kind as shorthand syntax.
                push_binding_target(&mut targets, current, src, handler);
            }
            continue;
        }
        if handler.aggregate_pair_kinds.contains(&current.kind()) {
            if let Some(value) = handler
                .aggregate_value_field_names
                .iter()
                .find_map(|field| current.child_by_field_name(field))
            {
                stack.push(value);
                continue;
            }
        }
        let mut cursor = current.walk();
        let mut children = Vec::new();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                let field_is_metadata = cursor
                    .field_name()
                    .is_some_and(|field| handler.non_binding_pattern_field_names.contains(&field));
                if child.is_named() && !field_is_metadata {
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

fn push_binding_target(out: &mut Vec<String>, node: Node<'_>, src: &[u8], handler: &GrammarHandler) {
    let target = handler
        .binding_name_extractor
        .and_then(|extract| extract(node, src))
        .unwrap_or_else(|| node_text(&node, src).trim().to_string());
    let target = target.trim();
    if !target.is_empty()
        && looks_like_bare_identifier(target)
        && handler.binding_name_filter.is_none_or(|filter| filter(target))
        && !out.iter().any(|seen| same_identifier_name(seen, target))
    {
        out.push(target.to_string());
    }
}

pub fn pattern_binding_assign(
    file: FileId,
    span_node: &Node<'_>,
    target: &str,
    source: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    if !looks_like_bare_identifier(target) {
        return None;
    }
    let (source_name, mut source_names) = binding_source_facts(source, src, handler);
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

fn binding_source_facts(
    source: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> (Option<String>, Vec<String>) {
    let source_name = argument_place(&source, src, handler);
    let mut source_names = extract_rhs_expr_operands(&source, src, handler);
    if source_names.is_empty() {
        source_names.extend(source_name.iter().cloned());
    }
    source_names.sort();
    source_names.dedup();
    (source_name, source_names)
}

pub fn dedup_assign_events(events: Vec<FlowEvent>) -> Vec<FlowEvent> {
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
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    let Some((lhs, rhs)) = handler
        .comprehension_binding_extractor
        .and_then(|extract| extract(*clause))
    else {
        return Vec::new();
    };
    let targets = binding_targets_from_pattern_node(&lhs, src, handler);
    if targets.is_empty() {
        return Vec::new();
    }
    let (source_name, source_names) = binding_source_facts(rhs, src, handler);
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

pub(super) fn extract_foreach_binding_assigns(
    file: FileId,
    node: &Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<FlowEvent> {
    if let Some((binding, iterable)) = handler
        .foreach_binding_extractor
        .and_then(|extract| extract(*node))
    {
        let targets = binding_targets_from_pattern_node(&binding, src, handler);
        if !targets.is_empty() {
            let (source_name, source_names, source_call, source_call_args) =
                foreach_binding_source_facts(iterable, src, handler);
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
    src: &[u8],
    handler: &GrammarHandler,
) -> (Option<String>, Vec<String>, Option<String>, Vec<String>) {
    if let Some((source_call, source_call_args)) = extract_direct_call_info(&iterable, src, handler) {
        return (None, Vec::new(), source_call, source_call_args);
    }
    let source_name = argument_place(&iterable, src, handler);
    let mut source_names = extract_rhs_expr_operands(&iterable, src, handler);
    if source_names.is_empty() {
        source_names.extend(source_name.iter().cloned());
    }
    source_names.sort();
    source_names.dedup();
    (source_name, source_names, None, Vec::new())
}
