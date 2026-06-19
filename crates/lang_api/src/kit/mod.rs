//! Shared helpers for building adapters on top of
//! `tree-sitter-language-pack`. Adapter crates are free to ignore this and
//! hand-roll their implementation.
//!
//! The highlights consumers rely on:
//!
//! - [`language_from_pack`] / [`parse_with`] — Tree-sitter boilerplate.
//! - [`GrammarHandler`] + [`walk_flow_events`] — grammar-driven extraction
//!   of branches, loops, calls, assignments, returns, throws. This is what
//!   lets the cross-module tracer emit real execution flow rather than a
//!   flat list of call sites.
//! - [`decl_index_with_handler`] — full adapter pipeline (decls + refs
//!   + per-function flow events) using a supplied [`GrammarHandler`].
//!
//! ## Module navigation (sections within this file)
//!
//! This file is large; future contributors should split it along
//! these existing seams (see `docs/contributing/adapter-contract.mdx` for the
//! formal contract; this comment is a navigation aid):
//!
//! 1. **Tree-sitter primitives** (lines ~22-130): `language_from_pack`,
//!    `parse_with`, `collect_kinds`, `node_text`, `span_of`,
//!    `first_named_child*`, `first_identifier*`.
//! 2. **Return / throw / catch extraction** (~134-330): all the
//!    `extract_return_value_*`, `extract_throw_value_*`,
//!    `extract_catch_param` family.
//! 3. **Identifier-shape detection** (~117-340): `looks_like_*`
//!    predicates.
//! 4. **`GrammarHandler` config + `GENERIC_HANDLER`** (~353-700):
//!    declarative grammar configuration shared across adapters.
//! 5. **Flow-event walker** (~807-1705): `walk_flow_events` and
//!    `walk_into`. The core of the framework — drives all per-event
//!    emission.
//! 6. **Branch repair** (~2761): `repair_branch_events_by_else_keyword`
//!    and helpers. Last-resort fix-up for grammars that lump both
//!    arms under one body field.
//! 7. **Pseudo-call synthesis** (~2139-2350): `pseudo_call_event`,
//!    `jsx_call_from_opening`, `named_child_args`,
//!    `infix_expression_args`. Adapters lower their language's
//!    non-call-shaped invocations (Scala infix, JSX components,
//!    Dart selector chains) here.
//! 8. **Assignment / qualified-target normalization** (~2353-2487):
//!    `qualified_assign_target`, `normalise_qualified_text`,
//!    `assignment_rhs_text`.
//! 9. **Foreach header parsing** (~3256-3300): `split_foreach_header`,
//!    binding-keyword stripping.
//! 10. **Param extraction** (~5400-): `extract_param_names`,
//!     `extract_param_annotations`.
//!
//! Each section can become its own file (`kit/walker.rs`, `kit/branch_repair.rs`, ...)
//! during normal maintenance. Pure-data items (`GENERIC_HANDLER`,
//! `COMMON_CALL_KINDS`) and `pub` re-exports stay at the top level.

mod branch_repair;
mod foreach_header;
mod identifiers;
mod param_extraction;
mod pseudo_call;
mod qualified;
mod return_extraction;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

pub use identifiers::{
    first_identifier_descendant, first_identifier_like_child, first_named_child, first_named_child_of_kind,
    looks_like_bare_identifier, looks_like_identifier,
};
pub use param_extraction::extract_param_annotations;
pub use return_extraction::{
    extract_catch_param, extract_return_value_name, extract_return_value_text, extract_throw_value_name,
};

use identifiers::has_direct_child_kind;
use param_extraction::extract_param_names;
use pseudo_call::pseudo_call_event;
use qualified::{
    assignment_rhs_text, binary_operator_is_assignment, normalise_qualified_text, qualified_assign_target,
    type_only_declaration_without_initializer,
};

use crate::{AdapterContext, AdapterError, CallArg, CallKind, FlowEvent, ImportScope, LoopKind};
use bonsai_common::{FileId, Span};
use bonsai_vfs::FileSnapshot;
use std::sync::Arc;
use tree_sitter::{Language, Node, Tree};

use branch_repair::{looks_like_branch_arm_node, repair_branch_events_by_else_keyword};
use foreach_header::split_foreach_header;

/// Internal carrier name for language-level rest/varargs values that
/// have no user-visible identifier, such as Lua `...` and C-family
/// `...` parameters. This is syntax semantics, not a security rule.
pub const SYNTHETIC_VARARGS_PARAM: &str = "__bonsai_varargs";

/// Look up a language from the pack and wrap any error nicely.
pub fn language_from_pack(name: &str) -> Result<Language, AdapterError> {
    tree_sitter_language_pack::get_language(name)
        .map_err(|e| AdapterError::GrammarUnavailable(format!("{name}: {e}")))
}

/// Parse a single file using the given pack name. Returns `None` if the
/// file is unknown to the VFS.
pub fn parse_with(name: &str, file: FileId, ctx: &AdapterContext<'_>) -> Option<(FileSnapshot, Arc<Tree>)> {
    let snapshot = ctx.vfs.snapshot(file).ok()?;
    let language = language_from_pack(name).ok()?;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(snapshot.text.as_bytes(), None)?;
    Some((snapshot, Arc::new(tree)))
}

/// Reshape pattern-match arms inside flat `Branch::then_events` lists
/// into nested per-arm `Branch` chains so the engine forks state per
/// arm. Used by adapters whose match/switch grammar emits a single
/// `Branch` event whose `then_events` contains every arm's events
/// concatenated (today: Scala `match_expression`, Swift
/// `switch_statement`).
///
/// `arm_spans` is one entry per match expression in the file; each
/// entry is the list of arm-body byte spans for that match. The
/// helper finds Branch events whose `then_events` contain at least
/// one event from each arm-body span (heuristic for "this Branch is
/// the match's collapsed form") and rewrites `then_events` into a
/// right-leaning chain: `arm[0]` body in `then_events`, the rest
/// recursively in `else_events`. Each arm sees a fresh fork of the
/// pre-match state and unions back at the merge.
///
/// Adapter contract: collect arm body spans by walking the parse
/// tree's match nodes, then pass to this helper. See
/// `crates/lang_scala/src/lib.rs::collect_scala_match_arm_spans` for
/// the canonical example.
#[allow(clippy::ptr_arg)] // explicit `Vec` to mirror the FlowEvent::Branch field shape
pub fn split_match_arms_in_branch_events(
    events: &mut Vec<crate::FlowEvent>,
    arm_spans: &[Vec<bonsai_common::Span>],
) {
    use crate::FlowEvent;
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                // Recurse first so nested matches peel from the inside out.
                split_match_arms_in_branch_events(then_events, arm_spans);
                split_match_arms_in_branch_events(else_events, arm_spans);
                // Look for the arm-set this Branch's `then_events` covers.
                // A flat Branch from a match expression contains every
                // arm's events; a normal `if` only spans one source region.
                let matched_arm_set = arm_spans
                    .iter()
                    .find(|candidate| then_events_cover_arm_set(then_events, candidate));
                if let Some(arms) = matched_arm_set {
                    *then_events = peel_match_arms(std::mem::take(then_events), arms);
                }
            }
            // Other containers may host a match expression — keep walking.
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                split_match_arms_in_branch_events(body, arm_spans);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                split_match_arms_in_branch_events(body, arm_spans);
                split_match_arms_in_branch_events(catch_events, arm_spans);
                split_match_arms_in_branch_events(finally_events, arm_spans);
            }
            _ => {}
        }
    }
}

/// True iff `then_events` contains at least one event from EACH of the
/// given arm-body spans. That's the heuristic for "this Branch is the
/// flat collapse of a multi-arm match." A single-arm match (or an `if`)
/// has nothing to peel.
fn then_events_cover_arm_set(then_events: &[crate::FlowEvent], arm_spans: &[bonsai_common::Span]) -> bool {
    if arm_spans.len() < 2 {
        return false;
    }
    arm_spans
        .iter()
        .all(|arm_span| then_events_contain_span(then_events, arm_span))
}

/// Does any event in `events` have a span that falls inside `arm_span`?
/// Walks one level deep — recursion lives in
/// `split_match_arms_in_branch_events` instead so peeling can be done
/// in the parent frame.
fn then_events_contain_span(events: &[crate::FlowEvent], arm_span: &bonsai_common::Span) -> bool {
    events
        .iter()
        .any(|ev| span_contains(*arm_span, flow_event_span(ev)))
}

/// Bucket flat arm events by source-span containment, then rebuild as
/// a right-leaning Branch chain so the engine forks state per arm.
///
/// Each event lands in exactly one bucket — the arm whose body span
/// contains it. Events that don't fall inside any arm (rare: a binding
/// emitted between arms, or a synthetic event from a kit post-process)
/// stay sequential before the chain so they execute as part of the
/// pre-match preamble.
fn peel_match_arms(flat: Vec<crate::FlowEvent>, arm_spans: &[bonsai_common::Span]) -> Vec<crate::FlowEvent> {
    use crate::FlowEvent;
    // One bucket per arm; preamble for events outside every arm.
    let mut per_arm_events: Vec<Vec<FlowEvent>> = (0..arm_spans.len()).map(|_| Vec::new()).collect();
    let mut preamble: Vec<FlowEvent> = Vec::new();
    'next_event: for event in flat {
        let event_span = flow_event_span(&event);
        // Find the arm that owns this event's source range, if any.
        for (arm_index, arm_span) in arm_spans.iter().enumerate() {
            if span_contains(*arm_span, event_span) {
                per_arm_events[arm_index].push(event);
                continue 'next_event;
            }
        }
        preamble.push(event);
    }
    // Build the nested Branch chain bottom-up. Innermost arm goes
    // deepest in the else-chain; outermost arm becomes the new Branch's
    // `then_events`. Each intermediate Branch's else holds the rest.
    let outermost_arm_span = arm_spans[0];
    let mut nested_else: Vec<FlowEvent> = Vec::new();
    for (arm_index, arm_events) in per_arm_events.into_iter().enumerate().rev() {
        if arm_index == 0 {
            // Outermost arm: emit the wrapping Branch into the preamble
            // and return — it carries every subsequent arm in its else.
            preamble.push(FlowEvent::Branch {
                span: outermost_arm_span,
                condition: None,
                then_events: arm_events,
                else_events: nested_else,
            });
            return preamble;
        }
        // Intermediate / innermost arm: wrap this arm's events as the
        // current Branch's `then`, with the previously-built nested
        // chain as its `else`.
        nested_else = vec![FlowEvent::Branch {
            span: arm_spans[arm_index],
            condition: None,
            then_events: arm_events,
            else_events: nested_else,
        }];
    }
    nested_else
}

fn flow_event_span(event: &crate::FlowEvent) -> bonsai_common::Span {
    event.span()
}

/// Walk a tree in pre-order, collecting every node whose kind is in `want`.
pub fn collect_kinds<'a>(tree: &'a Tree, want: &[&str]) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut cursor = tree.walk();
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if want.iter().any(|k| *k == node.kind()) {
            out.push(node);
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

pub fn c_family_preproc_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<crate::ImportSpec> {
    let mut imports = Vec::new();
    for include_node in collect_kinds(tree, &["preproc_include"]) {
        let Some(path_node) = include_node.child_by_field_name("path") else {
            continue;
        };
        let module = match path_node.kind() {
            "system_lib_string" => node_text(&path_node, src)
                .trim_matches(|c: char| matches!(c, '<' | '>'))
                .to_string(),
            "string_literal" => first_named_child_of_kind(&path_node, "string_content")
                .map(|content_node| node_text(&content_node, src).to_string())
                .unwrap_or_else(|| node_text(&path_node, src).trim_matches('"').to_string()),
            _ => node_text(&path_node, src).to_string(),
        };
        if module.is_empty() {
            continue;
        }
        imports.push(crate::ImportSpec {
            span: span_of(file, &include_node),
            module,
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: crate::ImportScope::Module,
        });
    }
    imports
}

#[must_use]
pub fn node_text<'a>(node: &Node<'_>, src: &'a [u8]) -> &'a str {
    std::str::from_utf8(&src[node.byte_range()]).unwrap_or("")
}

#[must_use]
pub fn span_of(file: FileId, node: &Node<'_>) -> Span {
    Span::new(
        file,
        u64::try_from(node.start_byte()).unwrap_or(u64::MAX),
        u64::try_from(node.end_byte()).unwrap_or(u64::MAX),
    )
}

/// True when this callable's syntax is broken — its node (or detached
/// body, for split signature/body grammars) contains an ERROR or
/// MISSING node. Flow facts must come only from syntactically correct
/// code: a recovered parse can mis-scope reads, writes, and calls, so a
/// broken callable contributes NO flow events (its decl is still
/// indexed for browsing). `has_error` is the tree-sitter subtree flag —
/// it covers MISSING nodes too and is O(1).
fn callable_has_syntax_error(node: &Node<'_>, body_node: Option<&Node<'_>>) -> bool {
    node.has_error() || body_node.is_some_and(tree_sitter::Node::has_error)
}

/// True when `span` overlaps any of `error_spans`. Zero-width MISSING
/// spans (`start == end`) are treated as touching either side.
fn span_overlaps_error(span: Span, error_spans: &[Span]) -> bool {
    error_spans.iter().any(|err| {
        if err.start == err.end {
            span.start <= err.start && err.start <= span.end
        } else {
            span.start < err.end && err.start < span.end
        }
    })
}

/// Drop the LEAF flow events whose span falls inside a recovered
/// ERROR / MISSING span, while keeping control-flow containers and
/// recursing into their bodies. A container's span covers its whole
/// extent, so filtering it by its own span would discard valid
/// children — instead we keep the container and prune only the leaf
/// events (calls, assigns, returns, …) that the error actually
/// mis-scopes. This preserves flows from the correctly-parsed parts of
/// a callable that has one localized parse error.
fn retain_flow_events_outside_errors(events: &mut Vec<FlowEvent>, error_spans: &[Span]) {
    events.retain_mut(|event| match event {
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            retain_flow_events_outside_errors(then_events, error_spans);
            retain_flow_events_outside_errors(else_events, error_spans);
            true
        }
        FlowEvent::Loop { body, .. } => {
            retain_flow_events_outside_errors(body, error_spans);
            true
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            retain_flow_events_outside_errors(body, error_spans);
            retain_flow_events_outside_errors(catch_events, error_spans);
            retain_flow_events_outside_errors(finally_events, error_spans);
            true
        }
        FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            retain_flow_events_outside_errors(body, error_spans);
            true
        }
        // C/C++ `x = va_arg(ap, TYPE)`: tree-sitter-c/cpp cannot parse the
        // TYPE operand of the `va_arg` builtin (`const char *` → an ERROR
        // node), so the assignment's span always overlaps a benign error.
        // The taint-relevant operand — the `ap` va_list — parses cleanly,
        // and `va_start` taint propagation depends on this Assign surviving.
        // Keep it: the error is in a non-runtime type position, not the
        // value flow.
        leaf @ FlowEvent::Assign { .. } if assign_is_variadic_builtin_read(leaf) => true,
        leaf => !span_overlaps_error(leaf.span(), error_spans),
    });
}

/// True when `event` is an `Assign` whose RHS is a C/C++ `va_arg` /
/// `__builtin_va_arg` builtin read. These are exempt from
/// error-span pruning because the macro's TYPE argument is unparseable
/// by tree-sitter and produces a spurious ERROR node that would
/// otherwise discard the whole assignment.
fn assign_is_variadic_builtin_read(event: &FlowEvent) -> bool {
    matches!(
        event,
        FlowEvent::Assign { source_call: Some(call), .. }
            if call == "va_arg" || call == "__builtin_va_arg"
    )
}

/// Byte spans of every ERROR / MISSING node in the tree. Mirrors the
/// parser's diagnostic walk; only called when the root has errors.
fn syntax_error_spans(tree: &tree_sitter::Tree, file: FileId) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() {
            spans.push(span_of(file, &node));
        }
        if !node.is_error() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.has_error() || child.is_missing() {
                    stack.push(child);
                }
            }
        }
    }
    spans
}

const LARGE_LITERAL_INITIALIZER_BYTES: usize = 64 * 1024;

fn is_large_literal_initializer_node(kind: &str, node: &Node<'_>) -> bool {
    is_initializer_list_kind(kind)
        && node.end_byte().saturating_sub(node.start_byte()) > LARGE_LITERAL_INITIALIZER_BYTES
}

fn is_initializer_list_kind(kind: &str) -> bool {
    matches!(
        kind,
        "initializer_list" | "initializer_list_expression" | "braced_initializer_list"
    )
}

fn is_large_data_declaration_node(kind: &str, node: &Node<'_>) -> bool {
    matches!(kind, "declaration" | "init_declarator" | "field_declaration")
        && node.end_byte().saturating_sub(node.start_byte()) > LARGE_LITERAL_INITIALIZER_BYTES
        && (has_direct_large_literal_initializer_child(node)
            || has_direct_large_initializer_declarator_child(node))
}

fn has_direct_large_literal_initializer_child(node: &Node<'_>) -> bool {
    let mut cursor = node.walk();
    let found = node
        .named_children(&mut cursor)
        .any(|child| is_large_literal_initializer_node(child.kind(), &child));
    found
}

fn has_direct_large_initializer_declarator_child(node: &Node<'_>) -> bool {
    let mut cursor = node.walk();
    let found = node.named_children(&mut cursor).any(|child| {
        child.kind() == "init_declarator"
            && child.end_byte().saturating_sub(child.start_byte()) > LARGE_LITERAL_INITIALIZER_BYTES
            && has_direct_large_literal_initializer_child(&child)
    });
    found
}

/// Synthesize the implicit members that `record` / positional value
/// declarations auto-generate but the grammar emits no nodes for: a
/// canonical constructor (`this.<comp> = <comp>` for each component) and
/// a zero-arg accessor per component (`<comp>()` returns `this.<comp>`).
/// Covers Java records (`parameters` list of `formal_parameter`) and C#
/// positional records (`parameter_list` of `parameter`). Without these,
/// `new R(.., tainted, ..)` and `r.comp()` are opaque and taint cannot
/// thread through the data holder.
///
/// The synthetic constructor's `receiver_field_writes` drive the IDG's
/// constructor field-forwarding (arg → object field); the accessors'
/// `receiver_state_sources` + field-read `Return` let a tainted receiver
/// field flow out through `r.comp()`. The record type must already be
/// indexed as a class-like decl (so `record_declaration` is in the
/// handler's `class_kinds`) — this only adds its missing members.
pub fn synthesize_record_members(index: &mut crate::DeclIndex, tree: &Tree, src: &[u8], file: FileId) {
    let mut next_symbol = index
        .defs
        .iter()
        .map(|d| d.symbol.raw())
        .max()
        .map_or(1, |m| m + 1);
    let mut synthesized: Vec<crate::Decl> = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
        if node.kind() != "record_declaration" {
            continue;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let record_span = span_of(file, &node);
        let Some((parent, module_path, visibility)) = index
            .defs
            .iter()
            .find(|d| d.span == record_span)
            .map(|d| (Some(d.symbol), d.module_path.clone(), d.visibility))
        else {
            continue;
        };
        // The canonical component list is the record's own direct
        // parameter list (`parameters` in Java, `parameter_list` in C#) —
        // NOT params of any method declared in the record body.
        let mut components: Vec<(String, Span)> = Vec::new();
        let mut rc = node.walk();
        for child in node.children(&mut rc) {
            // Java: `formal_parameters` (the `parameters:` field); C#:
            // `parameter_list`. Match by node kind so we never pick up a
            // method's param list from the record body.
            if !matches!(child.kind(), "formal_parameters" | "parameter_list") {
                continue;
            }
            let mut pc = child.walk();
            for p in child.children(&mut pc) {
                if !matches!(p.kind(), "formal_parameter" | "parameter") {
                    continue;
                }
                if let Some(cn) = p.child_by_field_name("name") {
                    let comp = node_text(&cn, src).trim().to_string();
                    if !comp.is_empty() {
                        components.push((comp, span_of(file, &cn)));
                    }
                }
            }
            break;
        }
        if components.is_empty() {
            continue;
        }
        let comp_names: Vec<String> = components.iter().map(|(c, _)| c.clone()).collect();

        let has_explicit_ctor = index
            .defs
            .iter()
            .any(|d| d.parent == parent && matches!(d.kind, crate::DeclKind::Constructor));
        if !has_explicit_ctor {
            let receiver_field_writes = components
                .iter()
                .enumerate()
                .map(|(idx, (comp, comp_span))| crate::FieldWrite {
                    span: *comp_span,
                    target: format!("this.{comp}"),
                    source_param_indices: vec![idx],
                })
                .collect::<Vec<_>>();
            synthesized.push(crate::Decl {
                symbol: bonsai_common::SymbolId::new(next_symbol),
                kind: crate::DeclKind::Constructor,
                name: node_text(&name_node, src).trim().to_string(),
                qualified_name: None,
                module_path: module_path.clone(),
                span: span_of(file, &name_node),
                name_span: span_of(file, &name_node),
                visibility,
                parent,
                body_span: Some(span_of(file, &name_node)),
                flow_events: Vec::new(),
                has_implicit_returns: false,
                params: comp_names.clone(),
                param_annotations: Vec::new(),
                type_aliases: Vec::new(),
                bases: Vec::new(),
                receiver_param_index: None,
                receiver_field_writes,
                implicit_receiver_names: vec!["this".to_string()],
                receiver_state_sources: Vec::new(),
                return_type: None,
                is_variadic: false,
            });
            next_symbol += 1;
        }

        for (comp, comp_span) in &components {
            let already_declared = index
                .defs
                .iter()
                .any(|d| d.parent == parent && d.name == *comp && d.params.is_empty());
            if already_declared {
                continue;
            }
            let field = format!("this.{comp}");
            synthesized.push(crate::Decl {
                symbol: bonsai_common::SymbolId::new(next_symbol),
                kind: crate::DeclKind::Method,
                name: comp.clone(),
                qualified_name: None,
                module_path: module_path.clone(),
                span: *comp_span,
                name_span: *comp_span,
                visibility,
                parent,
                body_span: Some(*comp_span),
                flow_events: vec![crate::FlowEvent::Return {
                    span: *comp_span,
                    value_text: Some(field.clone()),
                    value_name: Some(field.clone()),
                }],
                has_implicit_returns: false,
                params: Vec::new(),
                param_annotations: Vec::new(),
                type_aliases: Vec::new(),
                bases: Vec::new(),
                receiver_param_index: None,
                receiver_field_writes: Vec::new(),
                implicit_receiver_names: vec!["this".to_string()],
                receiver_state_sources: vec![field],
                return_type: None,
                is_variadic: false,
            });
            next_symbol += 1;
        }
    }
    index.defs.extend(synthesized);
}

/// Find the descendant of `root` whose byte range matches `span`,
/// preferring nodes whose kind is in `expected_kinds` when multiple
/// nodes share an exact span (e.g. a `statements` wrapper and the
/// `try_expression` it contains both span the same range).
///
/// Resolution order: exact-span match with kind in `expected_kinds`
/// → any exact-span match → smallest enclosing node. Returns `None`
/// only if no node touches `span`.
///
/// Used by adapter post-processes (Java / Kotlin / C# typed-exception
/// extraction, etc.) that have a `FlowEvent` span and want to walk
/// back into the parse tree to read structural detail the kit didn't
/// surface in the event itself.
#[must_use]
pub fn node_at_span<'a>(root: Node<'a>, span: Span, expected_kinds: &[&str]) -> Option<Node<'a>> {
    // Three candidates collected during the walk; preference is the
    // typed exact match, then any exact match, then the smallest
    // enclosing node (used as a last resort when the kit's emitted
    // span has been adjusted away from a real grammar node boundary).
    let mut exact_typed: Option<Node<'a>> = None;
    let mut exact_any: Option<Node<'a>> = None;
    let mut tightest_container: Option<Node<'a>> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let node_start = u64::try_from(node.start_byte()).unwrap_or(u64::MAX);
        let node_end = u64::try_from(node.end_byte()).unwrap_or(u64::MAX);
        // An exact byte-range match wins outright if the kind matches.
        // If only the range matches, hold it as a fallback.
        if node_start == span.start && node_end == span.end {
            if expected_kinds.iter().any(|k| *k == node.kind()) {
                exact_typed.get_or_insert(node);
            } else {
                exact_any.get_or_insert(node);
            }
        }
        // Track the tightest containing node so we can return *something*
        // even if no node spans the requested range exactly.
        let node_contains_span = node_start <= span.start && node_end >= span.end;
        if node_contains_span {
            let node_width = node_end - node_start;
            let prev_width = tightest_container.map(|prev| (prev.end_byte() - prev.start_byte()) as u64);
            if prev_width.is_none_or(|prev| node_width < prev) {
                tightest_container = Some(node);
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    exact_typed.or(exact_any).or(tightest_container)
}

/// Normalize `target = callee(args...)` assignment facts so dataflow
/// crosses the call edge instead of also treating the callee and
/// argument tokens as direct assignment RHS carriers.
///
/// Adapters often synthesize call-result assignments from a broad CST
/// expression node, which can leave `source_name = Some(callee)` and
/// `source_names = [callee, arg, ...]`. That duplicates the
/// source-to-target path and can fabricate self-loop or overtainted
/// chains. Keep semantic receiver tokens because method receivers can
/// be data-bearing (`target.call(payload)`), and keep uppercase
/// receiver factory tails (`Logger.getLogger`) for existing type
/// inference heuristics.
pub fn normalize_call_result_assignment_sources(events: &mut [crate::FlowEvent]) {
    for event_index in 0..events.len() {
        let adjacent_call_args = adjacent_call_args_for_call_result_assignment(events, event_index);
        match &mut events[event_index] {
            crate::FlowEvent::Assign {
                source_name,
                source_call: Some(source_call),
                source_call_args,
                source_names,
                ..
            } => {
                if !adjacent_call_args.is_empty()
                    && (source_call_args.is_empty() || adjacent_call_args.len() > source_call_args.len())
                {
                    *source_call_args = adjacent_call_args;
                }
                *source_name = None;
                prune_call_result_source_names(source_call, source_call_args, source_names);
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_call_result_assignment_sources(then_events);
                normalize_call_result_assignment_sources(else_events);
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => {
                normalize_call_result_assignment_sources(body);
            }
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_call_result_assignment_sources(body);
                normalize_call_result_assignment_sources(catch_events);
                normalize_call_result_assignment_sources(finally_events);
            }
            _ => {}
        }
    }
}

fn adjacent_call_args_for_call_result_assignment(
    events: &[crate::FlowEvent],
    event_index: usize,
) -> Vec<String> {
    let Some(crate::FlowEvent::Assign {
        source_call: Some(source_call),
        source_call_args,
        span: assign_span,
        ..
    }) = events.get(event_index)
    else {
        return Vec::new();
    };

    events
        .iter()
        .skip(event_index + 1)
        .take(3)
        .find_map(|event| match event {
            crate::FlowEvent::Call { name, args, span, .. }
                if call_result_names_match(source_call, name)
                    && span.file == assign_span.file
                    && span.start >= assign_span.start
                    && !args.is_empty()
                    && (source_call_args.is_empty() || args.len() > source_call_args.len()) =>
            {
                Some(args.iter().map(|arg| arg.value_text.clone()).collect())
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn prune_call_result_source_names(
    source_call: &str,
    source_call_args: &[String],
    source_names: &mut Vec<String>,
) {
    let call = source_call.trim();
    if call.is_empty() {
        return;
    }
    let receiver_and_tail = call_receiver_and_tail(call);
    let arg_texts = source_call_args
        .iter()
        .map(|arg| arg.trim())
        .filter(|arg| !arg.is_empty())
        .collect::<Vec<_>>();
    let arg_identifiers = source_call_args
        .iter()
        .flat_map(|arg| call_result_identifier_tokens(arg))
        .collect::<Vec<_>>();

    source_names.retain(|name| {
        let name = name.trim();
        if name.is_empty() || name == call || arg_texts.contains(&name) {
            return false;
        }
        let Some((receiver, tail, receiver_is_type)) = receiver_and_tail else {
            return !arg_identifiers.iter().any(|arg| arg == name);
        };
        if name == receiver {
            return true;
        }
        if name == tail {
            return receiver_is_type;
        }
        !arg_identifiers.iter().any(|arg| arg == name)
    });
    dedup_call_result_source_names(source_names);
}

fn call_result_names_match(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    if left == right {
        return true;
    }
    call_result_short_tail(left) == call_result_short_tail(right)
}

fn call_receiver_and_tail(call: &str) -> Option<(&str, &str, bool)> {
    [".", "::", "->"].into_iter().find_map(|separator| {
        let (receiver, tail) = call.rsplit_once(separator)?;
        let receiver = receiver.trim();
        let tail = tail.trim();
        if receiver.is_empty() || tail.is_empty() {
            return None;
        }
        Some((
            receiver,
            tail,
            receiver.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()),
        ))
    })
}

fn call_result_short_tail(name: &str) -> &str {
    name.rsplit(['.', ':', '>']).next().unwrap_or(name).trim()
}

fn call_result_identifier_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            push_unique_call_result_identifier(&mut out, &current);
            current.clear();
        }
    }
    if !current.is_empty() {
        push_unique_call_result_identifier(&mut out, &current);
    }
    out
}

fn push_unique_call_result_identifier(out: &mut Vec<String>, token: &str) {
    if token
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && !out.iter().any(|existing| existing == token)
    {
        out.push(token.to_string());
    }
}

fn dedup_call_result_source_names(source_names: &mut Vec<String>) {
    let mut seen = Vec::<String>::new();
    source_names.retain(|name| {
        if seen.iter().any(|existing| existing == name) {
            false
        } else {
            seen.push(name.clone());
            true
        }
    });
}

/// Strip generics and qualified prefixes from a type-name string,
/// leaving the bare class name. `java.io.IOException` → `IOException`.
/// `List<Foo>` → `List`. `kotlin.collections.MutableList<E>` →
/// `MutableList`.
///
/// Used by adapter typed-exception extraction (Java, Kotlin, C#) to
/// canonicalize `Throw::thrown_type` and `Try::catch_types` so
/// fully-qualified and short forms compare equal.
#[must_use]
pub fn canonical_simple_type_name(text: &str) -> String {
    // L3: strip the same array / nullable / force-unwrap / pointer /
    // reference decorations as `canonical_short_type_name`, so a return
    // type like `User?` / `byte[]` / `*const T` / `&User` resolves to the
    // class indexed under its bare name for base-class expansion. Without
    // this the decorated form misses `by_canonical_name` and no bases are
    // added (a subclass rule `[Base, method]` never fires).
    let trimmed = text
        .trim()
        .trim_start_matches('&')
        .trim()
        .trim_start_matches("*const ")
        .trim_start_matches("*mut ")
        .trim_start_matches('*')
        .trim_start_matches("mut ")
        .trim();
    let head = trimmed.split('<').next().unwrap_or(trimmed);
    let head = head.split('[').next().unwrap_or(head);
    let head = head.rsplit('.').next().unwrap_or(head);
    let head = head.rsplit("::").next().unwrap_or(head).trim();
    head.trim_end_matches('?')
        .trim_end_matches('!')
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// Grammar-driven flow extraction
// ---------------------------------------------------------------------------

/// Per-language classification of Tree-sitter node kinds. Adapter crates
/// supply one of these. The defaults cover the most common kind names
/// across Tree-sitter grammars; language-specific kinds are layered on top.
///
/// Fields are grouped logically below. The struct is intentionally
/// flat rather than nested-structs so adapter declarations stay
/// ergonomic (`GrammarHandler { fn_kinds: ..., ..GENERIC_HANDLER }`).
/// New fields land in their group with a comment.
#[derive(Clone, Debug, Default)]
pub struct GrammarHandler {
    // === Decl shapes ===
    /// Function-like declarations. The walker creates one `Decl` per
    /// match.
    pub fn_kinds: &'static [&'static str],
    /// Class-like declarations (struct, trait, enum, interface, ...).
    pub class_kinds: &'static [&'static str],
    /// Method declarations. Subset of `fn_kinds` for grammars that
    /// distinguish methods from free functions.
    pub method_kinds: &'static [&'static str],
    /// Ancestor node kinds whose function-like children are methods
    /// for receiver-parameter purposes. This is narrower than
    /// `class_kinds` because some grammars expose modules or type
    /// specs as class-like declarations but they do not imply a
    /// receiver binding.
    pub method_context_kinds: &'static [&'static str],
    /// Constructor-shaped method kinds (`__init__`, `constructor`,
    /// `__construct`, `new`, ...).
    pub constructor_method_kinds: &'static [&'static str],
    /// Bare names that adapters treat as constructors regardless of
    /// kind (`__init__`, `constructor`, `__construct`, `init`, `new`).
    pub constructor_names: &'static [&'static str],

    // === Branch / loop shapes ===
    pub if_kinds: &'static [&'static str],
    pub for_kinds: &'static [&'static str],
    pub foreach_kinds: &'static [&'static str],
    pub while_kinds: &'static [&'static str],
    pub do_kinds: &'static [&'static str],
    /// Unconditional infinite-loop constructs (Rust `loop { }`, etc.)
    /// that have no condition expression and no init/update slots.
    /// These map to `LoopKind::Loop` so consumers can distinguish them
    /// from do/while loops.
    pub loop_kinds: &'static [&'static str],

    // === Call / assignment / return / lambda shapes ===
    pub call_kinds: &'static [&'static str],
    pub assignment_kinds: &'static [&'static str],
    pub return_kinds: &'static [&'static str],
    pub throw_kinds: &'static [&'static str],
    pub lambda_kinds: &'static [&'static str],

    // === Try / catch / finally shapes ===
    pub try_kinds: &'static [&'static str],
    pub catch_kinds: &'static [&'static str],
    pub finally_kinds: &'static [&'static str],

    // === Loop control + suspension shapes ===
    pub break_kinds: &'static [&'static str],
    pub continue_kinds: &'static [&'static str],
    pub yield_kinds: &'static [&'static str],
    pub await_kinds: &'static [&'static str],
    pub defer_kinds: &'static [&'static str],
    pub using_kinds: &'static [&'static str],

    // === Receiver / self handling ===
    /// For languages whose grammar represents a method receiver as an
    /// ordinary formal parameter, the adapter declares the receiver's
    /// parameter index here. Consumers must use this metadata instead of
    /// guessing from parameter names.
    pub method_receiver_param_index: Option<usize>,
    /// Receiver spellings for languages whose method receiver is implicit
    /// in the grammar. The adapter has already emitted assignment targets
    /// from tree-sitter member/instance-variable nodes; these spellings let
    /// the adapter summary classify `this.x = arg`, `$this->x = arg`, or
    /// similar receiver-state writes before common taint consumes it.
    pub implicit_receiver_names: &'static [&'static str],
    /// Receiver prefixes for grammars that emit receiver-state writes as a
    /// single prefixed place rather than a member expression. This is adapter
    /// metadata, not taint-engine behavior.
    pub implicit_receiver_prefixes: &'static [&'static str],

    // === Per-language semantic flags ===
    /// Languages such as Rust and Ruby can return the final expression in a
    /// function body without an explicit return keyword. Adapters opt in so
    /// the shared tree-sitter walker can expose that terminal expression as a
    /// normal Return event.
    pub tail_expression_returns: bool,
}

/// A reasonable starter grammar handler covering node names most Tree-sitter
/// grammars agree on. Adapters can override any field with their own slice.
pub const GENERIC_HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &[
        "function_definition",
        "function_declaration",
        "function_item",
        "method_declaration",
        "method_definition",
        "method_signature",
        "constructor_declaration",
        "subroutine_declaration_statement",
        "local_function_statement",
        // Ruby uses bare `method` / `singleton_method` for `def` blocks.
        "method",
        "singleton_method",
        // JavaScript generator functions.
        "generator_function_declaration",
        "generator_function",
    ],
    class_kinds: &[
        "class_definition",
        "class_declaration",
        "class_specifier",
        "struct_item",
        "struct_declaration",
        "struct_specifier",
        "object_declaration",
        "object_definition",
        "trait_item",
        "trait_definition",
        "enum_item",
        "enum_definition",
        "interface_declaration",
        // Java 16+ / C# records — value-type holders whose canonical
        // constructor and component accessors are implicit (synthesized
        // by the adapter), so the type itself must still be indexed as a
        // class so `new R(..)` resolves a constructor candidate.
        "record_declaration",
        // Go's `type X struct/interface { ... }` lowers to a type_spec
        // inside a type_declaration.
        "type_spec",
        // Ruby uses bare `class` / `module` kind names.
        "class",
        "module",
    ],
    method_kinds: &["method_declaration", "method_definition", "method_signature"],
    method_context_kinds: &[
        "class_definition",
        "class_declaration",
        "class_specifier",
        "class",
        "class_body",
        "impl_item",
        "implementation_declaration",
        "class_implementation",
        "interface_declaration",
        "trait_item",
        // Scala singleton object — the contained functions
        // dispatch as methods of the object. (Kotlin's
        // `object Box { ... }` parses as `infix_expression` in
        // tree-sitter-kotlin, not `object_declaration`, and is
        // handled by a Kotlin-adapter post-process.)
        "object_definition",
    ],
    constructor_method_kinds: &["constructor_declaration", "init_declaration"],
    constructor_names: &["__init__", "constructor", "__construct", "init", "new"],
    if_kinds: &[
        "if_statement",
        "if_expression",
        "conditional_expression",
        // Perl's tree-sitter grammar uses `conditional_statement` for `if`.
        "conditional_statement",
        // Ruby uses bare `if`, `unless`, `case`.
        "if",
        "if_modifier",
        "unless",
        "unless_modifier",
        "case",
        "case_match",
        // Switch / match / when all branch on a discriminant.
        "switch_statement",
        "switch_expression",
        "expression_switch_statement",
        "type_switch_statement",
        "match_expression",
        "match_statement",
        "when_expression",
        // Python's `elif` parses as `elif_clause` inside the outer if
        // statement's alternative. Without listing it as a branch kind
        // we'd stop descending at the first elif, losing every later
        // arm's calls.
        "elif_clause",
        // Swift's `guard` is a one-sided branch (fall-through or exit).
        "guard_statement",
    ],
    for_kinds: &[
        "for_statement",
        "for_expression",
        // Perl C-style `for (;;) { ... }` loop.
        "cstyle_for_statement",
        // Ruby's bare `for x in xs` form.
        "for",
    ],
    foreach_kinds: &[
        "for_in_statement",
        "for_of_statement",
        "for_range_loop",
        "enhanced_for_statement",
        "foreach_statement",
    ],
    while_kinds: &[
        "while_statement",
        "while_expression",
        // Perl's generic `while`/`until` loop.
        "loop_statement",
        // Ruby uses bare `while` / `until`.
        "while",
        "until",
    ],
    do_kinds: &["do_statement", "do_while_statement", "repeat_while_statement"],
    loop_kinds: &["loop_expression"],
    call_kinds: COMMON_CALL_KINDS,
    assignment_kinds: &[
        "assignment",
        "assignment_expression",
        "assignment_statement",
        "augmented_assignment",
        "augmented_assignment_expression",
        "compound_assignment_expr",
        "short_var_declaration",
        // Scala `val x = ...` and `var x = ...` bindings.
        "val_definition",
        "var_definition",
        // JS / TS `const x = ...` / `let x = ...` / `var x = ...`.
        // The declaration wraps one or more `variable_declarator`
        // nodes; the walker descends into each and emits an Assign
        // per binding via the `variable_declarator` kind below.
        "variable_declarator",
        // Kotlin / Swift property bindings: `val x = ...` / `let x = ...`.
        "property_declaration",
        // C# local declarations: `var x = init()` / `int x = init()`.
        "variable_declaration",
        "local_declaration_statement",
        // Go `var x T = value` declarations.
        "var_declaration",
        "var_spec",
        // Rust `let x = ...` binding.
        "let_declaration",
        // Python walrus operator `x := value`.
        "named_expression",
        // Dart `var x = ...` / `final x = ...` / typed local bindings.
        "initialized_variable_definition",
        // Erlang's `match_expr` (LHS = RHS pattern match).
        "match_expr",
        // C / C++ / Objective-C `int x = ...` initializer declarators.
        "init_declarator",
    ],
    return_kinds: &[
        "return_statement",
        "return_expression",
        "jump_expression",
        "control_transfer_statement",
        // Ruby uses bare `return`.
        "return",
        // C++20 coroutines.
        "co_return_statement",
    ],
    throw_kinds: &["throw_statement", "throw_expression", "raise_statement"],
    lambda_kinds: &[
        "lambda",
        "lambda_expression",
        "anonymous_function",
        "anonymous_fun",
        "arrow_function",
        "function_expression",
        "closure_expression",
        "anonymous_function_creation_expression",
        "lambda_literal",
        "func_literal",
        // Kotlin wraps its trailing-closure block in `annotated_lambda`
        // which CONTAINS the `lambda_literal`. Treat the wrapper as a
        // lambda too so callers that inline lambda bodies (e.g. higher-
        // order function args like `xs.forEach { ... }`) reach the
        // actual body.
        "annotated_lambda",
        // Ruby uses `do_block` for `do |x| ... end` blocks — it's
        // specifically a closure form, unlike the generic `block`
        // node which appears everywhere and must NOT be treated as a
        // lambda.
        "do_block",
    ],
    try_kinds: &[
        "try_statement",
        "try_expression",
        "try_block",
        "do_statement",
        // Ruby wraps the try region in a `begin` block whose rescue /
        // ensure children act as catch / finally.
        "begin",
        "begin_block",
        // Java's `try (Resource r = ...) { ... }` block — the resource
        // list is the acquisition, the body is the guarded section, and
        // catch/finally may follow.
        "try_with_resources_statement",
    ],
    catch_kinds: &[
        "catch_clause",
        "catch",
        "catch_block",
        // Python / Cython use `except` for the catch arm.
        "except_clause",
        "except",
        // Ruby uses `rescue`.
        "rescue",
        "rescue_clause",
    ],
    finally_kinds: &[
        "finally_clause",
        "finally",
        "finally_block",
        // Ruby uses `ensure`.
        "ensure",
        "ensure_clause",
    ],
    break_kinds: &[
        "break_statement",
        "break_expression",
        // Perl's `last` / `next` / `redo` all lower into a
        // `loopex_expression` whose leading bareword names the effect.
        "loopex_expression",
        "last_statement",
        // Ruby uses bare `break`, `next`, `redo`, `retry` keywords.
        "break",
        "next",
        "redo",
        "retry",
    ],
    continue_kinds: &[
        "continue_statement",
        "continue_expression",
        "continue",
        // Perl's `next` form.
        "next_statement",
    ],
    yield_kinds: &[
        "yield",
        "yield_statement",
        "yield_expression",
        "yield_from_expression",
        // C++20 coroutines.
        "co_yield_statement",
        "co_yield_expression",
    ],
    await_kinds: &[
        "await",
        "await_expression",
        "await_statement",
        // C++20 `co_await expr`.
        "co_await_expression",
    ],
    defer_kinds: &["defer_statement", "defer_expression"],
    using_kinds: &[
        // Python context-manager statement.
        "with_statement",
        // C# `using (var x = ...) { ... }` block form.
        "using_statement",
    ],
    method_receiver_param_index: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
};

/// Kinds of Tree-sitter nodes that represent a call-site across most
/// grammars. Kept as a const for direct use by non-handler consumers.
pub const COMMON_CALL_KINDS: &[&str] = &[
    "call",
    "call_expression",
    "function_call",
    "function_call_expression",
    "method_call",
    "method_call_expression",
    "method_invocation",
    "invocation_expression",
    "method_invocation_expression",
    "scoped_call_expression",
    "object_creation_expression",
    "instance_expression",
    "constructor_invocation",
    "explicit_constructor_invocation",
    "macro_invocation",
    "subroutine_call_expression",
    "generic_function",
    // PHP's `$obj->method()` arrow-call form.
    "member_call_expression",
    // PHP's `$obj?->method()` nullsafe arrow-call form (H13).
    "nullsafe_member_call_expression",
    // Perl's tree-sitter grammar tags bareword calls without parens as an
    // `ambiguous_function_call_expression` — still a call site for us.
    "ambiguous_function_call_expression",
    // Objective-C `[receiver method:arg]` bracket-send — the grammar
    // exposes `receiver` + `method` fields, which `method_receiver_name`
    // already understands. Unique to ObjC; no conflict with other grammars.
    "message_expression",
    // Solidity `emit EventName(args)` — treated as a call to the event
    // so rulepack sink rules targeting event emission (information
    // disclosure, state-change notifications) can fire.
    "emit_statement",
    // Solidity `revert / require / assert(...)` and similar assertion
    // forms — the grammar exposes them as dedicated statement kinds
    // rather than plain calls. Keep them in the call-ref stream so
    // security rules on require-bypass / assert-on-user-input hit.
    "revert_statement",
    // Erlang `Mod:fn(args)` — the WhatsApp tree-sitter grammar tags
    // remote-qualified calls as `remote` rather than wrapping them in
    // `call`. Without this entry top-level remote calls produce no
    // call ref and the resolver cannot link them.
    "remote",
    // Java `String::valueOf` and Kotlin/Scala `String::length` —
    // method references / bound function literals. The grammar
    // exposes the receiver + method as separate fields, identical
    // to a normal call site as far as resolution goes; emitting
    // them as Call refs lets `stream.map(String::valueOf)`
    // participate in the call graph and cross-file resolution.
    "method_reference_expression",
    "method_reference",
    "double_colon_reference",
];

impl GrammarHandler {
    fn is_fn(&self, k: &str) -> bool {
        self.fn_kinds.contains(&k) || GENERIC_HANDLER.fn_kinds.contains(&k)
    }
    fn is_class(&self, k: &str) -> bool {
        self.class_kinds.contains(&k) || GENERIC_HANDLER.class_kinds.contains(&k)
    }
    fn is_if(&self, k: &str) -> bool {
        self.if_kinds.contains(&k) || GENERIC_HANDLER.if_kinds.contains(&k)
    }
    fn is_for(&self, k: &str) -> bool {
        self.for_kinds.contains(&k) || GENERIC_HANDLER.for_kinds.contains(&k)
    }
    fn is_foreach(&self, k: &str) -> bool {
        self.foreach_kinds.contains(&k) || GENERIC_HANDLER.foreach_kinds.contains(&k)
    }
    fn is_while(&self, k: &str) -> bool {
        self.while_kinds.contains(&k) || GENERIC_HANDLER.while_kinds.contains(&k)
    }
    fn is_do(&self, k: &str) -> bool {
        self.do_kinds.contains(&k) || GENERIC_HANDLER.do_kinds.contains(&k)
    }
    fn is_loop(&self, k: &str) -> bool {
        self.loop_kinds.contains(&k) || GENERIC_HANDLER.loop_kinds.contains(&k)
    }
    fn is_call(&self, k: &str) -> bool {
        self.call_kinds.contains(&k) || GENERIC_HANDLER.call_kinds.contains(&k)
    }
    fn is_assignment(&self, k: &str) -> bool {
        self.assignment_kinds.contains(&k) || GENERIC_HANDLER.assignment_kinds.contains(&k)
    }
    fn is_return(&self, k: &str) -> bool {
        self.return_kinds.contains(&k) || GENERIC_HANDLER.return_kinds.contains(&k)
    }
    fn is_throw(&self, k: &str) -> bool {
        self.throw_kinds.contains(&k) || GENERIC_HANDLER.throw_kinds.contains(&k)
    }
    fn is_lambda(&self, k: &str) -> bool {
        self.lambda_kinds.contains(&k) || GENERIC_HANDLER.lambda_kinds.contains(&k)
    }
    fn is_constructor_method(&self, name: &str) -> bool {
        if self.constructor_names.is_empty() {
            GENERIC_HANDLER.constructor_names.contains(&name)
        } else {
            self.constructor_names.contains(&name)
        }
    }
    fn is_try(&self, k: &str) -> bool {
        self.try_kinds.contains(&k) || GENERIC_HANDLER.try_kinds.contains(&k)
    }
    fn is_catch(&self, k: &str) -> bool {
        self.catch_kinds.contains(&k) || GENERIC_HANDLER.catch_kinds.contains(&k)
    }
    fn is_finally(&self, k: &str) -> bool {
        self.finally_kinds.contains(&k) || GENERIC_HANDLER.finally_kinds.contains(&k)
    }
    fn is_break(&self, k: &str) -> bool {
        self.break_kinds.contains(&k) || GENERIC_HANDLER.break_kinds.contains(&k)
    }
    fn is_continue(&self, k: &str) -> bool {
        self.continue_kinds.contains(&k) || GENERIC_HANDLER.continue_kinds.contains(&k)
    }
    fn is_yield(&self, k: &str) -> bool {
        self.yield_kinds.contains(&k) || GENERIC_HANDLER.yield_kinds.contains(&k)
    }
    fn is_await(&self, k: &str) -> bool {
        self.await_kinds.contains(&k) || GENERIC_HANDLER.await_kinds.contains(&k)
    }
    fn is_defer(&self, k: &str) -> bool {
        self.defer_kinds.contains(&k) || GENERIC_HANDLER.defer_kinds.contains(&k)
    }
    fn is_using(&self, k: &str) -> bool {
        self.using_kinds.contains(&k) || GENERIC_HANDLER.using_kinds.contains(&k)
    }
}

/// Walk the subtree rooted at `node` and produce a tree of [`FlowEvent`].
/// The walker:
///
/// - Nests children of branch nodes under `Branch::then_events` / `else_events`.
/// - Nests children of loop nodes under `Loop::body`.
/// - Collects call-sites with their argument text, so the tracer can bind
///   callback parameters to concrete function references.
/// - Flags calls whose callee name matches a class declaration as
///   `CallKind::Constructor` (the tracer routes these to the class's ctor).
///
/// The caller owns `class_names` — the set of every workspace-visible class
/// short name, used for the constructor hint. Keeping it a borrowed slice
/// lets consumers build it once per workspace.
pub fn walk_flow_events(
    root: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    walk_into(root, file, src, handler, class_names, &mut out, true);
    out
}

fn walk_deep_sequence_executable_nodes(
    root: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) {
    let mut stack = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        stack.push(child);
    }
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if is_large_literal_initializer_node(kind, &node) {
            continue;
        }
        if is_initializer_list_kind(kind)
            || kind == "comma_expression"
            || !(handler.is_assignment(kind)
                || handler.is_call(kind)
                || COMMON_CALL_KINDS.contains(&kind)
                || kind == "selector")
        {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
            continue;
        }
        walk_into(node, file, src, handler, class_names, out, false);
    }
}

/// Recursive flow-event emitter. The biggest single function in the
/// kit — drives all per-event emission across 21 languages.
///
/// ## Dispatch order
///
/// The function tries each event-kind dispatch in priority order. The
/// first match consumes the node and recursion stops at this level
/// (children are walked from inside the matched arm if appropriate):
///
/// 1. **Skippable nested fn/class** — early return; their events
///    belong to their own decls.
/// 2. **`if` / `match` / `case`** (line ~709) — emit `Branch` with
///    then/else_events, calls `repair_branch_events_by_else_keyword`.
/// 3. **`for` / `foreach` / `while` / `loop` / `do`** (~790) — emit
///    `Loop { kind, body }`. `extract_foreach_binding_assigns` adds
///    synthetic Assigns for binding shapes.
/// 4. **`return`** (~848) — emit `Return { value_text, value_name }`.
/// 5. **`throw` / `raise` / `panic`** (~890) — emit `Throw`.
/// 6. **`assign` / `=`** (~905) — emit `Assign` with target + source
///    metadata. The biggest arm by far; covers initializers,
///    augmented assigns, qualified-target normalization,
///    constructor field-assigns.
/// 7. **`call` / `new`** (~1195) — emit `Call` with receiver + args.
///    Calls `pseudo_call_event` for JSX / channel send / Dart
///    selector synthesis.
/// 8. **`try` / `catch` / `finally`** (~1288) — emit `Try` with
///    body + catch_events + finally_events.
/// 9. **`break` / `continue`** (~1380, ~1403) — emit terminator
///    events.
/// 10. **`yield` / `await`** (~1415, ~1441) — emit suspension
///     events.
/// 11. **`defer` / `using`** (~1471, ~1484) — emit scope-bound
///     event with body.
///
/// Anything not matched falls through to the catch-all child walk.
///
/// `is_root=true` only on the top-level call from `walk_flow_events`;
/// recursive calls pass `false` so nested fn/class definitions are
/// correctly skipped.
///
/// Comprehension / generator-expression node kinds whose `for_in_clause`
/// binds the loop variable and whose body holds calls/sinks. Shared by
/// the comprehension branch of `walk_into` and the call-argument loop
/// (a genexpr passed as a call arg — `any(f(t) for t in xs)` — exposes
/// the `generator_expression` directly as the call's `arguments` field,
/// so it must be walked AS a comprehension, not iterated as a container).
fn is_comprehension_kind(kind: &str) -> bool {
    matches!(
        kind,
        "list_comprehension"
            | "dict_comprehension"
            | "dictionary_comprehension"
            | "set_comprehension"
            | "generator_expression"
            | "array_comprehension"
    )
}

fn walk_into(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
    is_root: bool,
) {
    let kind = node.kind();
    if is_large_literal_initializer_node(kind, &node) {
        return;
    }
    if is_initializer_list_kind(kind) || kind == "comma_expression" {
        walk_deep_sequence_executable_nodes(node, file, src, handler, class_names, out);
        return;
    }
    if is_large_data_declaration_node(kind, &node) {
        return;
    }

    // Skip over nested function/class definitions — their flow belongs to
    // their own decls. But do walk into their *declarators* to catch inline
    // default-arg expressions (rare; best-effort).
    //
    // Elixir exception: `call` is in its FN_KINDS (Elixir function defs
    // are `def foo do ... end` parsed as a `call`), but the same `call`
    // kind also covers ordinary runtime calls. Only skip the call when
    // it's actually a def-macro; let runtime calls fall through to the
    // call handler below.
    let is_skippable_nested_fn = if !is_root && kind == "call" {
        // Only treat a nested call as a skippable function decl when
        // its target identifier is one of Elixir's def macros.
        elixir_unwrap_def(&node, src).is_some()
    } else {
        !is_root && handler.is_fn(kind)
    };
    if is_skippable_nested_fn || (!is_root && (handler.is_class(kind) || handler.is_lambda(kind))) {
        return;
    }

    if let Some(event) = pseudo_call_event(&node, file, src) {
        out.push(event);
    }

    // Comprehensions / generator expressions across Python, JS, TS.
    // Tree-sitter exposes them as `list_comprehension`,
    // `dict_comprehension`, `set_comprehension`, `generator_expression`
    // (Python), `array_comprehension` / `generator_expression` (JS/TS
    // proposals). Each one has one or more `for_in_clause` children
    // that bind a loop variable from an iterable. Without explicit
    // handling the loop-variable assignment never surfaces — taint
    // on the iterable can't reach the comprehension's body
    // expression. Synthesize an Assign per for-clause + walk the body
    // so calls inside the expression are observed in the enclosing
    // scope's flow events. Adapter-agnostic: relies only on the
    // common `for_in_clause` / `comp_for` shape that all three
    // grammars expose.
    if is_comprehension_kind(kind) {
        // Emit the `for_in_clause` loop-variable bindings BEFORE the body,
        // regardless of AST order (python lays the body out first). This
        // gives the natural flow order — bindings then body — so a NESTED
        // comprehension's chained bindings resolve: `[f(t) for row in rows
        // for t in row]` emits `row<-rows` then `t<-row` then the body, so
        // taint flows rows -> row -> t into the sink. (A single-clause comp
        // worked even body-first since its binding is a direct param, but
        // the two-hop nested chain needs binding-before-body.)
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            let child_kind = child.kind();
            if child_kind == "for_in_clause" || child_kind == "comp_for" {
                out.extend(extract_comprehension_for_clause_assigns(file, &child, src));
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            let child_kind = child.kind();
            if child_kind != "for_in_clause" && child_kind != "comp_for" {
                walk_into(child, file, src, handler, class_names, out, false);
            }
        }
        return;
    }

    if handler.is_if(kind) {
        let then_node = node
            .child_by_field_name("consequence")
            .or_else(|| node.child_by_field_name("then"))
            .or_else(|| node.child_by_field_name("body"))
            .or_else(|| first_named_child_of_kind(&node, "statements"));
        let else_node = node
            .child_by_field_name("alternative")
            .or_else(|| node.child_by_field_name("else"))
            // Solidity's grammar exposes both if arms with the same
            // `body` field. `child_by_field_name("body")` returns the
            // first arm only, so recover the second body-like sibling
            // when no explicit alternative field exists.
            .or_else(|| then_node.and_then(|then| next_named_sibling_within(&node, then)));
        let mut then_events = Vec::new();
        if let Some(n) = then_node {
            walk_into(n, file, src, handler, class_names, &mut then_events, false);
        }
        let mut else_events = Vec::new();
        if let Some(n) = else_node {
            walk_into(n, file, src, handler, class_names, &mut else_events, false);
        }
        // Python's if/elif/elif/else lays out additional elif_clause
        // and else_clause nodes as SIBLINGS inside the if_statement
        // (not as nested alternatives), so the single `alternative`
        // field only exposes the first elif. Walk every remaining
        // elif_clause / else_clause named child so later branches'
        // calls still surface.
        let then_id = then_node.map(|n| n.id());
        let else_id = else_node.map(|n| n.id());
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if Some(child.id()) == then_id || Some(child.id()) == else_id {
                continue;
            }
            if child.kind() == "elif_clause" || child.kind() == "else_clause" {
                walk_into(child, file, src, handler, class_names, &mut else_events, false);
            }
        }
        // Switch/match/when don't expose consequence/alternative fields: if
        // neither path produced any events, walk all named children so the
        // calls inside case arms still surface in the flow.
        if then_events.is_empty() && else_events.is_empty() {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_into(child, file, src, handler, class_names, &mut then_events, false);
            }
        }
        repair_branch_events_by_else_keyword(&mut then_events, &mut else_events, &node, src);
        let match_bindings = extract_match_binding_assigns(file, &node, src);
        if !match_bindings.is_empty() {
            let mut prefixed = match_bindings.clone();
            prefixed.extend(then_events);
            then_events = prefixed;
            if !else_events.is_empty() {
                let mut prefixed_else = match_bindings;
                prefixed_else.extend(else_events);
                else_events = prefixed_else;
            }
        }
        // Also descend into the discriminant for any nested calls.
        // Grammars name it differently:
        //   * if:    `condition`
        //   * match / switch (Python, Rust): `subject` / `value`
        //   * when-expression (Kotlin):       `subject`
        let mut condition = None;
        for field in ["condition", "subject", "value", "discriminant"] {
            if let Some(cond) = node.child_by_field_name(field) {
                condition.get_or_insert_with(|| node_text(&cond, src).trim().to_string());
                walk_into(cond, file, src, handler, class_names, out, false);
            }
        }
        out.push(FlowEvent::Branch {
            span: span_of(file, &node),
            condition,
            then_events,
            else_events,
        });
        return;
    }

    if handler.is_for(kind)
        || handler.is_foreach(kind)
        || handler.is_while(kind)
        || (handler.is_do(kind) && !has_direct_child_kind(&node, "catch_block"))
        || handler.is_loop(kind)
    {
        let body_node = node
            .child_by_field_name("body")
            .or_else(|| node.child_by_field_name("consequence"));
        let mut body = Vec::new();
        if let Some(n) = body_node {
            walk_into(n, file, src, handler, class_names, &mut body, false);
            // Loop headers: iterable / condition / init / update / range
            // expressions are NOT in the body — they execute before or
            // between iterations. Walk every non-body named child into
            // the outer flow so calls like `for v in gen():` surface at
            // the enclosing scope, regardless of whether the grammar
            // labels the header piece with a field name (PHP's
            // `foreach_statement` doesn't; Python / Go / Java / JS all
            // pick different field names).
            let body_id = n.id();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.id() == body_id {
                    continue;
                }
                walk_into(child, file, src, handler, class_names, out, false);
            }
        } else {
            // No named "body" field — walk all named children and pick up
            // whatever's inside.
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_into(child, file, src, handler, class_names, &mut body, false);
            }
        }
        let loop_kind = if handler.is_foreach(kind) {
            LoopKind::ForEach
        } else if handler.is_for(kind) {
            LoopKind::For
        } else if handler.is_loop(kind) {
            LoopKind::Loop
        } else if handler.is_do(kind) {
            LoopKind::DoWhile
        } else {
            LoopKind::While
        };
        if matches!(loop_kind, LoopKind::ForEach | LoopKind::For) {
            out.extend(extract_foreach_binding_assigns(file, &node, src));
        }
        out.push(FlowEvent::Loop {
            span: span_of(file, &node),
            loop_kind,
            body,
        });
        return;
    }

    if handler.is_return(kind) {
        // Kotlin's `jump_expression` covers `return`, `throw`, `break`,
        // `continue` — disambiguate by the leading keyword.
        let leading = node_text(&node, src).trim_start();
        if leading.starts_with("break") {
            out.push(FlowEvent::Break {
                span: span_of(file, &node),
                label: None,
            });
            return;
        } else if leading.starts_with("continue") {
            out.push(FlowEvent::Continue {
                span: span_of(file, &node),
                label: None,
            });
            return;
        }
        // Walk children FIRST so call / assign events nested inside the
        // return expression (e.g. `return foo(x)`) surface BEFORE the
        // terminator. This matters for the intraprocedural pass: when
        // CFG construction sees a `Return` it ends the block, so any
        // events that came after the Return would be unreachable. We
        // want the call's effects on taint to be observed at the
        // moment of return, not lost to a dead-code block.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, out, false);
        }
        if leading.starts_with("throw") {
            out.push(FlowEvent::Throw {
                span: span_of(file, &node),
                value_name: extract_throw_value_name(&node, src),
                thrown_type: None,
            });
        } else {
            out.push(FlowEvent::Return {
                span: span_of(file, &node),
                value_text: extract_return_value_text(&node, src),
                value_name: extract_return_value_name(&node, src),
            });
        }
        return;
    }
    if handler.is_throw(kind) {
        // Walk children FIRST so call events nested inside the thrown
        // expression (e.g. `throw new Foo(tainted())`) surface BEFORE the
        // terminator — same rationale as the `is_return` arm above: CFG
        // construction ends the block at the throw, so any event ordered
        // after it would land in a dead block and be lost. Assignment
        // children are skipped: a thrown expression's own sub-assignments
        // are not statement-level writes in the enclosing block.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if handler.is_assignment(child.kind()) {
                continue;
            }
            walk_into(child, file, src, handler, class_names, out, false);
        }
        out.push(FlowEvent::Throw {
            span: span_of(file, &node),
            value_name: extract_throw_value_name(&node, src),
            thrown_type: None,
        });
        return;
    }

    if ruby_append_mutation_assignment(&node, file, src, out) {
        return;
    }

    if handler.is_assignment(kind) {
        if kind == "binary_operator" && !binary_operator_is_assignment(&node, src) {
            // G3 follow-up: synthesizing a Call event for every
            // binary_operator broke the C interproc-empty-seed
            // invariant (every `int x = a + b;` produced a synthetic
            // call propagation record). The Path-overload case
            // needs a more targeted approach — gated on the LHS
            // being a known constructor (Path, PurePath, etc.) so
            // we don't synthesize calls for arithmetic. Tracked as
            // task #109 for a follow-up.
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_into(child, file, src, handler, class_names, out, false);
            }
            return;
        }
        if assignment_wrapper_has_variable_declarator(kind, &node) {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                walk_into(child, file, src, handler, class_names, out, false);
            }
            return;
        }
        // Target-name extraction. Grammars disagree on field names, and
        // some emit keywords (`val`, `var`, `let`, `const`, `auto`) as
        // visible named children — skip those so the real identifier
        // gets picked. Kotlin `property_declaration` is the canonical
        // offender: its first named child is the `val`/`var` keyword
        // node, which without filtering would become the target text.
        let target_node = node
            .child_by_field_name("left")
            .or_else(|| node.child_by_field_name("lhs"))
            .or_else(|| node.child_by_field_name("target"))
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("pattern"))
            .or_else(|| node.child_by_field_name("declarator"))
            .or_else(|| {
                (kind == "property_declaration")
                    .then(|| first_named_child_of_kind(&node, "variable_declaration"))
                    .flatten()
            })
            .or_else(|| first_non_keyword_named_child(&node, src));
        // If the picked target is itself a declarator wrapper —
        // tree-sitter emits `variable_declarator` in C# /
        // JavaScript / TypeScript / Java, `init_declarator` in C /
        // C++, and similar in Solidity / Swift — descend into its
        // identifier child so the emitted `target` is the variable
        // name rather than the whole `name = rhs` expression. Also
        // the downstream walker will visit the declarator anyway
        // and emit its own clean Assign, so without this unwrap we
        // get two events per variable: one with wrapper text and one
        // with the canonical identifier.
        let target_node = target_node.map(|n| match n.kind() {
            "variable_declarator"
            | "init_declarator"
            | "declarator"
            | "property_identifier"
            | "variable_declaration" => n
                .child_by_field_name("name")
                .or_else(|| {
                    first_named_child_of_kind(&n, "variable_declarator")
                        .and_then(|decl| decl.child_by_field_name("name"))
                })
                .or_else(|| first_non_keyword_named_child(&n, src))
                .unwrap_or(n),
            _ => n,
        });
        let raw_target = target_node
            .map(|n| node_text(&n, src).trim().to_string())
            .unwrap_or_default();
        // C# tree-sitter-c-sharp doesn't expose the binding identifier as a
        // *named* node inside `variable_declarator` — `action` in
        // `action = req.Query["action"].ToString()` is anonymous, so every
        // named-child walker picks up the RHS instead and the target
        // becomes `action = req.Query…`. Same pattern surfaces in Solidity
        // (`bytes32 t`), Perl (`my $query`), Lua (full statement), and Go
        // multi-return destructuring (`result, _`). When the picked target
        // text has shape `LHS = RHS`, keep just the LHS; when it has a
        // space, keep the last whitespace-delimited token (types on
        // Solidity / Perl stay off the target). The underlying identifier
        // is still reachable through the structured `target` field on
        // downstream analyses — we just display the clean name.
        let target = sanitize_assign_target(&raw_target);
        // RHS: most grammars expose it via `right` or `value`. Kotlin's
        // property_declaration has no field for the initializer — it's
        // just a sibling of the variable-declaration identifier. We'd
        // rather over-walk than miss calls on the RHS, so as a fallback
        // we pick the LAST named child that isn't the target node.
        let rhs = node
            .child_by_field_name("right")
            .or_else(|| node.child_by_field_name("rhs"))
            .or_else(|| node.child_by_field_name("value"))
            .or_else(|| node.child_by_field_name("result"))
            .or_else(|| node.child_by_field_name("target"))
            .or_else(|| last_named_child_excluding(&node, target_node));
        let source_name = rhs.and_then(|rhs_node| {
            let rhs_text = node_text(&rhs_node, src).trim();
            // Only emit `source_name` for bare-identifier RHS — compound
            // expressions go through `source_call` / `source_names`.
            if looks_like_bare_identifier(rhs_text) {
                Some(rhs_text.to_string())
            } else {
                None
            }
        });
        // source_call: when the RHS is a direct call expression,
        // capture the callee name + the call's positional
        // argument identifier texts. This is what the interprocedural
        // taint pass uses to propagate return-value taint:
        //   `y = transform(x)` → source_call = Some("transform"),
        //   `y = item.get("k")` → source_call = Some("item.get"),
        //   source_call_args = ["x"]. If transform's summary says
        //   param 0 flows to the return, y inherits x's taint.
        let (source_call, source_call_args) = rhs
            .and_then(|n| extract_direct_call_info(&n, src))
            .or_else(|| rhs.and_then(|n| extract_dart_selector_call_info(n, file, src)))
            .or_else(|| {
                rhs.is_none()
                    .then(|| {
                        first_call_descendant(node).and_then(|call| extract_direct_call_info(&call, src))
                    })
                    .flatten()
            })
            .or_else(|| extract_dart_selector_call_info(node, file, src))
            .unwrap_or((None, Vec::new()));
        // G2: when the RHS is a compound expression (template literal,
        // string concat, binary op, f-string, interpolation, member /
        // subscript access, ternary, null-coalesce), there is no
        // single call or bare identifier. Extract every bare-identifier
        // operand into `source_names` so the intra / inter passes
        // treat "any operand tainted → target tainted". This makes
        // `y = "prefix" + tainted` / `y = f"{x}"` / `` y = `${x}` `` /
        // `y = obj.field` / `y = cond ? a : b` propagate taint
        // correctly across all grammars without requiring the adapter
        // to evaluate the expression AST itself.
        let mut source_names: Vec<String> = Vec::new();
        let rhs_is_large_literal = rhs
            .as_ref()
            .is_some_and(|n| is_large_literal_initializer_node(n.kind(), n))
            || has_direct_large_literal_initializer_child(&node);
        if let Some(n) = rhs.filter(|n| !is_large_literal_initializer_node(n.kind(), n)) {
            source_names.extend(extract_rhs_expr_operands(&n, src));
        }
        // Some grammars expose a declaration initializer as a wrapper
        // whose "rhs" fallback is only the callee/type node, while the
        // actual argument expressions are siblings inside the full
        // assignment/declaration node. Walk the full assignment as a
        // tree-sitter expression fallback and drop the target itself so
        // constructor/object-literal assignments like
        // `env = Envelope(cmd: raw)` preserve the `raw` dependency.
        if rhs.is_none() {
            source_names.extend(extract_rhs_expr_operands(&node, src));
        }
        if source_names.is_empty() && !rhs_is_large_literal {
            if let Some(rhs_text) = assignment_rhs_text(node_text(&node, src)) {
                source_names.extend(identifier_tokens_from_text(rhs_text));
            }
        }
        // H1: `x OP= rhs` desugars to `x = x OP rhs`, so the LHS is always
        // read. Keep it among the sources (don't strip via same_identifier)
        // so a literal / untainted RHS can't reach the clean-overwrite kill
        // arm and drop `x`'s prior taint.
        let is_compound = assignment_is_compound(&node, kind, src);
        if !is_compound {
            source_names.retain(|name| !same_identifier_name(name, &target));
        }
        if source_names.is_empty() && !rhs_is_large_literal {
            if let Some(rhs_text) = assignment_rhs_text(node_text(&node, src)) {
                source_names.extend(identifier_tokens_from_text(rhs_text));
                if !is_compound {
                    source_names.retain(|name| !same_identifier_name(name, &target));
                }
            }
        }
        if is_compound
            && !target.is_empty()
            && !source_names
                .iter()
                .any(|name| same_identifier_name(name, &target))
        {
            source_names.push(target.clone());
        }
        source_names.sort();
        source_names.dedup();
        // Some grammars emit a declaration-name wrapper as an
        // assignment-shaped node (`val raw` / `local raw`) in addition
        // to the real initializer assignment. A node with no RHS and
        // no surfaced source operands has no value semantics; emitting
        // it would be a fake clean overwrite that erases the real
        // source assignment immediately after it.
        let has_value_semantics =
            (rhs.is_some() || source_name.is_some() || source_call.is_some() || !source_names.is_empty())
                && !rhs_is_large_literal
                && !type_only_declaration_without_initializer(&node);
        if has_value_semantics {
            // G3 + G4: when the LHS is a member / subscript expression
            // (`self.cmd = x`, `env['cmd'] = x`), also emit an Assign for
            // the FULL qualified form so reads of `self.cmd` / `env.cmd`
            // elsewhere in the function can see the write. The bare
            // `cmd` Assign below stays because many reads still come
            // through as the bare identifier (`cmd = self.cmd; use(cmd)`).
            // Both entries carry the same source_name / source_call so
            // the taint transfer sees the same RHS dependency on both
            // keys.
            let qualified_target = qualified_assign_target(target_node, src);
            if let Some(qname) = qualified_target.as_ref() {
                if qname != &target {
                    out.push(FlowEvent::Assign {
                        span: span_of(file, &node),
                        target: qname.clone(),
                        source_name: source_name.clone(),
                        source_call: source_call.clone(),
                        source_call_args: source_call_args.clone(),
                        source_names: source_names.clone(),
                        declares_new_binding: false,
                        value_kind: None,
                    });
                }
            }
            if qualified_target.is_none() {
                for extra_target in extra_assign_targets(&raw_target, &target) {
                    out.push(FlowEvent::Assign {
                        span: span_of(file, &node),
                        target: extra_target,
                        source_name: source_name.clone(),
                        source_call: source_call.clone(),
                        source_call_args: source_call_args.clone(),
                        source_names: source_names.clone(),
                        declares_new_binding: false,
                        value_kind: None,
                    });
                }
            }
            for extra_target in extra_lhs_binding_targets(&node, target_node, src, &target) {
                if qualified_target.is_some() {
                    continue;
                }
                out.push(FlowEvent::Assign {
                    span: span_of(file, &node),
                    target: extra_target,
                    source_name: source_name.clone(),
                    source_call: source_call.clone(),
                    source_call_args: source_call_args.clone(),
                    source_names: source_names.clone(),
                    declares_new_binding: false,
                    value_kind: None,
                });
            }
            // Subscript-assign `obj[key] = value` is semantically
            // `obj.__setitem__(key, value)`. Emit a synthetic Call so
            // `kind: call` rules can match the item-set with the RHS value
            // as a tainted arg (e.g. Django `response[name] = tainted`
            // header injection). Gated to a simple `<ident>[...]` LHS so it
            // never fires on member/nested-subscript shapes. Harmless for
            // languages with no `__setitem__` rule — nothing matches it.
            if let Some(bracket) = raw_target.find('[') {
                let base = raw_target[..bracket].trim();
                if !base.is_empty() && base.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$') {
                    // arg 0 = subscript KEY (`name` in `obj[name]`), arg 1 =
                    // RHS VALUE. Either being tainted is a header-injection
                    // vector, so the rule uses any_arg_tainted.
                    let key_text = raw_target
                        .rfind(']')
                        .filter(|close| *close > bracket)
                        .map(|close| raw_target[bracket + 1..close].trim().to_string())
                        .unwrap_or_default();
                    let key_sources = if looks_like_bare_identifier(&key_text) {
                        vec![key_text.clone()]
                    } else {
                        Vec::new()
                    };
                    let mut value_sources = source_names.clone();
                    if let Some(sn) = source_name.clone() {
                        if !value_sources.contains(&sn) {
                            value_sources.push(sn);
                        }
                    }
                    let value_text = rhs
                        .map(|n| normalize_call_name_whitespace(node_text(&n, src)))
                        .unwrap_or_default();
                    let span = span_of(file, &node);
                    out.push(FlowEvent::Call {
                        span,
                        receiver: Some(base.to_string()),
                        receiver_types: Vec::new(),
                        name: format!("{base}.__setitem__"),
                        call_kind: crate::CallKind::Method,
                        args: vec![
                            crate::CallArg {
                                span,
                                name: None,
                                place: None,
                                source_names: key_sources,
                                value_text: key_text,
                            },
                            crate::CallArg {
                                span,
                                name: None,
                                place: rhs.and_then(|n| argument_place(&n, src)),
                                source_names: value_sources,
                                value_text,
                            },
                        ],
                    });
                }
            }
            out.push(FlowEvent::Assign {
                span: span_of(file, &node),
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                declares_new_binding: false,
                value_kind: None,
            });
        }
        // Walk every named child so nested calls inside the LHS or RHS
        // surface, regardless of whether the grammar exposes
        // `right`/`value` fields. C# `variable_declaration` wraps the
        // initializer in a `variable_declarator`; Kotlin's
        // `property_declaration` has no field for the initializer at
        // all; JS's `variable_declarator` nests the initializer under
        // a `value` that we DO have but also has nothing else to skip.
        // Over-walking a rhs is fine — call events surface once.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, out, false);
        }
        return;
    }

    // Dart-specific: tree-sitter-dart (UserNobody14) models calls as
    // `identifier` followed by a sibling `selector` (which contains
    // `argument_part > arguments > argument*`), rather than a unified
    // call node. We synthesize a Call event when we see a selector
    // whose previous named sibling is an identifier-like callee.
    // Re-run for `dotted` receivers: `receiver.method(args)` parses as
    // `identifier.identifier selector`, so the prev sibling is a `.`
    // followed by the method identifier; we walk back as needed.
    if kind == "selector" {
        if let Some(event) = build_dart_selector_call_event(node, file, src) {
            out.push(event);
            // Descend into arguments for nested calls.
            if let Some(arg_part) = first_named_child_of_kind(&node, "argument_part") {
                if let Some(args) = first_named_child_of_kind(&arg_part, "arguments") {
                    let mut cursor = args.walk();
                    for arg in args.named_children(&mut cursor) {
                        walk_into(arg, file, src, handler, class_names, out, false);
                    }
                }
            }
            return;
        }
    }

    // Scala-specific: `foo.!` / `foo.bar_!` (Scala operator-method
    // postfix invocations — used by the `sys.process` "run-as-shell-
    // command" idiom). tree-sitter-scala parses these as
    // `field_expression` with an `operator_identifier` as the second
    // child, NOT as a call. Emit a Call event here so the sink
    // surfaces in the flow.
    if kind == "field_expression" && is_scala_operator_method_call(&node) {
        let name = node_text(&node, src).trim().to_string();
        if !name.is_empty() {
            out.push(FlowEvent::Call {
                span: span_of(file, &node),
                receiver: call_receiver_from_name(&name),
                receiver_types: Vec::new(),
                name,
                call_kind: crate::CallKind::Method,
                args: Vec::new(),
            });
        }
        return;
    }

    // Swift-specific: `defer { body }` parses as a `call_expression`
    // with callee `defer` and a trailing `lambda_literal`. Convert to
    // a Defer event BEFORE the generic call handler would turn it
    // into a regular Call (which would lose the body's contents).
    if kind == "call_expression" && is_swift_defer_call(&node, src) {
        let mut body = Vec::new();
        // The `lambda_literal` may be a direct child OR nested inside
        // a `call_suffix` wrapper. Find it either way.
        fn find_and_walk(
            n: Node<'_>,
            file: FileId,
            src: &[u8],
            handler: &GrammarHandler,
            class_names: &[String],
            out: &mut Vec<FlowEvent>,
            depth: usize,
        ) {
            if depth > 3 {
                return;
            }
            let mut cursor = n.walk();
            for child in n.named_children(&mut cursor) {
                if child.kind() == "lambda_literal" {
                    walk_lambda_body(child, file, src, handler, class_names, out);
                } else if child.kind() == "call_suffix" {
                    find_and_walk(child, file, src, handler, class_names, out, depth + 1);
                }
            }
        }
        find_and_walk(node, file, src, handler, class_names, &mut body, 0);
        out.push(FlowEvent::Defer {
            span: span_of(file, &node),
            body,
        });
        return;
    }

    if kind == "call"
        && (emit_elixir_control_flow_call(&node, file, src, handler, class_names, out)
            || emit_erlang_functional_loop_call(&node, file, src, handler, class_names, out)
            || emit_ruby_block_loop_call(&node, file, src, handler, class_names, out))
    {
        return;
    }

    if handler.is_call(kind) {
        let call_event = build_call_event(node, file, src, handler, class_names);
        if let Some(lambda) = immediately_invoked_lambda_callee(&node, handler) {
            walk_call_argument_expressions(node, file, src, handler, class_names, out);
            if let Some(event) = call_event.as_ref() {
                emit_invoked_lambda_param_bindings(lambda, file, src, event, out);
            }
            walk_lambda_body(lambda, file, src, handler, class_names, out);
            return;
        }
        if let Some(event) = call_event.clone() {
            out.push(event);
        }
        let closure_source_names = call_event
            .as_ref()
            .map(call_event_value_source_names)
            .unwrap_or_default();
        // Also descend into nested calls inside arguments. For lambda
        // arguments (`xs.forEach { x -> body }`, `xs.map(x => body)`,
        // `[...].forEach(x => body)`), inline the closure body into
        // the OUTER flow — higher-order-function calls execute the
        // closure as part of the caller's behavior, so their calls
        // are flow-relevant and shouldn't be lost to the usual
        // is_lambda short-circuit.
        let arg_containers = call_argument_containers(node);
        let mut walked_closures = std::collections::HashSet::new();
        for container in arg_containers {
            // `any(f(t) for t in xs)` / `list(g(t) for t in xs)`: python
            // exposes the bare generator_expression DIRECTLY as the call's
            // `arguments` field (no `argument_list` wrapper). Iterating its
            // children would walk the body call and `for_in_clause`
            // separately — losing the loop-variable binding so the sink's
            // arg stays untainted. Walk the comprehension AS a whole so the
            // COMPREHENSION_KINDS branch binds the iterator and emits the body.
            if is_comprehension_kind(container.kind()) {
                walk_into(container, file, src, handler, class_names, out, false);
                continue;
            }
            let mut cursor = container.walk();
            for arg in container.named_children(&mut cursor) {
                if is_closure_arg(arg.kind(), handler) {
                    walked_closures.insert(arg.id());
                    let extra_sources = inline_closure_param_extra_sources(call_event.as_ref(), arg, src);
                    emit_inline_closure_param_bindings_with_extra_sources(
                        arg,
                        file,
                        src,
                        &closure_source_names,
                        &extra_sources,
                        out,
                    );
                    // Inline the lambda body so its calls belong to
                    // the enclosing function. Walks via a helper that
                    // bypasses the is_lambda short-circuit.
                    walk_lambda_body(arg, file, src, handler, class_names, out);
                } else {
                    walk_into(arg, file, src, handler, class_names, out, false);
                }
            }
        }
        // Some grammars attach the trailing-closure block as a direct
        // sibling of the call (Ruby `xs.each { |x| ... }` — the `block`
        // is a top-level child of the call, not inside any arguments
        // container). Scan the call's direct children for such closures
        // and inline their bodies too.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "do_block" && elixir_call_name(&node, src).is_some() {
                continue;
            }
            if is_closure_arg(child.kind(), handler) {
                if !walked_closures.insert(child.id()) {
                    continue;
                }
                if ruby_call_block_uses_yield_result(&node, &child, src) {
                    emit_inline_closure_param_bindings_from_yield_call(
                        child,
                        file,
                        src,
                        call_event.as_ref(),
                        out,
                    );
                } else {
                    let extra_sources = inline_closure_param_extra_sources(call_event.as_ref(), child, src);
                    emit_inline_closure_param_bindings_with_extra_sources(
                        child,
                        file,
                        src,
                        &closure_source_names,
                        &extra_sources,
                        out,
                    );
                }
                walk_lambda_body(child, file, src, handler, class_names, out);
            }
        }
        // Elixir-specific: control-flow constructs (`case`, `cond`,
        // `if`, `with`, `try`, `receive`, `for`) are all parsed as
        // `call` nodes whose body lives in a `do_block` direct child.
        // Without this descent, calls inside those bodies wouldn't
        // surface in the enclosing function's flow events.
        if elixir_call_name(&node, src).is_some() {
            if let Some(do_block) = first_named_child_of_kind(&node, "do_block") {
                let mut do_cursor = do_block.walk();
                for child in do_block.named_children(&mut do_cursor) {
                    walk_into(child, file, src, handler, class_names, out, false);
                }
            }
        }
        // Method-chain receivers. Rust / Swift / Kotlin / JS / TS
        // parse `a.b().c().d()` as a nested call_expression chain
        // where each step's `function` field wraps the previous step
        // as its receiver. Without descending into the function /
        // callee field, only the outermost call emits an event and
        // the inner calls' structured args are lost. Walk through
        // field-access wrappers (`field_expression`,
        // `member_expression`, navigation_expression, etc.) to
        // reach any nested call_expression and emit a proper event
        // per inner call.
        let receiver_node = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("callee"))
            .or_else(|| node.child_by_field_name("receiver"))
            .or_else(|| node.child_by_field_name("object"));
        if let Some(recv) = receiver_node {
            walk_method_chain_receivers(recv, file, src, handler, class_names, out);
        }
        return;
    }

    if handler.is_try(kind) {
        let mut body = Vec::new();
        let mut catch_events = Vec::new();
        let mut finally_events = Vec::new();
        // Prefer the `body` / `block` field for the try body; otherwise the
        // first named block-like child that isn't itself a catch/finally.
        let body_node = node
            .child_by_field_name("body")
            .or_else(|| node.child_by_field_name("block"));
        let body_id = body_node.map(|n| n.id());
        let mut pre_body_child_ids = Vec::new();
        if let Some(b) = body_node {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.id() == b.id() {
                    break;
                }
                let ck = child.kind();
                if handler.is_catch(ck) || handler.is_finally(ck) || ck == "on_part" {
                    continue;
                }
                walk_into(child, file, src, handler, class_names, &mut body, false);
                pre_body_child_ids.push(child.id());
            }
            walk_into(b, file, src, handler, class_names, &mut body, false);
        }
        let mut cursor = node.walk();
        let mut saw_catch_kind = false;
        let mut saw_finally_kind = false;
        let mut block_children: Vec<Node<'_>> = Vec::new();
        // Dart parses `catch (e) { body }` as TWO siblings: a catch_clause
        // (containing only the parameters) followed by a sibling `block`
        // that IS the catch body. Same for `on E catch (e) { body }`.
        // Track whether the previous named sibling was a catch/on marker
        // so the following block gets routed into catch_events.
        let mut prev_was_catch_marker = false;
        for child in node.named_children(&mut cursor) {
            if pre_body_child_ids.contains(&child.id()) {
                prev_was_catch_marker = false;
                continue;
            }
            let ck = child.kind();
            if handler.is_catch(ck) || ck == "on_part" {
                saw_catch_kind = true;
                walk_into(child, file, src, handler, class_names, &mut catch_events, false);
                prev_was_catch_marker = true;
                continue;
            } else if handler.is_finally(ck) {
                saw_finally_kind = true;
                walk_into(child, file, src, handler, class_names, &mut finally_events, false);
                prev_was_catch_marker = false;
                continue;
            } else if prev_was_catch_marker && (ck == "block" || ck == "compound_statement") {
                // Dart: the block right after a catch_clause/on_part is the
                // catch body. Route it into catch_events.
                walk_into(child, file, src, handler, class_names, &mut catch_events, false);
                prev_was_catch_marker = false;
                continue;
            } else if Some(child.id()) == body_id {
                // Already walked via the body field — don't double-count.
                prev_was_catch_marker = false;
                continue;
            } else if body_node.is_none() {
                walk_into(child, file, src, handler, class_names, &mut body, false);
                if ck == "block" || ck == "compound_statement" {
                    block_children.push(child);
                }
            } else if ck == "block" || ck == "compound_statement" {
                block_children.push(child);
            } else {
                // Solidity: `try <call_expression> returns (r) <body> catch
                // { ... }` parses the tried expression as a sibling of the
                // body block. The expression IS the protected operation,
                // so walk its calls into body so callgraph sees them as
                // part of the try scope.
                walk_into(child, file, src, handler, class_names, &mut body, false);
            }
            prev_was_catch_marker = false;
        }
        // Fallback for grammars (e.g. Perl) that don't label the catch
        // block with a dedicated kind: when we saw zero catch/finally
        // kinds and there are at least two sibling `block` children, the
        // second is the catch body (the first was already used as the
        // try body above).
        if !saw_catch_kind && !saw_finally_kind && block_children.len() >= 2 {
            // The second block-child is the catch body regardless of
            // whether the first was assigned as body via a named field or
            // via the walked-children fallback.
            let catch_block = &block_children[1];
            walk_into(
                *catch_block,
                file,
                src,
                handler,
                class_names,
                &mut catch_events,
                false,
            );
        }
        out.push(FlowEvent::Try {
            span: span_of(file, &node),
            body,
            catch_events,
            finally_events,
            catch_param: extract_catch_param(&node, src),
            catch_types: Vec::new(),
        });
        return;
    }

    if handler.is_break(kind) {
        let label = node
            .child_by_field_name("label")
            .map(|n| node_text(&n, src).trim().to_string())
            .filter(|s| !s.is_empty());
        // Perl's `loopex_expression` is a bucket for `last`, `next`, and
        // `redo` — sort by the leading keyword so the flow surfaces the
        // right event.
        let leading = node_text(&node, src).trim_start();
        if leading.starts_with("next") {
            out.push(FlowEvent::Continue {
                span: span_of(file, &node),
                label,
            });
        } else {
            out.push(FlowEvent::Break {
                span: span_of(file, &node),
                label,
            });
        }
        return;
    }

    if handler.is_continue(kind) {
        let label = node
            .child_by_field_name("label")
            .map(|n| node_text(&n, src).trim().to_string())
            .filter(|s| !s.is_empty());
        out.push(FlowEvent::Continue {
            span: span_of(file, &node),
            label,
        });
        return;
    }

    if handler.is_yield(kind) {
        let value_text = {
            let full = node_text(&node, src).trim();
            let stripped = full
                .strip_prefix("yield from ")
                .or_else(|| full.strip_prefix("yield "))
                .unwrap_or(full)
                .trim();
            if stripped.is_empty() || stripped == "yield" {
                None
            } else {
                Some(stripped.to_string())
            }
        };
        out.push(FlowEvent::Yield {
            span: span_of(file, &node),
            value_text,
        });
        // Descend so calls inside `yield f()` still surface.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, out, false);
        }
        return;
    }

    if handler.is_await(kind) {
        // Capture the awaited value name when the node is a bare
        // identifier (`await promise`) so the intra pass can
        // propagate taint through the await boundary. Compound
        // awaited expressions (`await f(x)`) leave `value_name =
        // None`; their taint is tracked via the nested Call event
        // the child walk emits.
        let value_name = {
            let mut cursor = node.walk();
            let first_child = node.named_children(&mut cursor).next();
            first_child.and_then(|child| {
                let child_text = node_text(&child, src).trim();
                // Bare-identifier awaited values get a `value_name`;
                // anything compound is left None and tracked via the
                // nested call event.
                if looks_like_bare_identifier(child_text) {
                    Some(child_text.to_string())
                } else {
                    None
                }
            })
        };
        out.push(FlowEvent::Await {
            span: span_of(file, &node),
            value_name,
        });
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, out, false);
        }
        return;
    }

    if handler.is_defer(kind) {
        let mut body = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_into(child, file, src, handler, class_names, &mut body, false);
        }
        out.push(FlowEvent::Defer {
            span: span_of(file, &node),
            body,
        });
        return;
    }

    if handler.is_using(kind) {
        let body_node = node
            .child_by_field_name("body")
            .or_else(|| node.child_by_field_name("block"));
        let mut body = Vec::new();
        if let Some(b) = body_node {
            walk_into(b, file, src, handler, class_names, &mut body, false);
            // Python `with open('f') as fh:` / C# `using (var x = init()) {...}`
            // — the init expression (`open('f')`, `init()`) is NOT in the body
            // field, it's a sibling (`with_clause` / the init). Walk every
            // non-body named child into the OUTER flow so those calls surface
            // at the enclosing scope instead of disappearing.
            let body_id = b.id();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.id() == body_id {
                    continue;
                }
                emit_using_as_pattern_assigns(child, file, src, out);
                walk_into(child, file, src, handler, class_names, out, false);
            }
        } else {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                emit_using_as_pattern_assigns(child, file, src, &mut body);
                walk_into(child, file, src, handler, class_names, &mut body, false);
            }
        }
        out.push(FlowEvent::Using {
            span: span_of(file, &node),
            body,
        });
        return;
    }

    // Default: recurse into every named child.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_into(child, file, src, handler, class_names, out, false);
    }
}

/// Walk a using-clause subtree (`with_clause`/`using_declaration` and
/// their `with_item`/`using_variable_declaration` children) and emit
/// a synthetic `FlowEvent::Assign` for every `as`-bound name found.
///
/// `with Transaction(runner, tag) as tx:` looks like
/// `with_statement > with_clause > with_item { value: <call>, alias:
/// <ident "tx"> }` (newer grammars) or wraps the binding in an
/// `as_pattern { value, alias }` node (older grammars). Without this
/// emission the binding `tx` has no assignment record, so the alias
/// map cannot bind `tx → Type{Transaction}` and the receiver-typed
/// dispatch for `tx.perform(...)` fails. The synthetic Assign feeds
/// into [`extend_alias_map_with_flow_events`] just like a regular
/// `tx = Transaction(runner, tag)` would.
fn emit_using_as_pattern_assigns(
    node: tree_sitter::Node<'_>,
    file: bonsai_common::FileId,
    src: &[u8],
    out: &mut Vec<crate::FlowEvent>,
) {
    fn extract_alias_target<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
        let alias = node
            .child_by_field_name("alias")
            .or_else(|| node.child_by_field_name("name"))?;
        match alias.kind() {
            "identifier" | "simple_identifier" | "variable_name" | "name" | "type_identifier" => Some(alias),
            _ => first_identifier_descendant(alias).or(Some(alias)),
        }
    }

    fn extract_alias_value<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
        if let Some(value_field) = node
            .child_by_field_name("value")
            .or_else(|| node.child_by_field_name("expression"))
            .or_else(|| node.child_by_field_name("init"))
            .or_else(|| node.child_by_field_name("initializer"))
        {
            return Some(value_field);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "call"
                    | "call_expression"
                    | "object_creation_expression"
                    | "instance_expression"
                    | "new_expression"
            ) {
                return Some(child);
            }
        }
        None
    }

    let mut work = vec![node];
    let mut emitted_spans: std::collections::HashSet<bonsai_common::Span> = std::collections::HashSet::new();
    while let Some(current) = work.pop() {
        // Match only the binding shapes the main walker doesn't
        // already turn into `Assign` events. `variable_declarator`,
        // `variable_declaration`, and `init_declarator` are in
        // [`GrammarHandler::assignment_kinds`] and would emit a
        // duplicate Assign here; let the main walker own those.
        if matches!(
            current.kind(),
            "with_item"
                | "with_variable_assignment"
                | "with_declarator"
                | "as_pattern"
                | "using_variable_declaration"
                | "using_declarator"
        ) {
            if let (Some(name_node), Some(value_node)) =
                (extract_alias_target(current), extract_alias_value(current))
            {
                let target = node_text(&name_node, src).trim().to_string();
                let value_text = node_text(&value_node, src).trim().to_string();
                let span = span_of(file, &current);
                if !target.is_empty() && !value_text.is_empty() && emitted_spans.insert(span) {
                    let (source_call, source_call_args, source_names) =
                        synthesize_assign_components_from_value(value_node, src, &value_text);
                    out.push(crate::FlowEvent::Assign {
                        span,
                        target,
                        source_name: None,
                        source_call,
                        source_call_args,
                        source_names,
                        declares_new_binding: false,
                        value_kind: None,
                    });
                }
            }
        }
        // Always descend: an outer container (`with_item`) may not
        // expose alias/value fields directly but its inner
        // `as_pattern` does, and vice versa. The `emitted_spans`
        // set prevents duplicate emission when both levels match.
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            work.push(child);
        }
    }
}

fn synthesize_assign_components_from_value(
    value_node: tree_sitter::Node<'_>,
    src: &[u8],
    value_text: &str,
) -> (Option<String>, Vec<String>, Vec<String>) {
    if matches!(
        value_node.kind(),
        "call" | "call_expression" | "object_creation_expression" | "instance_expression" | "new_expression"
    ) {
        // Constructor or call: pull out the callee tail so
        // `extend_alias_map_with_flow_events` recognises the
        // PascalCase constructor convention and binds the target as
        // a Type alias. Argument operands feed source_call_args so
        // the engine sees what data flowed into the call.
        let callee_node = value_node
            .child_by_field_name("function")
            .or_else(|| value_node.child_by_field_name("type"))
            .or_else(|| value_node.child_by_field_name("name"))
            .or_else(|| {
                let mut cursor = value_node.walk();
                let mut found = None;
                for child in value_node.named_children(&mut cursor) {
                    if matches!(
                        child.kind(),
                        "identifier" | "simple_identifier" | "type_identifier" | "navigation_expression"
                    ) {
                        found = Some(child);
                        break;
                    }
                }
                found
            });
        let callee = callee_node
            .map(|n| node_text(&n, src).trim().to_string())
            .unwrap_or_else(|| value_text.to_string());
        let arguments = value_node
            .child_by_field_name("arguments")
            .or_else(|| value_node.child_by_field_name("argument_list"));
        let mut args: Vec<String> = Vec::new();
        if let Some(args_node) = arguments {
            let mut cursor = args_node.walk();
            for child in args_node.named_children(&mut cursor) {
                let text = node_text(&child, src).trim().to_string();
                if !text.is_empty() {
                    args.push(text);
                }
            }
        }
        let mut source_names = vec![callee.clone()];
        if let Some((_, tail)) = callee.rsplit_once(['.', ':']) {
            let tail = tail.trim().to_string();
            if !tail.is_empty() && !source_names.contains(&tail) {
                source_names.push(tail);
            }
        }
        (Some(callee), args, source_names)
    } else {
        // Bare identifier or expression: surface as source_names so
        // engine taint propagation picks up any tainted operand.
        (None, Vec::new(), vec![value_text.to_string()])
    }
}

fn append_tail_expression_return(
    events: &mut Vec<FlowEvent>,
    body: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) {
    let Some(tail) = last_named_child(body) else {
        return;
    };
    let kind = tail.kind();
    if handler.is_return(kind)
        || handler.is_throw(kind)
        || handler.is_assignment(kind)
        || matches!(
            kind,
            "let_declaration"
                | "declaration"
                | "expression_statement"
                | "statement_block"
                | "block"
                | "function_body"
                | "body_statement"
        )
    {
        return;
    }
    let text = node_text(&tail, src).trim().to_string();
    if text.is_empty() || text.ends_with(';') {
        return;
    }
    let span = span_of(file, &tail);
    if events
        .iter()
        .any(|event| matches!(event, FlowEvent::Return { span: existing, .. } if *existing == span))
    {
        return;
    }
    events.push(FlowEvent::Return {
        span,
        value_text: Some(text),
        value_name: tail_expression_value_name(&tail, src),
    });
}

fn append_expression_body_return(events: &mut Vec<FlowEvent>, body: &Node<'_>, file: FileId, src: &[u8]) {
    let text = node_text(body, src).trim().to_string();
    if text.is_empty() || text.ends_with(';') {
        return;
    }
    let span = span_of(file, body);
    if events
        .iter()
        .any(|event| matches!(event, FlowEvent::Return { span: existing, .. } if *existing == span))
    {
        return;
    }
    events.push(FlowEvent::Return {
        span,
        value_text: Some(text),
        value_name: tail_expression_value_name(body, src),
    });
}

fn body_has_implicit_return(body: &Node<'_>, handler: &GrammarHandler) -> bool {
    let kind = body.kind();
    if handler.is_return(kind) || handler.is_throw(kind) || handler.is_assignment(kind) {
        return false;
    }
    !matches!(
        kind,
        "block"
            | "statement_block"
            | "compound_statement"
            | "function_body"
            | "body_statement"
            | "clause_body"
            | "statements"
            | "declaration_list"
            | "program"
            // Elixir / Ruby `do ... end` — a statement container, never
            // itself the tail expression; the tail-expression-return
            // path picks the block's last statement instead.
            | "do_block"
    )
}

fn implicit_return_expression_node<'tree>(
    body: &Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    if body_has_implicit_return(body, handler) {
        return Some(*body);
    }
    if !matches!(body.kind(), "function_body" | "statements") {
        return None;
    }
    let mut cursor = body.walk();
    let mut children = body.named_children(&mut cursor);
    let first = children.next()?;
    if children.next().is_some() {
        return None;
    }
    if matches!(first.kind(), "function_body" | "statements") {
        return implicit_return_expression_node(&first, handler);
    }
    if !body_has_implicit_return(&first, handler) {
        return None;
    }
    implicit_return_expression_node(&first, handler).or(Some(first))
}

fn last_named_child<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn binding_name_node<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let parent = node.parent()?;
    let value_is_node = parent
        .child_by_field_name("value")
        .or_else(|| parent.child_by_field_name("right"))
        .or_else(|| parent.child_by_field_name("rhs"))
        .is_some_and(|value| value.id() == node.id());
    match parent.kind() {
        "variable_declarator" | "initialized_variable_definition" | "property_declaration"
            if value_is_node =>
        {
            parent
                .child_by_field_name("name")
                .or_else(|| parent.child_by_field_name("pattern"))
        }
        "assignment_expression" | "assignment" | "assignment_statement" if value_is_node => parent
            .child_by_field_name("left")
            .or_else(|| parent.child_by_field_name("lhs"))
            .or_else(|| parent.child_by_field_name("target")),
        "pair" | "pair_pattern" if value_is_node => parent.child_by_field_name("key"),
        _ => None,
    }
}

fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

fn tail_expression_value_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if looks_like_identifier(node.kind()) {
        let text = node_text(node, src).trim().to_string();
        if !text.is_empty() {
            return Some(text);
        }
    }
    let text = node_text(node, src).trim();
    looks_like_bare_identifier(text).then(|| text.to_string())
}

/// Walk a method-chain receiver subtree looking for nested
/// call_expression nodes. Each such node is walked via `walk_into`
/// so `build_call_event` fires on it, producing a structured Call
/// event (with its own args / callee text) for every step in the
/// chain. Passes through field-access wrappers (`field_expression`,
/// `member_expression`, navigation / selector / scope-resolution
/// nodes) that don't themselves carry args but contain the inner
/// call. Stops at leaves that can't host a call.
fn walk_method_chain_receivers(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) {
    // Erlang's `Mod:fn(args)` parses as an outer `call` whose
    // `function` field is a `remote` node, and `remote` is also in
    // `COMMON_CALL_KINDS` (so bare top-level remotes still surface
    // a call ref). The outer call's `build_call_event` already
    // captured `Mod:fn` as the qualified callee, so descending
    // would push a duplicate Call event for the same site.
    if node.kind() == "remote" {
        return;
    }
    // If this node IS a call, walk it so build_call_event fires.
    if handler.is_call(node.kind()) {
        walk_into(node, file, src, handler, class_names, out, false);
        return;
    }
    // Wrapper kinds that hold a nested call / further wrapper on their
    // `value` / `object` / `receiver` / `function` / `expression` /
    // `target` field. We don't enumerate every wrapper kind — we just
    // look for these field names and a few common node shapes.
    const WRAPPER_KINDS: &[&str] = &[
        "field_expression",
        "member_expression",
        "member_access_expression",
        "navigation_expression",
        "selector_expression",
        "scoped_identifier",
        "scope_resolution",
        "selector",
        "postfix_expression",
        "parenthesized_expression",
        "expression",
        "primary_expression",
        "dot",
    ];
    if !WRAPPER_KINDS.contains(&node.kind()) && !handler.is_lambda(node.kind()) {
        // Leaf or unknown wrapper — nothing more to do.
        return;
    }
    let next = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("object"))
        .or_else(|| node.child_by_field_name("receiver"))
        .or_else(|| node.child_by_field_name("function"))
        .or_else(|| node.child_by_field_name("callee"))
        .or_else(|| node.child_by_field_name("operand"))
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.child_by_field_name("target"));
    if let Some(inner) = next {
        walk_method_chain_receivers(inner, file, src, handler, class_names, out);
    }
}

fn build_call_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
) -> Option<FlowEvent> {
    // Method-invocation shapes across grammars use different field
    // names for the receiver and the method identifier. Concatenate
    // them into a `receiver.method` string so the full callee path
    // is preserved:
    //   * Ruby:                receiver + method            → `r.m`
    //   * Java:                object   + name              → `o.name`
    //   * PHP arrow-call:      object   + name  (sep `->`)  → `o->name`
    //   * C#  member_access:   expression + name            → `e.name`
    // Without this, `Runtime.getRuntime().exec(x)` in Java would
    // collapse to just `exec` (losing the qualified path) and
    // `$conn->query($q)` in PHP would collapse to just `query`.
    let method_compound = method_receiver_name(&node, src);
    let erlang_remote = erlang_remote_callee(&node, src);
    let callee_node = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("constructor"))
        .or_else(|| node.child_by_field_name("type"))
        .or_else(|| node.child_by_field_name("callee"))
        .or_else(|| erlang_remote.as_ref().map(|(n, _)| *n))
        .or_else(|| method_compound.as_ref().map(|(n, _)| *n))
        .or_else(|| node.child_by_field_name("name"))
        // Many grammars (Kotlin, Swift) don't name the callee field; the
        // first named child IS the call target (e.g. a navigation_expression
        // for `list.add`). Prefer that over walking to the first identifier.
        .or_else(|| first_named_child(&node))
        .or_else(|| first_identifier_like_child(&node))
        .or_else(|| first_identifier_descendant(node))?;
    let mut full_text = erlang_remote
        .as_ref()
        .map(|(_, name)| name.as_str())
        .or_else(|| method_compound.as_ref().map(|(_, name)| name.as_str()))
        .unwrap_or_else(|| node_text(&callee_node, src).trim())
        .to_string();
    if node.kind() == "macro_invocation" && !full_text.ends_with('!') {
        let node_src = node_text(&node, src);
        let rest = node_src.trim_start().strip_prefix(&full_text).unwrap_or_default();
        if rest.trim_start().starts_with('!') {
            full_text.push('!');
        }
    }
    if full_text.is_empty() {
        return None;
    }
    let is_method = full_text.contains('.') || full_text.contains("->") || full_text.contains("::");
    let short = short_name_of(&full_text);
    let is_ctor = class_names.iter().any(|c| c == &full_text || c == short);
    let call_kind = if is_ctor
        || matches!(
            node.kind(),
            "new_expression"
                | "object_creation_expression"
                | "instance_expression"
                | "constructor_invocation"
                | "explicit_constructor_invocation"
                | "composite_literal"
        )
        || short == "new"
    {
        CallKind::Constructor
    } else if handler.is_lambda(node.kind()) {
        CallKind::Indirect
    } else if is_method {
        CallKind::Method
    } else {
        CallKind::Function
    };
    // Preserve the *full* qualified text so pattern matchers like
    // `inspect os.system` or `inspect jwt.decode` land correctly.
    // Resolution helpers (cross-module tracer, lookup) normalize
    // via `short_name_of`.
    //
    // Collapse runs of whitespace: method-chain call expressions in
    // Rust / Swift / Kotlin span multiple source lines, so the raw
    // `node_text(..).trim()` for a callee like
    //   Command::new("sh")\n    .arg("-c")\n    .arg(&full_cmd)\n    .output
    // survives with embedded newlines + indentation. That turns the
    // `calls` column into a mess and breaks downstream substring
    // filters that assume single-line names. Fold all whitespace
    // runs into single spaces so a multi-line method chain renders as
    //   `Command::new("sh") .arg("-c") .arg(&full_cmd) .output`.
    let name = normalize_call_name_whitespace(&full_text);

    let mut args = Vec::new();
    // Find the argument-list child. Grammars disagree on the field name
    // so we try the common ones. Kotlin uses a `call_suffix` wrapper
    // that contains `value_arguments` inside.
    let arg_list = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(&node, "arguments"))
        .or_else(|| first_named_child_of_kind(&node, "argument_list"))
        .or_else(|| first_named_child_of_kind(&node, "value_arguments"))
        .or_else(|| {
            // Kotlin: wrap `call_suffix` to find nested value_arguments.
            first_named_child_of_kind(&node, "call_suffix")
                .and_then(|cs| first_named_child_of_kind(&cs, "value_arguments"))
        })
        .or_else(|| first_named_child_of_kind(&node, "literal_value"))
        .or_else(|| first_named_child_of_kind(&node, "tuple_expression")); // swift

    // Solidity's `call_expression` has each argument as a direct
    // `call_argument` child rather than a wrapper — synthesize a virtual
    // container by collecting them. Same shape works for any grammar that
    // uses direct `call_argument` children.
    let solidity_args: Vec<Node<'_>> = {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|c| c.kind() == "call_argument")
            .collect()
    };

    // Erlang's `call` node has `args: expr_args` (field name is "args").
    let erlang_args_field = node
        .child_by_field_name("args")
        .or_else(|| erlang_remote_args_node(&node));
    if let Some(arg_list) = arg_list {
        let mut cursor = arg_list.walk();
        for arg in arg_list.named_children(&mut cursor) {
            // Swift wraps each arg in `value_argument` with a `value` field.
            let arg = if arg.kind() == "value_argument" || arg.kind() == "tuple_expression_element" {
                arg.child_by_field_name("value").unwrap_or(arg)
            } else {
                arg
            };
            // Keyword arg (Python `k=v`, some C# / JS named args, Kotlin
            // `key = value` inside value_arguments, Dart `name: value`
            // as named_argument with a `label` child).
            let (name, value_node) = if arg.kind() == "keyword_argument"
                || arg.kind() == "named_argument"
                || arg.kind() == "value_argument"
                || arg.kind() == "named_expression"
                || arg.kind() == "labeled_expression"
            {
                // Resolve the name field. Most grammars expose `name`;
                // Dart's named_argument holds a `label` child whose
                // first named child is the identifier.
                let nm = arg
                    .child_by_field_name("name")
                    .map(|n| node_text(&n, src).to_string())
                    .or_else(|| {
                        arg.named_children(&mut arg.walk())
                            .find(|c| c.kind() == "label")
                            .and_then(|lbl| {
                                lbl.named_children(&mut lbl.walk())
                                    .next()
                                    .map(|id| node_text(&id, src).to_string())
                            })
                    })
                    .or_else(|| {
                        arg.child_by_field_name("label")
                            .map(|n| node_text(&n, src).trim_end_matches(':').trim().to_string())
                    });
                // Resolve the value node.
                let vn = arg
                    .child_by_field_name("value")
                    .or_else(|| arg.child_by_field_name("expression"))
                    .or_else(|| {
                        // Dart named_argument: the value is the named
                        // sibling AFTER the `label` child.
                        let children: Vec<_> = arg.named_children(&mut arg.walk()).collect();
                        let label_idx = children.iter().position(|c| c.kind() == "label");
                        match label_idx {
                            Some(i) if i + 1 < children.len() => Some(children[i + 1]),
                            _ => None,
                        }
                    })
                    .unwrap_or(arg);
                (nm, vn)
            } else {
                (None, arg)
            };
            let value_text = normalize_call_name_whitespace(node_text(&value_node, src));
            if value_text.is_empty() {
                continue;
            }
            args.push(CallArg {
                span: span_of(file, &arg),
                name,
                place: argument_place(&value_node, src),
                source_names: extract_rhs_expr_operands(&value_node, src),
                value_text,
            });
        }
    }

    // Solidity: direct `call_argument` siblings on the call_expression.
    // Each call_argument contains an `expression` with the actual value.
    for arg in &solidity_args {
        let inner = first_named_child(arg).unwrap_or(*arg);
        let value_text = normalize_call_name_whitespace(node_text(&inner, src));
        if value_text.is_empty() {
            continue;
        }
        args.push(CallArg {
            span: span_of(file, arg),
            name: None,
            place: argument_place(&inner, src),
            source_names: extract_rhs_expr_operands(&inner, src),
            value_text,
        });
    }

    // Erlang: `args: expr_args` with `args: var` (or identifier-like)
    // children. expr_args can hold complex expressions; we take each
    // named child's trimmed text as the value.
    if let Some(eargs) = erlang_args_field {
        if eargs.kind() == "expr_args" {
            let mut cursor = eargs.walk();
            for arg in eargs.named_children(&mut cursor) {
                let value_text = normalize_call_name_whitespace(node_text(&arg, src));
                if value_text.is_empty() {
                    continue;
                }
                args.push(CallArg {
                    span: span_of(file, &arg),
                    name: None,
                    place: argument_place(&arg, src),
                    source_names: extract_rhs_expr_operands(&arg, src),
                    value_text,
                });
            }
        }
    }

    // Objective-C: `message_expression` has no arguments container —
    // args are direct children of the message, interleaved with
    // additional `method:` keyword selector parts. The grammar gives
    // the first keyword as `method` (a field name); subsequent
    // selector keywords also have field name `method`. Args are the
    // identifier / literal / expression children in between. We
    // collect all direct children except the `receiver` field and
    // any child whose field name is `method`.
    if node.kind() == "message_expression" {
        // tree-sitter exposes field names per child via
        // `cursor.field_name()` while walking; we need the cursor
        // form (not `named_children`) to see field names.
        let mut cur = node.walk();
        if cur.goto_first_child() {
            loop {
                let child = cur.node();
                if child.is_named() {
                    let field = cur.field_name();
                    let skip = matches!(field, Some("receiver" | "method"));
                    if !skip {
                        let value_text = normalize_call_name_whitespace(node_text(&child, src));
                        if !value_text.is_empty() {
                            args.push(CallArg {
                                span: span_of(file, &child),
                                name: None,
                                place: argument_place(&child, src),
                                source_names: extract_rhs_expr_operands(&child, src),
                                value_text,
                            });
                        }
                    }
                }
                if !cur.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    Some(FlowEvent::Call {
        span: span_of(file, &callee_node),
        receiver: call_receiver_from_name(&name),
        receiver_types: Vec::new(),
        name,
        call_kind,
        args,
    })
}

/// Extract every bare-identifier operand from a compound RHS
/// expression. Used for G2 (expression-level taint propagation):
/// any identifier appearing in the RHS becomes a candidate "tainted
/// this target" signal, so `y = "prefix" + tainted` / `y = f"{x}"` /
/// `` y = `${a}${b}` `` / `y = a.field` all carry the right
/// dependency info without the analyses needing grammar-specific
/// expression lowering.
///
/// The walker visits every descendant of the RHS node, collects any
/// node whose kind is an identifier-like form AND whose text is a
/// plausible bare identifier (`looks_like_bare_identifier`), and also
/// emits fully-qualified place reads such as `obj.field`, `obj['field']`,
/// and `obj->field`. Downstream taint propagation treats the qualified
/// read as the value-bearing operand and ignores the carrier token when
/// that token only appears as the base of a qualified access.
fn extract_rhs_expr_operands(node: &Node<'_>, src: &[u8]) -> Vec<String> {
    const IDENT_KINDS: &[&str] = &[
        "identifier",
        "simple_identifier",
        "constant",
        "variable_name",
        "var",
        "varname",
        "name",
        "property_identifier",
        "shorthand_property_identifier",
        "scope_resolution",
        "interpolated_identifier",
        "identifier_dollar_escaped",
    ];
    if is_large_literal_initializer_node(node.kind(), node) {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    out.extend(qualified_accesses_from_text(node_text(node, src)));
    let mut stack: Vec<Node<'_>> = vec![*node];
    while let Some(n) = stack.pop() {
        if is_large_literal_initializer_node(n.kind(), &n) {
            continue;
        }
        out.extend(call_receiver_source_names(&n, src));
        // Avoid descending into nested CALL sites — those are handled
        // separately by `extract_direct_call_info` on the outer call.
        // Constructor-style initializers can wrap a value-bearing call inside
        // an argument-list RHS (`Repo repo(std::move(env))`). Keep the nested
        // call's argument operands while still skipping the callee name.
        if COMMON_CALL_KINDS.contains(&n.kind()) && n.id() != node.id() {
            // M8: Kotlin/Swift expose call args under `value_arguments`
            // (often wrapped in a `call_suffix`) or a Swift `tuple_expression`
            // rather than `arguments`/`argument_list`. Without these a nested
            // call inside a compound RHS or call argument contributed NO
            // operands for Kotlin/Swift, unlike Python/JS/Java/Go. Mirror the
            // broader arg-list lookup used when building CallArgs.
            if let Some(args_node) = n
                .child_by_field_name("arguments")
                .or_else(|| n.child_by_field_name("argument_list"))
                .or_else(|| first_named_child_of_kind(&n, "value_arguments"))
                .or_else(|| {
                    first_named_child_of_kind(&n, "call_suffix")
                        .and_then(|cs| first_named_child_of_kind(&cs, "value_arguments"))
                })
                .or_else(|| first_named_child_of_kind(&n, "tuple_expression"))
            {
                let mut arg_cursor = args_node.walk();
                for arg in args_node.named_children(&mut arg_cursor) {
                    out.extend(extract_rhs_expr_operands(&arg, src));
                }
            }
            continue;
        }
        if MEMBER_EXPR_KINDS.contains(&n.kind()) {
            if let Some(name) = normalize_member_name(&n, src) {
                out.push(name);
            }
            // H6: suppress the member TAIL (the property / attribute name)
            // as a standalone bare operand. Consumers only ever strip the
            // qualified BASE, never the tail, so a bare tail like `field`
            // makes `y = obj.field` falsely read as tainted whenever an
            // unrelated local named `field` is tainted -- a name-only FP.
            // Descend into every child EXCEPT the tail so the real
            // value-bearing operands (the object/receiver base, plus any
            // index/argument subexpressions nested in the base) are still
            // collected. The tail is identified by grammar field name --
            // NOT by a fixed object-field lookup, which varies across
            // grammars (C# `member_access_expression` uses
            // `expression`/`name`; JS `member_expression` uses
            // `object`/`property`) and previously dropped the C# receiver.
            let tail_id = n
                .child_by_field_name("name")
                .or_else(|| n.child_by_field_name("property"))
                .or_else(|| n.child_by_field_name("field"))
                .map(|tail| tail.id());
            let mut member_cursor = n.walk();
            for child in n.named_children(&mut member_cursor) {
                if Some(child.id()) != tail_id {
                    stack.push(child);
                }
            }
            continue;
        }
        if let Some(place) = argument_place(&n, src) {
            if place.contains('.') {
                out.push(place);
            }
        }
        if IDENT_KINDS.contains(&n.kind()) {
            let text = node_text(&n, src).trim();
            let cleaned = text.trim_start_matches('$');
            if looks_like_bare_identifier(cleaned) {
                out.push(cleaned.to_string());
                // PHP/Perl carry the `$` in identifier text; some
                // taint paths store the variable with the sigil
                // (`$token`) while others store it bare (`token`).
                // Emit both so downstream matching works regardless
                // of which form the tainted set holds.
                if text != cleaned {
                    out.push(text.to_string());
                }
            }
        }
        let mut child_cursor = n.walk();
        for child in n.named_children(&mut child_cursor) {
            stack.push(child);
        }
    }
    let value_bearing_text = strip_value_free_operator_operands(node_text(node, src));
    out.retain(|operand| operand_occurs_in_value_bearing_text(&value_bearing_text, operand));
    out
}

fn call_receiver_source_names(node: &Node<'_>, src: &[u8]) -> Vec<String> {
    if !COMMON_CALL_KINDS.contains(&node.kind()) {
        return Vec::new();
    }
    let Some(receiver) = call_receiver_node(node) else {
        return Vec::new();
    };
    receiver_value_bases(receiver, src)
}

fn call_receiver_node<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    node.child_by_field_name("receiver")
        .or_else(|| node.child_by_field_name("object"))
        .or_else(|| node.child_by_field_name("invocant"))
        .or_else(|| {
            let function = node.child_by_field_name("function")?;
            let inner = if function.kind() == "expression" {
                first_named_child(&function).unwrap_or(function)
            } else {
                function
            };
            if MEMBER_EXPR_KINDS.contains(&inner.kind()) {
                inner
                    .child_by_field_name("object")
                    .or_else(|| inner.child_by_field_name("receiver"))
                    .or_else(|| inner.child_by_field_name("target"))
            } else {
                None
            }
        })
}

fn receiver_value_bases(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(base) = leftmost_value_base(node, src) {
        push_receiver_base_variants(&mut out, &base);
    }
    if out.is_empty() {
        if let Some(base) = receiver_base_from_text(node_text(&node, src)) {
            push_receiver_base_variants(&mut out, &base);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn leftmost_value_base(node: Node<'_>, src: &[u8]) -> Option<String> {
    let kind = node.kind();
    if matches!(
        kind,
        "identifier"
            | "simple_identifier"
            | "constant"
            | "variable_name"
            | "var"
            | "varname"
            | "name"
            | "identifier_dollar_escaped"
    ) {
        let text = node_text(&node, src).trim();
        if looks_like_bare_identifier(text.trim_start_matches('$')) {
            return Some(text.to_string());
        }
    }
    if COMMON_CALL_KINDS.contains(&kind) {
        if let Some(receiver) = call_receiver_node(&node) {
            return leftmost_value_base(receiver, src);
        }
    }
    if MEMBER_EXPR_KINDS.contains(&kind) || matches!(kind, "element_reference" | "subscript_expression") {
        if let Some(object) = node
            .child_by_field_name("object")
            .or_else(|| node.child_by_field_name("receiver"))
            .or_else(|| node.child_by_field_name("value"))
        {
            return leftmost_value_base(object, src);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(base) = leftmost_value_base(child, src) {
            return Some(base);
        }
    }
    None
}

fn receiver_base_from_text(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_start_matches('&').trim_start_matches('*').trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut end = trimmed.len();
    for sep in [".", "->", "::", "[", "(", " "] {
        if let Some(idx) = trimmed.find(sep) {
            end = end.min(idx);
        }
    }
    let candidate = trimmed[..end].trim().trim_start_matches('$');
    looks_like_bare_identifier(candidate).then(|| candidate.to_string())
}

fn push_receiver_base_variants(out: &mut Vec<String>, base: &str) {
    let base = base.trim();
    if base.is_empty() {
        return;
    }
    let cleaned = base.trim_start_matches('$');
    if looks_like_bare_identifier(cleaned) {
        out.push(cleaned.to_string());
        if cleaned != base {
            out.push(base.to_string());
        }
    }
}

fn strip_value_free_operator_operands(text: &str) -> String {
    const PAREN_OPERATORS: &[&str] = &[
        "sizeof",
        "_Alignof",
        "alignof",
        "__alignof__",
        "__typeof__",
        "typeof",
        "nameof",
    ];
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while cursor < text.len() {
        if let Some(operator) = value_free_operator_at(text, cursor, PAREN_OPERATORS) {
            let mut after = cursor + operator.len();
            if operator == "sizeof" && text[after..].starts_with("...") {
                after += 3;
            }
            let after_ws = skip_ascii_ws(text, after);
            if text[after_ws..].starts_with('(') {
                out.push_str(operator);
                out.push(' ');
                cursor = skip_balanced_paren_text(text, after_ws);
                continue;
            }
            if operator == "sizeof" || operator == "typeof" {
                out.push_str(operator);
                out.push(' ');
                cursor = skip_unary_operand_text(text, after_ws);
                continue;
            }
        }
        let ch = text[cursor..].chars().next().expect("valid char boundary");
        out.push(ch);
        cursor += ch.len_utf8();
    }
    out
}

fn operand_occurs_in_value_bearing_text(text: &str, operand: &str) -> bool {
    let operand = operand.trim();
    if operand.is_empty() {
        return false;
    }
    contains_identifier_operand(text, operand)
        || contains_identifier_operand(&normalise_qualified_text(text), operand)
        || operand.trim_start_matches(['$', '@', '%']).ne(operand)
            && contains_identifier_operand(text, operand.trim_start_matches(['$', '@', '%']))
}

fn contains_identifier_operand(text: &str, operand: &str) -> bool {
    if operand.is_empty() {
        return false;
    }
    let mut search_from = 0usize;
    while let Some(relative) = text[search_from..].find(operand) {
        let start = search_from + relative;
        let end = start + operand.len();
        let before_ok =
            start == 0 || is_identifier_operand_left_boundary(text.as_bytes()[start - 1], operand);
        let after_ok = text
            .as_bytes()
            .get(end)
            .is_none_or(|byte| !is_ident_continue_byte(*byte));
        if before_ok && after_ok {
            return true;
        }
        search_from = end;
    }
    false
}

fn is_identifier_operand_left_boundary(byte: u8, operand: &str) -> bool {
    if !is_ident_continue_byte(byte) {
        return true;
    }
    // Parser-surfaced interpolation operands in languages such as
    // Kotlin appear in source as `$name`, while the AST child text is
    // `name`. The sigil is expression punctuation, not part of the
    // runtime identifier value. Keep this adapter fact without opening
    // substring matches inside normal identifier text.
    matches!(byte, b'$' | b'@' | b'%') && !operand.as_bytes().starts_with(&[byte])
}

fn value_free_operator_at<'a>(text: &str, offset: usize, operators: &'a [&'a str]) -> Option<&'a str> {
    operators.iter().copied().find(|operator| {
        text[offset..].starts_with(operator)
            && (offset == 0 || !is_ident_continue_byte(text.as_bytes()[offset - 1]))
            && text
                .as_bytes()
                .get(offset + operator.len())
                .is_none_or(|byte| !is_ident_continue_byte(*byte))
    })
}

fn skip_ascii_ws(text: &str, mut offset: usize) -> usize {
    while let Some(byte) = text.as_bytes().get(offset) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        offset += 1;
    }
    offset
}

fn skip_balanced_paren_text(text: &str, open_pos: usize) -> usize {
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    let mut depth = 0isize;
    let bytes = text.as_bytes();
    let mut idx = open_pos;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == q {
                quote = None;
            }
            idx += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
            idx += 1;
            continue;
        }
        if byte == b'(' {
            depth += 1;
        } else if byte == b')' {
            depth -= 1;
            if depth == 0 {
                return idx + 1;
            }
        }
        idx += 1;
    }
    text.len()
}

fn skip_unary_operand_text(text: &str, offset: usize) -> usize {
    let mut idx = offset;
    while idx < text.len() {
        let byte = text.as_bytes()[idx];
        if byte.is_ascii_whitespace() || matches!(byte, b',' | b')' | b']' | b'}' | b'+' | b'-' | b'*' | b'/')
        {
            break;
        }
        idx += 1;
    }
    idx
}

/// Pull every dotted/arrow qualified access out of an arbitrary text
/// (`obj.field`, `$ctx->user`, `@foo.bar`). Tokens without at least one
/// `.`/`->` are dropped — bare identifiers don't qualify here.
///
/// Used by source-name extraction for compound assignment RHS, where
/// we want `y = obj.field` to track `obj.field` as a source not just `obj`.
fn qualified_accesses_from_text(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut qualified_accesses = Vec::new();
    let mut byte_idx = 0usize;
    // Track string-literal state — `obj.field` inside a quoted string is
    // a string, not an access expression.
    let mut active_quote: Option<u8> = None;
    let mut escape_next = false;
    while byte_idx < bytes.len() {
        let byte = bytes[byte_idx];
        if let Some(quote_byte) = active_quote {
            if escape_next {
                escape_next = false;
            } else if byte == b'\\' {
                escape_next = true;
            } else if byte == quote_byte {
                active_quote = None;
            }
            byte_idx += 1;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            active_quote = Some(byte);
            byte_idx += 1;
            continue;
        }
        if !is_qualified_base_start(bytes, byte_idx) {
            byte_idx += 1;
            continue;
        }

        // Found a candidate base — capture its sigil (if any) plus the
        // identifier body.
        let base_start_idx = byte_idx;
        if matches!(bytes[byte_idx], b'$' | b'@' | b'%') {
            byte_idx += 1;
        }
        // After a sigil we still need a real identifier-start byte —
        // otherwise back up and continue from the next byte.
        if byte_idx >= bytes.len() || !is_ident_start_byte(bytes[byte_idx]) {
            byte_idx = base_start_idx + 1;
            continue;
        }
        byte_idx += 1;
        while byte_idx < bytes.len() && is_ident_continue_byte(bytes[byte_idx]) {
            byte_idx += 1;
        }
        let mut accumulated = text[base_start_idx..byte_idx].to_string();
        let mut at_least_one_field_seen = false;

        // Greedily extend with `.field` / `->field` / `->{field}` segments.
        loop {
            // Dotted access — JS/Python/Java/Go style.
            if byte_idx < bytes.len() && bytes[byte_idx] == b'.' {
                let field_start = byte_idx + 1;
                if field_start >= bytes.len() || !is_ident_start_byte(bytes[field_start]) {
                    break;
                }
                let mut field_end = field_start + 1;
                while field_end < bytes.len() && is_ident_continue_byte(bytes[field_end]) {
                    field_end += 1;
                }
                accumulated.push('.');
                accumulated.push_str(&text[field_start..field_end]);
                at_least_one_field_seen = true;
                byte_idx = field_end;
                continue;
            }
            // Arrow access — Perl/PHP/C style. May be brace-wrapped:
            // `$ctx->{user}`.
            if byte_idx + 1 < bytes.len() && bytes[byte_idx] == b'-' && bytes[byte_idx + 1] == b'>' {
                let mut field_start = byte_idx + 2;
                let brace_wrapped = field_start < bytes.len() && bytes[field_start] == b'{';
                if brace_wrapped {
                    field_start += 1;
                }
                if field_start >= bytes.len() || !is_ident_start_byte(bytes[field_start]) {
                    break;
                }
                let mut field_end = field_start + 1;
                while field_end < bytes.len() && is_ident_continue_byte(bytes[field_end]) {
                    field_end += 1;
                }
                accumulated.push('.');
                accumulated.push_str(&text[field_start..field_end]);
                at_least_one_field_seen = true;
                // Step past the closing brace when present.
                byte_idx = if brace_wrapped && field_end < bytes.len() && bytes[field_end] == b'}' {
                    field_end + 1
                } else {
                    field_end
                };
                continue;
            }
            // Static subscript access — Python/JS/Ruby style. Treat
            // string/symbol identifier keys as field projections:
            // `env["cmd"]` / `env['cmd']` / `params[:token]` →
            // `env.cmd` / `params.token`. Dynamic indexes are not
            // field-precise and intentionally stop extension here.
            if byte_idx < bytes.len() && bytes[byte_idx] == b'[' {
                let mut cursor = byte_idx + 1;
                while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if cursor >= bytes.len() {
                    break;
                }
                let mut symbol_key = false;
                if bytes[cursor] == b':' {
                    symbol_key = true;
                    cursor += 1;
                }
                let quote = bytes.get(cursor).copied().filter(|b| matches!(b, b'\'' | b'"'));
                if quote.is_some() {
                    cursor += 1;
                }
                let field_start = cursor;
                if field_start >= bytes.len() || !is_ident_start_byte(bytes[field_start]) {
                    break;
                }
                cursor += 1;
                while cursor < bytes.len() && is_ident_continue_byte(bytes[cursor]) {
                    cursor += 1;
                }
                let field_end = cursor;
                if let Some(q) = quote {
                    if cursor >= bytes.len() || bytes[cursor] != q {
                        break;
                    }
                    cursor += 1;
                } else if !symbol_key {
                    break;
                }
                while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if cursor >= bytes.len() || bytes[cursor] != b']' {
                    break;
                }
                accumulated.push('.');
                accumulated.push_str(&text[field_start..field_end]);
                at_least_one_field_seen = true;
                byte_idx = cursor + 1;
                continue;
            }
            break;
        }

        // Bare identifiers don't qualify; we only emit when at least one
        // field was attached. Dedup against previous entries.
        if at_least_one_field_seen && !qualified_accesses.iter().any(|existing| existing == &accumulated) {
            qualified_accesses.push(accumulated);
        }
    }
    qualified_accesses
}

/// True when `bytes[i]` could begin a qualified-access base — an
/// identifier-start byte or one of the recognised sigils, and not
/// continuing a longer identifier.
fn is_qualified_base_start(bytes: &[u8], i: usize) -> bool {
    let byte = bytes[i];
    let could_start_identifier = is_ident_start_byte(byte) || matches!(byte, b'$' | b'@' | b'%');
    could_start_identifier && (i == 0 || !is_ident_continue_byte(bytes[i - 1]))
}

/// Identifier-start byte: `_` or ASCII alphabetic.
fn is_ident_start_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

/// Identifier-continue byte: `_`, `$`, or ASCII alphanumeric.
pub(crate) fn is_ident_continue_byte(byte: u8) -> bool {
    byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric()
}

/// If `node` is a direct call expression (call / method-invocation /
/// similar), extract `(Some(callee_name), positional_arg_texts)`
/// so the surrounding `FlowEvent::Assign` can carry the call as its
/// RHS signal. Returns `None` for non-call RHS.
///
/// The returned callee name preserves receivers (`item.get`, not just
/// `get`) so downstream taint can model receiver-derived return
/// values. Resolver code still falls back to the short tail when it
/// needs to bind to a local function declaration. The returned arg
/// texts are the raw source strings of each positional argument.
pub(crate) fn extract_direct_call_info(node: &Node<'_>, src: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    if !COMMON_CALL_KINDS.contains(&node.kind()) {
        // Recurse only where a descendant call genuinely IS the RHS's
        // operative call: transparent single-call wrappers (member /
        // await / paren chains), a grouping list wrapping exactly one
        // expression (Go / Python `x := f()` → `expression_list` of one
        // call), or a lambda / closure literal whose body forwards into
        // a callee (`f = |x| sink(x)` — the legacy closure model binds
        // the lambda's call so invoking `f(arg)` reaches the sink). A
        // compound RHS (`a + f()`) or a multi-value list (`f(), g()`)
        // must NOT collapse to its first call — it falls through to
        // `source_names`.
        let single_expr_grouping = grouping_list_kind(node.kind()) && node.named_child_count() == 1;
        if !direct_call_wrapper_kind(node.kind())
            && !single_expr_grouping
            && !lambda_closure_kind(node.kind())
        {
            return None;
        }
        return first_call_descendant(*node).and_then(|call| extract_direct_call_info(&call, src));
    }
    let erlang_remote = node
        .child_by_field_name("expr")
        .and_then(|expr| erlang_remote_callee(&expr, src));
    let method_compound = method_receiver_name(node, src);
    // Callee node via common field names.
    let callee = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("callee"))
        .or_else(|| erlang_remote.as_ref().map(|(n, _)| *n))
        .or_else(|| method_compound.as_ref().map(|(n, _)| *n))
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| first_callee_expression_child(node))
        .or_else(|| first_identifier_like_child(node))?;
    let full = erlang_remote
        .as_ref()
        .map(|(_, name)| name.clone())
        .or_else(|| method_compound.as_ref().map(|(_, name)| name.clone()))
        .unwrap_or_else(|| node_text(&callee, src).trim().to_string());
    let full = normalize_call_name_whitespace(&full);
    if full.is_empty() {
        return None;
    }
    // Positional args — the arguments field is most commonly
    // `arguments`; grammars also expose it via `argument_list`.
    let args_node = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("args"))
        .or_else(|| first_named_child_of_kind(node, "arguments"))
        .or_else(|| first_named_child_of_kind(node, "argument_list"));
    let mut args: Vec<String> = Vec::new();
    if let Some(an) = args_node {
        let mut cursor = an.walk();
        for child in an.named_children(&mut cursor) {
            // Skip keyword-argument wrappers — we only want positional
            // text here. Keyword args don't participate in G1's
            // param-index-based summary lookup.
            if matches!(child.kind(), "keyword_argument" | "named_argument") {
                continue;
            }
            let t = normalize_call_name_whitespace(node_text(&child, src));
            if !t.is_empty() {
                args.push(t);
            }
        }
    } else {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !matches!(child.kind(), "argument" | "call_argument") {
                continue;
            }
            let t = normalize_call_name_whitespace(node_text(&child, src));
            if !t.is_empty() {
                args.push(t);
            }
        }
    }
    Some((Some(full), args))
}

/// Grammar node kinds that group a comma-separated expression series
/// (Go `expression_list`, Python tuple targets). When such a list wraps
/// exactly ONE expression it is a transparent wrapper around that single
/// expression; with more than one it is a genuine multi-value series and
/// must not be collapsed to its first call.
fn grouping_list_kind(kind: &str) -> bool {
    matches!(kind, "expression_list" | "expressions" | "expression_series")
}

/// Lambda / closure literal node kinds across the supported grammars.
/// When such a literal is the RHS of an assignment, the legacy closure
/// model forwards the lambda's operative call so a later invocation of
/// the bound variable reaches it.
fn lambda_closure_kind(kind: &str) -> bool {
    matches!(
        kind,
        "lambda"
            | "lambda_expression"
            | "lambda_literal"
            | "anonymous_function"
            | "anonymous_function_creation_expression"
            | "function_expression"
            | "function_definition"
            | "arrow_function"
            | "closure"
            | "closure_expression"
            | "fun_expr"
            | "block_literal"
            | "block_literal_expression"
    )
}

fn direct_call_wrapper_kind(kind: &str) -> bool {
    matches!(
        kind,
        "field_expression"
            | "member_expression"
            | "member_access_expression"
            | "navigation_expression"
            | "selector_expression"
            | "scoped_identifier"
            | "scope_resolution"
            | "selector"
            | "postfix_expression"
            | "parenthesized_expression"
            | "expression"
            | "primary_expression"
            // `await EXPR` is a transparent wrapper around its operand —
            // Python's grammar names the node `await` (bare), C++/JS use
            // `await_expression` / `co_await_expression`. Without `await`
            // here, `x = await f(arg)` fell through to `source_names` and
            // tokenized the `await` keyword + callee as pseudo-operands,
            // dropping the real `f(arg)` call (and overwriting `x`'s
            // taint with a clean value — see the async-for `chunk`
            // regression in examples/python/mega_flow).
            | "await"
            | "await_expression"
            | "co_await_expression"
            // Rust `expr?` (H25): a transparent single-call wrapper around
            // its operand, so `let x = foo()?` binds the `foo` call result
            // just like `let x = foo()` and return-summary taint flows.
            | "try_expression"
            // TS/C# type-assertion wrappers (M20): `const y = f(x) as T`,
            // `g() satisfies T`, `h()!`, `<T>i()`. These are transparent
            // single-call wrappers around their operand for the purpose of
            // the Assign->call source-call binding. `direct_call_wrapper_kind`
            // feeds ONLY `extract_direct_call_info` (the source_call binding
            // at the Assign RHS) and param extraction -- NOT
            // `extract_rhs_expr_operands` -- so this does not drop `raw` from
            // C# `new List<string>{ raw! }` ctor operands (the earlier
            // regression came from a broader change; the bare-operand path is
            // untouched here). For a no-arg transit `g() as T`, binding the
            // call result keeps `classify_assign_value_kinds` from labeling
            // the RHS a `Literal` and erasing prior taint.
            | "as_expression"
            | "satisfies_expression"
            | "non_null_expression"
            | "type_assertion"
            | "dot"
    )
}

/// True when the function's parameter list ends in a positional variadic
/// collector (`*args`, `...rest`, `T...`). Combined by callers with the
/// synthetic `__bonsai_varargs` marker (C-family bare `...`). Checks the
/// DIRECT children of the parameter container only, so a splat inside a
/// default-value expression (`def f(x=[*a])`) does not falsely flag the
/// callee. Keyword collectors (`**kwargs`, Ruby `**opts`) are deliberately
/// excluded -- they do not absorb overflow POSITIONAL args (audit M1).
fn parameter_list_is_variadic(fn_node: &Node<'_>) -> bool {
    const VARIADIC_PARAM_KINDS: &[&str] = &[
        "variadic_parameter", // go `...T`, php `...$x`, c `...`
        "variadic_declaration",
        "spread_parameter",   // java `T... args`
        "rest_parameter",     // typescript `...args`
        "rest_pattern",       // javascript `...args`
        "list_splat_pattern", // python `*args`
        "splat_parameter",    // ruby `*args`
    ];
    let Some(container) = fn_node
        .child_by_field_name("parameters")
        .or_else(|| first_named_child_of_kind(fn_node, "parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "formal_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "parameter_list"))
        .or_else(|| first_named_child_of_kind(fn_node, "function_value_parameters"))
        .or_else(|| first_named_child_of_kind(fn_node, "formal_parameter_list"))
    else {
        return false;
    };
    // Collect into Vecs first: tree-sitter cursors cannot outlive a borrow
    // inside an `.any()` closure, so the codebase materializes children
    // before iterating.
    let mut cursor = container.walk();
    let params: Vec<Node<'_>> = container.named_children(&mut cursor).collect();
    for param in params {
        if VARIADIC_PARAM_KINDS.contains(&param.kind()) {
            return true;
        }
        // A rest element nested inside a DESTRUCTURING pattern parameter
        // (`function f({a, ...rest}, b)` / `function f([x, ...tail])`) is
        // NOT a positional overflow collector -- it gathers the remaining
        // keys/elements of THAT one argument, so it must not flag the whole
        // callee variadic. Skip the nested scan for destructuring patterns.
        if matches!(
            param.kind(),
            "object_pattern" | "array_pattern" | "object_type" | "tuple_pattern"
        ) {
            continue;
        }
        // Some grammars wrap the splat one level down (a `parameter` whose
        // child is a `rest_pattern` / `list_splat_pattern`).
        let mut inner = param.walk();
        let nested: Vec<Node<'_>> = param.named_children(&mut inner).collect();
        if nested.iter().any(|c| VARIADIC_PARAM_KINDS.contains(&c.kind())) {
            return true;
        }
    }
    false
}

/// For a C/C++ `function_declarator` (or a definition node wrapping one),
/// if its declarator is a qualified/scoped name (`Class::method`), return
/// the `name` field node so an out-of-line definition is keyed under
/// `method`, not the leftmost scope token `Class` (H8).
fn qualified_method_name_node<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    let inner = if node.kind() == "function_declarator" {
        node.child_by_field_name("declarator")?
    } else {
        node.child_by_field_name("declarator")
            .filter(|d| d.kind() == "function_declarator")
            .and_then(|d| d.child_by_field_name("declarator"))?
    };
    if matches!(inner.kind(), "qualified_identifier" | "scoped_identifier") {
        inner.child_by_field_name("name")
    } else {
        None
    }
}

fn first_call_descendant<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
    for child in children {
        if COMMON_CALL_KINDS.contains(&child.kind()) {
            return Some(child);
        }
        if let Some(found) = first_call_descendant(child) {
            return Some(found);
        }
    }
    None
}

fn extract_dart_selector_call_info(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
) -> Option<(Option<String>, Vec<String>)> {
    let selector = if node.kind() == "selector" {
        Some(node)
    } else {
        first_dart_selector_call_descendant(node)
    }?;
    let FlowEvent::Call { name, args, .. } = build_dart_selector_call_event(selector, file, src)? else {
        return None;
    };
    let positional_args = args
        .into_iter()
        .filter(|arg| arg.name.is_none())
        .map(|arg| arg.value_text)
        .filter(|arg| !arg.trim().is_empty())
        .collect();
    Some((Some(name), positional_args))
}

fn first_dart_selector_call_descendant<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
    for child in children {
        if child.kind() == "selector" && first_named_child_of_kind(&child, "argument_part").is_some() {
            return Some(child);
        }
        if let Some(found) = first_dart_selector_call_descendant(child) {
            return Some(found);
        }
    }
    None
}

fn next_named_sibling_within<'tree>(parent: &Node<'tree>, after: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = parent.walk();
    let mut seen = false;
    for child in parent.named_children(&mut cursor) {
        if child.id() == after.id() {
            seen = true;
            continue;
        }
        if !seen {
            continue;
        }
        if looks_like_branch_arm_node(child.kind()) {
            return Some(child);
        }
    }
    None
}

fn synthetic_function_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() == "constructor_definition" {
        return Some("constructor".to_string());
    }
    if node.kind() == "fallback_receive_definition" {
        let text = node_text(node, src).trim_start();
        if text.starts_with("receive") {
            return Some("receive".to_string());
        }
        if text.starts_with("fallback") {
            return Some("fallback".to_string());
        }
        return Some("fallback_receive".to_string());
    }
    None
}

fn extract_match_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    out.extend(extract_instanceof_pattern_binding_assigns(file, node, src));
    out.extend(extract_is_pattern_binding_assigns(file, node, src));
    out.extend(extract_kotlin_when_subject_binding_assigns(file, node, src));
    out.extend(extract_case_match_binding_assigns(file, node, src));
    out.extend(extract_case_pattern_binding_assigns(file, node, src));
    out.extend(extract_elixir_case_stab_clause_bindings(file, node, src));

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

fn extract_elixir_case_stab_clause_bindings(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
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

fn binding_targets_from_pattern_node(pattern: &Node<'_>, src: &[u8]) -> Vec<String> {
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

fn pattern_binding_assign(
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

fn dedup_assign_events(events: Vec<FlowEvent>) -> Vec<FlowEvent> {
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
fn extract_comprehension_for_clause_assigns(file: FileId, clause: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
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

fn extract_foreach_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
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

fn iterable_source_names_from_text(text: &str) -> Vec<String> {
    let mut source_names = identifier_tokens_from_text(text);
    if text.contains("...") && !source_names.iter().any(|name| name == SYNTHETIC_VARARGS_PARAM) {
        source_names.push(SYNTHETIC_VARARGS_PARAM.to_string());
    }
    source_names.sort();
    source_names.dedup();
    source_names
}

/// Extract bare-identifier-shaped tokens from arbitrary expression
/// text. Used as a fallback by adapters when the AST walk doesn't
/// surface every operand structurally (loop iterables, match
/// subjects, comprehension binders, assignment-RHS fallback).
///
/// Critical correctness property: contents inside string / template
/// literal delimiters are SKIPPED. Without this, hardcoded strings
/// like `".category == \"electronics\""` would surface
/// `["category", "electronics"]` as bare identifiers, polluting
/// `source_names` and creating cross-cutting over-taint across
/// every adapter that uses the fallback.
///
/// Three quote styles cover every supported grammar: `"..."` (most
/// languages), `'...'` (Python/Ruby/PHP/Perl/Lua/etc.) and
/// `` `...` `` (template literals in JS/TS/Scala, raw strings in
/// Go). f-string / template-literal interpolation is intentionally
/// NOT walked here — interpolated identifiers are surfaced from real
/// AST children by `extract_rhs_expr_operands` and attached to
/// assignment or call-argument `source_names`. The taint engine does
/// not parse interpolation syntax out of raw string text.
fn identifier_tokens_from_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == q {
                in_quote = None;
            }
            continue;
        }
        if matches!(c, '"' | '\'' | '`') {
            if !current.is_empty() {
                push_text_identifier(&mut out, &mut current);
            }
            in_quote = Some(c);
            continue;
        }
        if c == '_' || c == '$' || c.is_ascii_alphanumeric() {
            current.push(c);
        } else if !current.is_empty() {
            push_text_identifier(&mut out, &mut current);
        }
    }
    if !current.is_empty() {
        push_text_identifier(&mut out, &mut current);
    }
    out.sort();
    out.dedup();
    out
}

fn push_text_identifier(out: &mut Vec<String>, current: &mut String) {
    let cleaned = current.trim_start_matches('$');
    if looks_like_bare_identifier(cleaned) {
        out.push(cleaned.to_string());
        if cleaned != current {
            out.push(current.clone());
        }
    }
    current.clear();
}

/// True when `op` is a compound (read-modify-write) assignment operator
/// like `+=`, `||=`, `.=`, `<<=`. A bare `=` is NOT compound, nor are
/// comparisons (`==`, `<=`), the walrus/short-var `:=`, or the arrow `=>`.
fn is_compound_assignment_operator(op: &str) -> bool {
    let op = op.trim();
    op.len() >= 2
        && op.ends_with('=')
        && !matches!(op, "==" | "!=" | "<=" | ">=" | ":=" | "=>")
        && op.chars().next().is_some_and(|c| {
            matches!(
                c,
                '+' | '-' | '*' | '/' | '%' | '&' | '|' | '^' | '.' | '<' | '>' | '?' | '~'
            )
        })
}

/// True when an assignment node is a compound `x OP= rhs` (so `x` is
/// always a read operand). Recognized by node kind, an `operator` field,
/// or a top-level `OP=` token among the node's unnamed children.
fn assignment_is_compound(node: &Node<'_>, kind: &str, src: &[u8]) -> bool {
    if matches!(
        kind,
        "augmented_assignment"
            | "augmented_assignment_expression"
            | "compound_assignment_expr"
            | "operator_assignment"
    ) {
        return true;
    }
    if let Some(op) = node.child_by_field_name("operator") {
        if is_compound_assignment_operator(node_text(&op, src)) {
            return true;
        }
    }
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    children
        .iter()
        .any(|child| !child.is_named() && is_compound_assignment_operator(node_text(child, src)))
}

/// Clean up an assign-target string picked up from a grammar
/// whose named-child exposure loses the bare identifier. Drops
/// the RHS when the text has shape `lhs = rhs`, strips trailing
/// declaration-only keywords (types / `my` / `let`), and keeps
/// only the last whitespace-delimited token when a type prefix
/// survives (`bytes32 t` → `t`, `my $query` → `$query`). Tuple
/// targets (Go `result, _`) keep only the first binding so the
/// emitted `target` is a plain identifier callers can substring
/// on.
#[must_use]
pub fn sanitize_assign_target(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Strip RHS: `action = req.Query[...]` → `action`.
    let lhs = trimmed.split_once('=').map_or(trimmed, |(l, _)| l).trim();
    // Tuple / destructuring: keep the first comma-delimited piece.
    // Covers Go `result, _ := foo()` and similar multi-return patterns.
    let first_tuple = lhs.split_once(',').map_or(lhs, |(a, _)| a).trim();
    if first_tuple.contains('[') {
        return normalise_qualified_text(first_tuple)
            .split_whitespace()
            .collect::<String>();
    }
    // Last whitespace-delimited token survives, so `my $query` → `$query`,
    // `bytes32 t` → `t`, `const int x` → `x`.
    let last_tok = first_tuple.split_whitespace().next_back().unwrap_or(first_tuple);
    last_tok
        .trim_matches(|c: char| {
            !(c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '@' | '%' | '!' | '?'))
        })
        .to_string()
}

/// Compare two identifier names, ignoring leading sigils (`$`, `@`, `%`)
/// so Perl `$foo` and adapter-emitted `foo` map to the same binding.
fn same_identifier_name(left: &str, right: &str) -> bool {
    let left_bare = left.trim().trim_start_matches(['$', '@', '%']);
    let right_bare = right.trim().trim_start_matches(['$', '@', '%']);
    left_bare == right_bare
}

/// Pull additional assign targets out of a multi-binding LHS — tuples,
/// destructures, parallel assignments. The `primary` target is already
/// emitted by the caller; this returns the *extras* the caller still
/// needs to emit one Assign event each for.
fn extra_assign_targets(raw: &str, primary: &str) -> Vec<String> {
    let lhs_text = raw
        .trim()
        .split_once('=')
        .map_or(raw.trim(), |(lhs, _)| lhs)
        .trim();
    let lhs_start = lhs_text.trim_start();
    if !lhs_start.starts_with(['[', '{', '('])
        && (lhs_text.contains('[') || lhs_text.contains('.') || lhs_text.contains("->"))
    {
        return Vec::new();
    }
    let mut extra_targets = Vec::new();
    // Comma-delimited tuple — skip the first element (it's `primary`).
    for tuple_part in lhs_text.split(',').skip(1) {
        let sanitized = sanitize_assign_target(tuple_part);
        if !sanitized.is_empty() && sanitized != primary && !extra_targets.iter().any(|t| t == &sanitized) {
            extra_targets.push(sanitized);
        }
    }
    // Pattern-shaped LHS — JS array/object destructure, Ruby pattern
    // assignment, Perl list assignment. Walk the pattern for binding
    // tokens.
    if primary.is_empty() || lhs_text.trim_start().starts_with('[') || lhs_text.contains(['(', '{', '|']) {
        for binding_token in binding_tokens_from_pattern(lhs_text) {
            let sanitized = sanitize_assign_target(&binding_token);
            if !sanitized.is_empty() && sanitized != primary && !extra_targets.iter().any(|t| t == &sanitized)
            {
                extra_targets.push(sanitized);
            }
        }
    }
    extra_targets
}

fn extra_lhs_binding_targets(
    node: &Node<'_>,
    target_node: Option<Node<'_>>,
    src: &[u8],
    primary: &str,
) -> Vec<String> {
    let lhs = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("target"))
        .or_else(|| first_named_child_of_kind(node, "variable_list"))
        .or_else(|| first_named_child_of_kind(node, "variables"))
        .or_else(|| first_named_child_of_kind(node, "pattern"));
    let Some(lhs) = lhs else {
        return Vec::new();
    };
    let lhs_text = node_text(&lhs, src);
    if qualified_assign_target(Some(lhs), src).is_some()
        || lhs_text.contains('[')
        || lhs_text.contains('.')
        || lhs_text.contains("->")
    {
        return Vec::new();
    }
    if target_node.is_some_and(|target| target.id() == lhs.id()) && !node_text(&lhs, src).contains(',') {
        return Vec::new();
    }
    let mut out = Vec::new();
    for target in binding_tokens_from_pattern(lhs_text) {
        let target = sanitize_assign_target(&target);
        if !target.is_empty() && target != primary && !out.iter().any(|t| t == &target) {
            out.push(target);
        }
    }
    out
}

fn ruby_append_mutation_assignment(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<FlowEvent>,
) -> bool {
    if node.kind() != "binary" {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    let Ok(operator_text) = std::str::from_utf8(&src[left.end_byte()..right.start_byte()]) else {
        return false;
    };
    if operator_text.trim() != "<<" {
        return false;
    }
    let target = qualified_assign_target(Some(left), src)
        .unwrap_or_else(|| sanitize_assign_target(node_text(&left, src)));
    if target.is_empty() {
        return false;
    }
    let right_text = node_text(&right, src).trim();
    let source_name = looks_like_bare_identifier(right_text).then(|| right_text.to_string());
    let mut source_names = extract_rhs_expr_operands(&right, src);
    if source_names.is_empty() {
        if let Some(source_name) = source_name.as_ref() {
            source_names.push(source_name.clone());
        }
    }
    source_names.retain(|name| !same_identifier_name(name, &target));
    source_names.sort();
    source_names.dedup();
    out.push(FlowEvent::Assign {
        span: span_of(file, node),
        target,
        source_name,
        source_call: None,
        source_call_args: Vec::new(),
        source_names,
        declares_new_binding: false,
        value_kind: None,
    });
    true
}

fn binding_tokens_from_pattern(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut token_start = 0usize;
    for (idx, c) in pattern.char_indices() {
        if c == '_' || c == '$' || c == '@' || c == '%' || c.is_ascii_alphanumeric() {
            if current.is_empty() {
                token_start = idx;
            }
            current.push(c);
        } else if !current.is_empty() {
            push_pattern_binding(pattern, token_start, idx, &mut current, &mut out);
        }
    }
    if !current.is_empty() {
        push_pattern_binding(pattern, token_start, pattern.len(), &mut current, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

fn push_pattern_binding(
    pattern: &str,
    start: usize,
    end: usize,
    current: &mut String,
    out: &mut Vec<String>,
) {
    let raw = std::mem::take(current);
    let cleaned = raw.trim_start_matches(&['$', '@', '%'][..]);
    let prev = pattern[..start].chars().rev().find(|c| !c.is_whitespace());
    let next = pattern[end..].chars().find(|c| !c.is_whitespace());
    let is_map_key = next == Some(':');
    let is_type_name = prev == Some('%') || cleaned.chars().next().is_some_and(|c| c.is_ascii_uppercase());
    let is_keyword = matches!(
        cleaned,
        "my" | "our"
            | "local"
            | "let"
            | "var"
            | "const"
            | "auto"
            | "in"
            | "do"
            | "true"
            | "false"
            | "nil"
            | "null"
            | "_"
    );
    if !is_map_key && !is_type_name && !is_keyword && looks_like_bare_identifier(cleaned) {
        let stripped = cleaned.to_string();
        let has_sigil = stripped != raw;
        out.push(raw);
        if has_sigil {
            out.push(stripped);
        }
    }
}

/// Fold every run of ASCII whitespace (spaces, tabs, newlines) in
/// `raw` into a single space and trim the result. Used to normalise
/// callee text across multi-line method chains — a Rust /
/// Swift / Kotlin expression spanning multiple source lines would
/// otherwise keep its embedded newlines + indentation in the
/// callee's displayed `name` field, cluttering the `calls` column
/// and breaking downstream substring filters.
#[must_use]
pub fn normalize_call_name_whitespace(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_ws = false;
    for c in raw.chars() {
        if c.is_whitespace() {
            if !in_ws {
                if !out.is_empty() {
                    out.push(' ');
                }
                in_ws = true;
            }
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    // `in_ws` at end means we pushed a trailing space; strip it.
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Strip common qualifier prefixes so `foo.bar.baz` / `Foo::bar` /
/// `this->bar` / `module:fn` (Erlang) resolve to the bare name.
pub fn short_name_of(raw: &str) -> &str {
    let trimmed = raw
        .trim()
        .trim_start_matches('&')
        .trim_start_matches('*')
        .trim_end_matches('!');
    let mut best = trimmed;
    // `::` must come before `:` so `Foo::bar` keeps `bar`, not `:bar`.
    // `.` and `->` are unambiguous. Erlang's single `:` is the last
    // fallback so we don't break the earlier matches.
    for sep in ["::", "->", ".", ":"] {
        if let Some(idx) = best.rfind(sep) {
            best = &best[idx + sep.len()..];
        }
    }
    best
}

/// Build a [`GrammarHandler`] that uses the supplied function-kind
/// list and inherits every other field from [`GENERIC_HANDLER`].
/// `const` so adapters can stamp out their handler at compile time:
///
/// ```ignore
/// const HANDLER: GrammarHandler = bonsai_lang_api::with_fn_kinds(&["function_definition"]);
/// ```
///
/// Use this when the language's grammar uses common construct names
/// for everything except the function-definition kind. Override the
/// resulting handler manually when grammar-specific kinds need
/// language-aware coverage.
#[must_use]
pub const fn with_fn_kinds(fn_kinds: &'static [&'static str]) -> GrammarHandler {
    with_fn_kinds_and_implicit_receivers(
        fn_kinds,
        GENERIC_HANDLER.implicit_receiver_names,
        GENERIC_HANDLER.implicit_receiver_prefixes,
    )
}

/// Convenience for adapters whose methods have implicit receiver syntax
/// rather than an explicit receiver parameter.
pub const fn with_fn_kinds_and_implicit_receivers(
    fn_kinds: &'static [&'static str],
    implicit_receiver_names: &'static [&'static str],
    implicit_receiver_prefixes: &'static [&'static str],
) -> GrammarHandler {
    GrammarHandler {
        fn_kinds,
        class_kinds: GENERIC_HANDLER.class_kinds,
        method_kinds: GENERIC_HANDLER.method_kinds,
        method_context_kinds: GENERIC_HANDLER.method_context_kinds,
        constructor_method_kinds: GENERIC_HANDLER.constructor_method_kinds,
        constructor_names: GENERIC_HANDLER.constructor_names,
        if_kinds: GENERIC_HANDLER.if_kinds,
        for_kinds: GENERIC_HANDLER.for_kinds,
        foreach_kinds: GENERIC_HANDLER.foreach_kinds,
        while_kinds: GENERIC_HANDLER.while_kinds,
        do_kinds: GENERIC_HANDLER.do_kinds,
        loop_kinds: GENERIC_HANDLER.loop_kinds,
        call_kinds: GENERIC_HANDLER.call_kinds,
        assignment_kinds: GENERIC_HANDLER.assignment_kinds,
        return_kinds: GENERIC_HANDLER.return_kinds,
        throw_kinds: GENERIC_HANDLER.throw_kinds,
        lambda_kinds: GENERIC_HANDLER.lambda_kinds,
        try_kinds: GENERIC_HANDLER.try_kinds,
        catch_kinds: GENERIC_HANDLER.catch_kinds,
        finally_kinds: GENERIC_HANDLER.finally_kinds,
        break_kinds: GENERIC_HANDLER.break_kinds,
        continue_kinds: GENERIC_HANDLER.continue_kinds,
        yield_kinds: GENERIC_HANDLER.yield_kinds,
        await_kinds: GENERIC_HANDLER.await_kinds,
        defer_kinds: GENERIC_HANDLER.defer_kinds,
        using_kinds: GENERIC_HANDLER.using_kinds,
        method_receiver_param_index: GENERIC_HANDLER.method_receiver_param_index,
        implicit_receiver_names,
        implicit_receiver_prefixes,
        tail_expression_returns: GENERIC_HANDLER.tail_expression_returns,
    }
}

/// Full pipeline for [`crate::LanguageAdapter::extract_imports`]:
/// parse the file (returning an empty index on parse failure),
/// then hand `tree`/`src`/`file` to a per-language extractor
/// that returns the [`crate::ImportSpec`] entries.
///
/// Every adapter calls this helper from its `extract_imports` impl
/// so the parse + empty-handling boilerplate lives in exactly one
/// place. The per-language `parse` callback contains the only
/// grammar-specific logic, keeping every adapter's import path
/// uniform in shape.
pub fn extract_imports_via<F>(
    pack_name: &str,
    file: FileId,
    ctx: &AdapterContext<'_>,
    parse: F,
) -> crate::ImportIndex
where
    F: FnOnce(&Tree, &[u8], FileId) -> Vec<crate::ImportSpec>,
{
    let Some((snapshot, tree)) = parse_with(pack_name, file, ctx) else {
        return crate::ImportIndex {
            file,
            ..Default::default()
        };
    };
    let imports = parse(&tree, snapshot.text.as_bytes(), file);
    crate::ImportIndex { file, imports }
}

/// Full adapter pipeline: parse with `pack_name`, scan for declarations,
/// populate each function's `flow_events` via [`walk_flow_events`], and
/// collect top-level call refs for legacy consumers.
pub fn decl_index_with_handler(
    pack_name: &str,
    file: FileId,
    ctx: &AdapterContext<'_>,
    handler: &GrammarHandler,
) -> crate::DeclIndex {
    let Some((snapshot, tree)) = parse_with(pack_name, file, ctx) else {
        return crate::DeclIndex {
            file,
            ..Default::default()
        };
    };
    let src = snapshot.text.as_bytes();
    // Cheap subtree flag; per-decl gates below only fire when true.
    let file_has_syntax_errors = tree.root_node().has_error();
    // Exact ERROR / MISSING spans, computed once. A callable with a
    // recovered parse error keeps the flow events from its
    // correctly-parsed statements and drops only the events that
    // actually fall inside an error span — so one malformed expression
    // (a complex string interpolation, an unsupported attribute) no
    // longer discards every call/flow in the enclosing function.
    let error_spans: Vec<Span> = if file_has_syntax_errors {
        syntax_error_spans(&tree, file)
    } else {
        Vec::new()
    };

    // Pass 1: collect classes — needed to recognize ctor calls during walk.
    let class_nodes = collect_kinds(&tree, handler.class_kinds);
    let mut class_names: Vec<String> = Vec::new();
    for n in &class_nodes {
        if let Some(nm) = n
            .child_by_field_name("name")
            .or_else(|| first_identifier_like_child(n))
        {
            let name = node_text(&nm, src).to_string();
            if !name.is_empty() {
                class_names.push(name);
            }
        }
    }

    // Pass 2: function-like declarations.
    let fn_nodes = collect_kinds(&tree, handler.fn_kinds);
    let mut defs: Vec<crate::Decl> = Vec::new();
    let mut function_parent_spans: Vec<(bonsai_common::SymbolId, bonsai_common::Span)> = Vec::new();
    let mut next: u32 = 0;
    for node in fn_nodes {
        // Elixir-specific: `def foo(x) do ... end` parses as a `call`
        // whose target is `def` / `defp`, first argument is a *second*
        // `call` carrying the real function name, and a `do_block`
        // child holding the body. Skip `call` nodes that don't look
        // like a def-macro (ordinary runtime calls also match the
        // `call` kind) and unwrap the ones that do.
        let elixir_def = if node.kind() == "call" {
            elixir_unwrap_def(&node, src)
        } else {
            None
        };
        // Prefer `name` field when the grammar exposes one (Rust, JS,
        // Python, Java, etc.). C / C++ `function_definition` nodes have
        // no `name` field but wrap the identifier in a `declarator`
        // subtree — dig into that BEFORE falling back to
        // `first_identifier_like_child`, which would otherwise pick the
        // return-type identifier (`UserInfo` in `UserInfo *get_user(...)`).
        let name_node = elixir_def
            .as_ref()
            .map(|def| def.name)
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| binding_name_node(&node))
            // H8: out-of-line `RetType Class::method(...)` — take the
            // qualified declarator's `name` field so the decl is keyed
            // under `method`, not the scope token `Class`.
            .or_else(|| {
                node.child_by_field_name("declarator")
                    .and_then(|d| qualified_method_name_node(&d))
            })
            .or_else(|| {
                node.child_by_field_name("declarator")
                    .and_then(first_identifier_descendant)
            })
            .or_else(|| first_identifier_like_child(&node));
        let synthetic_name = name_node
            .is_none()
            .then(|| synthetic_function_name(&node, src))
            .flatten();
        let Some(name_node) = name_node.or_else(|| synthetic_name.as_ref().map(|_| node)) else {
            continue;
        };
        // Lua-style `function M.updateUser(...)` gives us a
        // `dot_index_expression` (table + field) as the name node. Its
        // text is the dotted form `M.updateUser`; downstream resolution
        // works against the bare method name. Walk to the `field` child
        // when present so the stored decl name is the short form and
        // name-resolution doesn't need module-prefix stripping.
        let name_node = name_node.child_by_field_name("field").unwrap_or(name_node);
        let name = synthetic_name
            .as_deref()
            .unwrap_or_else(|| node_text(&name_node, src));
        if name.is_empty() {
            continue;
        }
        // Elixir-only: skip the call node if it's NOT a def/defp macro
        // call. The unwrap_def returned None, meaning this is an
        // ordinary runtime call like `IO.puts(x)` — indexing it as a
        // function decl is noise (and its "name" would be the callee).
        // We still want to index top-level `defmodule Foo do ... end`
        // calls as module markers, but those aren't functions, so
        // filter them here. The `node.kind() == "call"` check is
        // Elixir-specific (other grammars don't use `call` as a fn kind).
        if node.kind() == "call" && elixir_def.is_none() {
            continue;
        }

        let decl_kind = if handler.constructor_method_kinds.contains(&node.kind())
            || handler.is_constructor_method(name)
        {
            crate::DeclKind::Constructor
        } else if handler.method_kinds.contains(&node.kind())
            || has_ancestor_kind(&node, handler.method_context_kinds)
        {
            crate::DeclKind::Method
        } else {
            crate::DeclKind::Function
        };

        let body_node = elixir_def
            .as_ref()
            .and_then(|d| d.short_form_body)
            .or_else(|| node.child_by_field_name("body"))
            .or_else(|| node.child_by_field_name("block"))
            .or_else(|| first_named_child_of_kind(&node, "function_body"))
            .or_else(|| first_named_child_of_kind(&node, "block"))
            .or_else(|| first_named_child_of_kind(&node, "compound_statement"))
            .or_else(|| first_named_child_of_kind(&node, "statement_block"))
            .or_else(|| first_named_child_of_kind(&node, "method_body"))
            .or_else(|| first_named_child_of_kind(&node, "body_statement"))
            .or_else(|| first_named_child_of_kind(&node, "suite"))
            // Elixir: `def foo do ... end` → body is a `do_block` child
            // of the outer call. Erlang: `foo() -> body.` puts the body
            // inside a `clause_body` field on `function_clause`.
            .or_else(|| first_named_child_of_kind(&node, "do_block"))
            .or_else(|| first_named_child_of_kind(&node, "clause_body"))
            // Dart-style grammars put `function_body` as the next named
            // sibling of the signature rather than a child. No existing
            // adapter produces a `function_body` sibling without first
            // having a body child, so this fallback is cheap for every
            // language and essential for Dart's split signature/body
            // shape. Class methods wrap the `function_signature` in a
            // `method_signature`, so we also try the parent's next
            // sibling to reach the method's body.
            .or_else(|| {
                let sib = node.next_named_sibling();
                if let Some(s) = sib {
                    if matches!(s.kind(), "function_body" | "block" | "body_statement") {
                        return Some(s);
                    }
                }
                let parent = node.parent()?;
                let p_sib = parent.next_named_sibling()?;
                matches!(p_sib.kind(), "function_body" | "block" | "body_statement").then_some(p_sib)
            });
        let syntax_broken = file_has_syntax_errors && callable_has_syntax_error(&node, body_node.as_ref());
        let implicit_return_node = body_node.and_then(|b| implicit_return_expression_node(&b, handler));
        let body_implicit_returns = implicit_return_node.is_some();
        let mut flow_events = if let Some(b) = body_node {
            let mut events = walk_flow_events(b, file, src, handler, &class_names);
            if let Some(return_node) = implicit_return_node {
                append_expression_body_return(&mut events, &return_node, file, src);
            } else if handler.tail_expression_returns {
                append_tail_expression_return(&mut events, &b, file, src, handler);
            }
            events
        } else {
            Vec::new()
        };
        let mut pre_body_events = pre_body_call_events(&node, file, src, handler, &class_names);
        if !pre_body_events.is_empty() {
            pre_body_events.extend(flow_events);
            flow_events = pre_body_events;
        }
        // Narrow syntax-error gating: keep flows from the cleanly-parsed
        // statements, drop only the events inside a recovered error span.
        if syntax_broken {
            retain_flow_events_outside_errors(&mut flow_events, &error_spans);
        }

        // For Elixir def-macros, params live on the SIGNATURE call
        // (the first argument of the outer call), not on the outer
        // call node itself. Use the unwrapped signature node.
        let param_source = elixir_def.as_ref().map(|d| d.signature_call).unwrap_or(node);
        let params = extract_param_names(&param_source, src);
        // M1: a positional variadic collector (`*args`, `...rest`, `T...`,
        // C-family bare `...`) absorbs every overflow positional argument.
        // Flag it so `param_index_for_call_arg` routes those args onto the
        // collector instead of dropping them. Named splats are stored under
        // their bare name in `params`, so the engine cannot infer this from
        // the name alone.
        let is_variadic = parameter_list_is_variadic(&param_source)
            || params.last().is_some_and(|p| p == SYNTHETIC_VARARGS_PARAM);
        let param_annotations = extract_param_annotations(&param_source, src);
        let receiver_param_index =
            if matches!(decl_kind, crate::DeclKind::Method | crate::DeclKind::Constructor)
                || has_ancestor_kind(&node, handler.method_context_kinds)
            {
                handler
                    .method_receiver_param_index
                    .filter(|idx| *idx < params.len())
                    // Skip when the syntax proves no receiver exists:
                    // Python `@staticmethod` (decorator above the fn)
                    // and Rust associated functions whose first formal
                    // parameter is NOT a `self_parameter` grammar node.
                    .filter(|_| function_has_syntactic_receiver(&node, src))
            } else {
                None
            };
        let receiver_field_writes = collect_receiver_field_writes(
            &flow_events,
            &params,
            receiver_param_index,
            handler.implicit_receiver_names,
            handler.implicit_receiver_prefixes,
        );
        let implicit_receiver_names = if receiver_param_index.is_none()
            && (matches!(decl_kind, crate::DeclKind::Method | crate::DeclKind::Constructor)
                || has_ancestor_kind(&node, handler.method_context_kinds))
        {
            handler
                .implicit_receiver_names
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let receiver_state_sources =
            collect_receiver_state_sources(&flow_events, &params, handler.implicit_receiver_names);

        let parent_class_span = nearest_class_owner_span(&node, handler).map(|class| span_of(file, &class));
        let symbol = bonsai_common::SymbolId::new(next);
        next += 1;
        if let Some(parent_span) = parent_class_span {
            function_parent_spans.push((symbol, parent_span));
        }
        defs.push(crate::Decl {
            symbol,
            kind: decl_kind,
            name: name.to_string(),
            qualified_name: None,
            module_path: crate::ModulePath::default(),
            span: span_of(file, &node),
            name_span: span_of(file, &name_node),
            visibility: crate::Visibility::Public,
            parent: None,
            body_span: body_node.map_or_else(|| Some(span_of(file, &node)), |b| Some(span_of(file, &b))),
            flow_events,
            has_implicit_returns: handler.tail_expression_returns || body_implicit_returns,
            params,
            param_annotations,
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index,
            receiver_field_writes,
            implicit_receiver_names,
            receiver_state_sources,
            return_type: None,
            is_variadic,
        });
    }

    // Pass 2b: anonymous lambda / arrow-function / closure declarations.
    // Needed so HOF chains (`xs.forEach(x => sink(x))`, `list.map(|i|
    // ...)`) produce a decl whose body the taint engine can walk —
    // otherwise the lambda body is invisible and calls inside it
    // (`sink(x)`) never reach any analysis. Lambdas get a synthetic
    // name `<lambda@{line}:{col}>` so they're distinguishable in
    // diagnostics but never clash with a real function name.
    let lambda_nodes = collect_kinds(&tree, handler.lambda_kinds);
    for lambda in lambda_nodes {
        // Some adapters promote expression-bodied callables to normal
        // declarations because their grammar exposes enough structure
        // to name and walk them directly. Do not index the same syntax
        // again as a lambda; duplicate FuncIds split call resolution
        // from matcher attribution for a single semantic function.
        if handler.fn_kinds.contains(&lambda.kind()) {
            continue;
        }
        // Skip lambdas that are passed directly as call arguments.
        // `walk_into` inlines those bodies into the enclosing call's
        // owner via `walk_lambda_body`; emitting a second synthetic
        // decl for the same source events creates duplicate source
        // starts and duplicate findings with different chain roots.
        // Keep non-call-argument lambdas, including local or top-level
        // assignments, because their bodies are not otherwise inlined.
        if lambda_is_inlined_call_argument(&lambda, handler) {
            continue;
        }
        let span = span_of(file, &lambda);
        let binding_name = binding_name_node(&lambda);
        let name = binding_name.map_or_else(
            || {
                format!(
                    "<lambda@{}:{}>",
                    lambda.start_position().row + 1,
                    lambda.start_position().column + 1
                )
            },
            |name_node| callable_binding_name_from_text(node_text(&name_node, src)),
        );
        if name.is_empty() {
            continue;
        }
        // Params: lambdas surface them via `parameters` field, or
        // inline tokens (Rust `|x|`, Elixir `fn x ->`). Use the
        // generic param-names extractor.
        let params = extract_param_names(&lambda, src);
        // Body: `body` field, `block` child, or the lambda itself
        // as a single-expression body.
        let body_node = lambda
            .child_by_field_name("body")
            .or_else(|| lambda.child_by_field_name("block"))
            .or_else(|| first_named_child_of_kind(&lambda, "block"))
            .or_else(|| first_named_child_of_kind(&lambda, "compound_statement"))
            .or_else(|| first_named_child_of_kind(&lambda, "statement_block"))
            // Erlang `F = fun() -> Body end` (H17): the fun body nests under
            // `clause_body` (directly, or via a `fun_clause` wrapper), the
            // same field the main function-decl path handles.
            .or_else(|| first_named_child_of_kind(&lambda, "clause_body"))
            .or_else(|| {
                first_named_child_of_kind(&lambda, "fun_clause")
                    .and_then(|fc| first_named_child_of_kind(&fc, "clause_body"))
            });
        let syntax_broken = file_has_syntax_errors && callable_has_syntax_error(&lambda, body_node.as_ref());
        let implicit_return_node = body_node.and_then(|b| implicit_return_expression_node(&b, handler));
        let body_implicit_returns = implicit_return_node.is_some();
        let mut flow_events = if let Some(b) = body_node {
            let mut events = walk_flow_events(b, file, src, handler, &class_names);
            if let Some(return_node) = implicit_return_node {
                append_expression_body_return(&mut events, &return_node, file, src);
            } else if handler.tail_expression_returns {
                append_tail_expression_return(&mut events, &b, file, src, handler);
            }
            events
        } else {
            Vec::new()
        };
        if syntax_broken {
            retain_flow_events_outside_errors(&mut flow_events, &error_spans);
        }
        if params.is_empty() && flow_events.is_empty() {
            continue;
        }
        let symbol = bonsai_common::SymbolId::new(next);
        next += 1;
        defs.push(crate::Decl {
            symbol,
            kind: crate::DeclKind::Function,
            name,
            qualified_name: None,
            module_path: crate::ModulePath::default(),
            span,
            name_span: binding_name.map_or(span, |name_node| span_of(file, &name_node)),
            visibility: crate::Visibility::Public,
            parent: None,
            body_span: body_node.map(|b| span_of(file, &b)),
            flow_events,
            has_implicit_returns: handler.tail_expression_returns || body_implicit_returns,
            params,
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
    }

    // Pass 3: class declarations (recorded as Class decls so the tracer can
    // route Constructor calls through them).
    let mut class_infos: Vec<(String, bonsai_common::SymbolId, bonsai_common::Span)> = Vec::new();
    for cnode in &class_nodes {
        // For C / C++ `typedef struct { ... } UserInfo;` the
        // struct_specifier itself is anonymous — the name lives on a
        // sibling type_identifier in the enclosing type_definition. So
        // if the direct child lookup fails, walk up one level and look
        // for a type_identifier at the parent level.
        let name_node = cnode
            .child_by_field_name("name")
            .or_else(|| first_identifier_like_child(cnode))
            .or_else(|| anonymous_struct_typedef_name(cnode));
        let Some(name_node) = name_node else { continue };
        let name = node_text(&name_node, src);
        if name.is_empty() {
            continue;
        }
        let symbol = bonsai_common::SymbolId::new(next);
        next += 1;
        let class_span = span_of(file, cnode);
        class_infos.push((name.to_string(), symbol, class_span));
        defs.push(crate::Decl {
            symbol,
            kind: crate::DeclKind::Class,
            name: name.to_string(),
            qualified_name: None,
            module_path: crate::ModulePath::default(),
            span: class_span,
            name_span: span_of(file, &name_node),
            visibility: crate::Visibility::Public,
            parent: None,
            body_span: Some(span_of(file, cnode)),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
    }

    for (function_symbol, parent_span) in function_parent_spans {
        let Some((_, class_symbol, _)) = class_infos
            .iter()
            .find(|(_, _, class_span)| *class_span == parent_span)
        else {
            continue;
        };
        if let Some(decl) = defs.iter_mut().find(|decl| decl.symbol == function_symbol) {
            decl.parent = Some(*class_symbol);
        }
    }

    // Pass 4: top-level / module-scope code. PHP request handlers,
    // Python single-file scripts, Ruby Sinatra DSL apps, and Node
    // CommonJS module bodies often run code at file scope (outside any
    // fn/class), and the taint engine analyzes flow per-decl — without
    // a synthetic `__module__` decl those statements never reach the
    // engine.
    //
    // Root walks skip nested fn/class bodies, so this keeps true
    // top-level statements even when the file also declares handlers.
    // Module-scope facts only when module-scope syntax is correct: an
    // ERROR / MISSING outside every indexed decl means top-level code
    // did not parse cleanly, so the synthetic `__module__` decl emits
    // no flow events. Errors INSIDE a broken callable are already
    // handled by that callable's own gate above.
    let module_syntax_broken = error_spans.iter().any(|err| {
        !defs
            .iter()
            .any(|decl| decl.span.start <= err.start && err.end <= decl.span.end)
    });
    let mut root_events = walk_flow_events(tree.root_node(), file, src, handler, &class_names);
    if module_syntax_broken {
        // Top-level code didn't parse cleanly: keep the module-scope
        // statements outside the error spans, drop only those inside.
        retain_flow_events_outside_errors(&mut root_events, &error_spans);
    }
    let has_actionable_event = root_events.iter().any(|ev| {
        matches!(
            ev,
            crate::FlowEvent::Call { .. }
                | crate::FlowEvent::Assign { .. }
                | crate::FlowEvent::Yield { .. }
                | crate::FlowEvent::Await { .. }
        )
    });
    if has_actionable_event {
        let symbol = bonsai_common::SymbolId::new(next);
        let module_span = span_of(file, &tree.root_node());
        defs.push(crate::Decl {
            symbol,
            kind: crate::DeclKind::Function,
            name: "__module__".to_string(),
            qualified_name: None,
            module_path: crate::ModulePath::default(),
            span: module_span,
            name_span: module_span,
            visibility: crate::Visibility::Public,
            parent: None,
            body_span: Some(module_span),
            flow_events: root_events,
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        });
    }

    let mut refs = extract_call_refs(&tree, file, src);
    refs.extend(extract_decorators(&tree, file, src));
    refs.extend(extract_read_write_refs(&tree, file, src));
    let strings = extract_string_literals(&tree, file, src);
    let comments = extract_comments(&tree, file, src);
    crate::DeclIndex {
        file,
        defs,
        refs,
        strings,
        comments,
    }
}

fn callable_binding_name_from_text(text: &str) -> String {
    let trimmed = text.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if looks_like_bare_identifier(trimmed.trim_start_matches('$')) {
        return trimmed.to_string();
    }
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in trimmed.chars() {
        if ch == '$' || ch == '_' || ch.is_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
        .into_iter()
        .rev()
        .find(|token| {
            let bare = token.trim_start_matches('$');
            !bare.is_empty()
                && looks_like_bare_identifier(bare)
                && !matches!(bare, "my" | "our" | "local" | "let" | "var" | "const")
        })
        .unwrap_or_default()
}

fn pre_body_call_events(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
) -> Vec<FlowEvent> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "modifier_invocation" {
            continue;
        }
        if let Some(event) = build_call_event(child, file, src, handler, class_names) {
            out.push(event);
        }
    }
    out
}

fn has_ancestor_kind(node: &Node<'_>, kinds: &[&str]) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if kinds.contains(&parent.kind()) {
            return true;
        }
        current = parent.parent();
    }
    false
}

/// True when syntactic evidence indicates the function actually has
/// a receiver parameter, i.e. the `method_receiver_param_index`
/// declared by the handler is meaningful for this specific node.
///
/// Two negative cases are honored:
///
/// - **Rust associated functions**: if a parameter list is present
///   and its first formal parameter is NOT a `self_parameter` node,
///   the function has no receiver. `fn new(s: String)` inside
///   `impl Foo` lands here — without this check `params[0] = "s"`
///   would be misclassified as the implicit receiver.
/// - **Python `@staticmethod`**: when the function is wrapped in a
///   `decorated_definition` whose decorator list contains a
///   `staticmethod` reference, the function has no receiver.
///   Plain `@classmethod` keeps a receiver (it's `cls`).
///
/// Languages without these specific shapes (Java, Go, JS, etc.)
/// fall through to `true` so existing behavior is preserved.
fn function_has_syntactic_receiver(node: &Node<'_>, src: &[u8]) -> bool {
    // --- Rust: probe the parameter list for a `self_parameter` ---
    if let Some(params_node) = node
        .child_by_field_name("parameters")
        .or_else(|| first_named_child_of_kind(node, "parameters"))
    {
        let mut cur = params_node.walk();
        let mut saw_self = false;
        let mut saw_other_param = false;
        for child in params_node.named_children(&mut cur) {
            match child.kind() {
                "self_parameter" => saw_self = true,
                "parameter"
                | "method_parameter"
                | "formal_parameter"
                | "typed_parameter"
                | "default_parameter"
                | "typed_default_parameter"
                | "list_splat_pattern"
                | "dictionary_splat_pattern"
                | "identifier"
                | "shorthand_property_identifier_pattern"
                | "required_parameter"
                | "optional_parameter"
                | "rest_parameter" => saw_other_param = true,
                _ => {}
            }
        }
        // If the grammar exposes `self_parameter` and we didn't see
        // one, there is no receiver — even if other params exist.
        if !saw_self && saw_other_param && grammar_uses_self_parameter_kind(node) {
            return false;
        }
        if saw_self {
            return true;
        }
    }

    // --- Python: walk to a `decorated_definition` parent and look ---
    // --- for an exact `@staticmethod` / `@builtins.staticmethod`. ---
    if let Some(parent) = node.parent() {
        if parent.kind() == "decorated_definition" {
            let mut cur = parent.walk();
            for child in parent.named_children(&mut cur) {
                if child.kind() != "decorator" {
                    continue;
                }
                if decorator_is_staticmethod(&child, src) {
                    return false;
                }
            }
        }
    }

    true
}

/// True iff `decorator` is the bare `@staticmethod` decorator
/// (or one of its accepted aliases). Substring-matching the whole
/// decorator text would false-positive on
/// `@abc.abstractstaticmethod`, `@my_staticmethod_helper`,
/// `@StaticmethodWrapper`, etc., so we inspect the decorator's
/// identifier expression directly.
///
/// Accepted shapes (recurses through parens and call wrappers):
///   `@staticmethod`             → identifier
///   `@(staticmethod)`           → parenthesized_expression
///   `@staticmethod()`           → call(callee=identifier)
///   `@builtins.staticmethod`    → attribute(object=builtins, attr=staticmethod)
fn decorator_is_staticmethod(decorator: &Node<'_>, src: &[u8]) -> bool {
    let mut decorator_cursor = decorator.walk();
    let Some(decorator_expr) = decorator.named_children(&mut decorator_cursor).next() else {
        return false;
    };
    expr_is_staticmethod(&decorator_expr, src)
}

fn expr_is_staticmethod(node: &Node<'_>, src: &[u8]) -> bool {
    match node.kind() {
        "identifier" => node
            .utf8_text(src)
            .map(|t| t.trim() == "staticmethod")
            .unwrap_or(false),
        "attribute" => {
            // `attribute` is `<object>.<attribute>`. Only honor the
            // canonical `builtins.staticmethod` form so we don't
            // mis-match `@some_pkg.staticmethod` (the package's
            // arbitrary helper that happens to share the name).
            let attr_is_static = node
                .child_by_field_name("attribute")
                .and_then(|n| n.utf8_text(src).ok())
                .map(|t| t.trim() == "staticmethod")
                .unwrap_or(false);
            let object_is_builtins = node
                .child_by_field_name("object")
                .and_then(|n| n.utf8_text(src).ok())
                .map(|t| t.trim() == "builtins")
                .unwrap_or(false);
            attr_is_static && object_is_builtins
        }
        "parenthesized_expression" => {
            let mut c = node.walk();
            let inner = node.named_children(&mut c).next();
            inner.is_some_and(|n| expr_is_staticmethod(&n, src))
        }
        "call" => node
            .child_by_field_name("function")
            .is_some_and(|callee| expr_is_staticmethod(&callee, src)),
        _ => false,
    }
}

/// Heuristic: does the grammar containing `node` know about the
/// `self_parameter` kind at all? We check by looking at all named
/// descendants of the parameter list's parent for any node tagged
/// `self_parameter`. A grammar that doesn't model self-parameters
/// (Java, JS, Python, Go, etc.) will never emit one, so the absence
/// of a `self_parameter` child is not by itself proof of "no
/// receiver." Currently only Rust's tree-sitter grammar uses the
/// `self_parameter` kind.
fn grammar_uses_self_parameter_kind(node: &Node<'_>) -> bool {
    // Cheap proxy: check whether the function lives inside a
    // Rust-specific `impl_item` / `trait_item` ancestor. We
    // intentionally do NOT include `declaration_list` here — that
    // kind also exists in C/C++/Java/C#/PHP grammars and would
    // silently strip receiver-param indices from any future
    // language that sets `method_receiver_param_index = Some`.
    let mut cur = node.parent();
    while let Some(p) = cur {
        if matches!(p.kind(), "impl_item" | "trait_item") {
            return true;
        }
        cur = p.parent();
    }
    false
}

#[must_use]
pub fn collect_receiver_field_writes(
    events: &[crate::FlowEvent],
    params: &[String],
    receiver_param_index: Option<usize>,
    implicit_receiver_names: &[&str],
    implicit_receiver_prefixes: &[&str],
) -> Vec<crate::FieldWrite> {
    let param_keys: Vec<Vec<String>> = params.iter().map(|param| name_variants(param)).collect();
    let mut out = Vec::new();
    if let Some(receiver_idx) = receiver_param_index {
        if let Some(receiver_param) = params.get(receiver_idx) {
            collect_receiver_field_writes_inner(
                events,
                &[receiver_param.as_str()],
                &[],
                Some(receiver_idx),
                &param_keys,
                &mut out,
            );
        }
    }
    if !implicit_receiver_names.is_empty() || !implicit_receiver_prefixes.is_empty() {
        collect_receiver_field_writes_inner(
            events,
            implicit_receiver_names,
            implicit_receiver_prefixes,
            None,
            &param_keys,
            &mut out,
        );
    }
    out.sort_by_key(|write| (write.span.start, write.target.clone()));
    out.dedup_by(|a, b| {
        a.span == b.span && a.target == b.target && a.source_param_indices == b.source_param_indices
    });
    out
}

fn collect_receiver_field_writes_inner(
    events: &[crate::FlowEvent],
    receiver_names: &[&str],
    receiver_prefixes: &[&str],
    receiver_idx: Option<usize>,
    param_keys: &[Vec<String>],
    out: &mut Vec<crate::FieldWrite>,
) {
    for event in events {
        match event {
            crate::FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call_args,
                source_names,
                ..
            } => {
                if !place_matches_receiver(target, receiver_names, receiver_prefixes) {
                    continue;
                }
                let source_values =
                    assignment_source_values(source_name.as_ref(), source_call_args, source_names);
                let mut source_param_indices = Vec::new();
                for (idx, variants) in param_keys.iter().enumerate() {
                    if receiver_idx == Some(idx) {
                        continue;
                    }
                    if source_values
                        .iter()
                        .any(|source| variants.iter().any(|variant| source == variant))
                    {
                        source_param_indices.push(idx);
                    }
                }
                if !source_param_indices.is_empty() {
                    out.push(crate::FieldWrite {
                        span: *span,
                        target: target.clone(),
                        source_param_indices,
                    });
                }
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_receiver_field_writes_inner(
                    then_events,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
                collect_receiver_field_writes_inner(
                    else_events,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => {
                collect_receiver_field_writes_inner(
                    body,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
            }
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_receiver_field_writes_inner(
                    body,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
                collect_receiver_field_writes_inner(
                    catch_events,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
                collect_receiver_field_writes_inner(
                    finally_events,
                    receiver_names,
                    receiver_prefixes,
                    receiver_idx,
                    param_keys,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn place_matches_receiver(place: &str, receiver_names: &[&str], receiver_prefixes: &[&str]) -> bool {
    let trimmed = place.trim_start();
    receiver_names
        .iter()
        .any(|receiver| place_base_matches(place, receiver))
        || receiver_prefixes.iter().any(|prefix| trimmed.starts_with(prefix))
}

fn collect_receiver_state_sources(
    events: &[crate::FlowEvent],
    params: &[String],
    implicit_receiver_names: &[&str],
) -> Vec<String> {
    if implicit_receiver_names.is_empty() {
        return Vec::new();
    }
    let mut locals: std::collections::HashSet<String> = params.iter().cloned().collect();
    collect_assign_targets(events, &mut locals);
    let mut out: std::collections::BTreeSet<String> = implicit_receiver_names
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    collect_receiver_state_sources_inner(events, &locals, implicit_receiver_names, &mut out);
    out.into_iter().collect()
}

pub fn collect_assign_targets<S: std::hash::BuildHasher>(
    events: &[crate::FlowEvent],
    out: &mut std::collections::HashSet<String, S>,
) {
    for event in events {
        match event {
            crate::FlowEvent::Assign { target, .. } if !target.is_empty() => {
                out.insert(target.trim().to_string());
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assign_targets(then_events, out);
                collect_assign_targets(else_events, out);
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => collect_assign_targets(body, out),
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assign_targets(body, out);
                collect_assign_targets(catch_events, out);
                collect_assign_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

pub struct ImplicitMemberReadCall {
    pub source_call: String,
    pub call_name: String,
    pub receiver: Option<String>,
    pub call_kind: crate::CallKind,
}

pub fn rewrite_implicit_member_reads<F, SG, SL>(
    events: &mut Vec<crate::FlowEvent>,
    getters: &std::collections::HashSet<String, SG>,
    locals: &std::collections::HashSet<String, SL>,
    call_for_name: F,
) where
    F: Fn(&str) -> ImplicitMemberReadCall + Copy,
    SG: std::hash::BuildHasher,
    SL: std::hash::BuildHasher,
{
    for event in events.iter_mut() {
        match event {
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_implicit_member_reads(then_events, getters, locals, call_for_name);
                rewrite_implicit_member_reads(else_events, getters, locals, call_for_name);
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => {
                rewrite_implicit_member_reads(body, getters, locals, call_for_name);
            }
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_implicit_member_reads(body, getters, locals, call_for_name);
                rewrite_implicit_member_reads(catch_events, getters, locals, call_for_name);
                rewrite_implicit_member_reads(finally_events, getters, locals, call_for_name);
            }
            _ => {}
        }
    }

    let mut idx = 0usize;
    while idx < events.len() {
        let (qualify_name, span) = match &events[idx] {
            crate::FlowEvent::Assign {
                target,
                source_name,
                source_call,
                span,
                ..
            } => {
                if source_call.is_some() {
                    (None, *span)
                } else if let Some(name) = source_name.as_deref().map(str::trim).map(str::to_string) {
                    if getters.contains(&name) && !locals.contains(&name) && name != target.trim() {
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
        let call = call_for_name(&name);
        if let crate::FlowEvent::Assign {
            source_name,
            source_call,
            source_call_args,
            source_names,
            value_kind,
            ..
        } = &mut events[idx]
        {
            *source_call = Some(call.source_call.clone());
            *source_call_args = Vec::new();
            *source_name = None;
            source_names.retain(|s| {
                let trimmed = s.trim();
                trimmed != name && trimmed != call.source_call
            });
            *value_kind = Some(crate::AssignValueKind::CallResult);
        }
        events.insert(
            idx,
            crate::FlowEvent::Call {
                span,
                name: call.call_name,
                receiver: call.receiver,
                receiver_types: Vec::new(),
                call_kind: call.call_kind,
                args: Vec::new(),
            },
        );
        idx += 2;
    }
}

fn collect_receiver_state_sources_inner(
    events: &[crate::FlowEvent],
    locals: &std::collections::HashSet<String>,
    implicit_receiver_names: &[&str],
    out: &mut std::collections::BTreeSet<String>,
) {
    for event in events {
        match event {
            crate::FlowEvent::Assign {
                source_name,
                source_names,
                ..
            } => {
                if let Some(source) = source_name {
                    collect_receiver_state_source_name(source, locals, implicit_receiver_names, out);
                }
                for source in source_names {
                    collect_receiver_state_source_name(source, locals, implicit_receiver_names, out);
                }
            }
            crate::FlowEvent::Call { receiver, .. } => {
                if let Some(receiver) = receiver {
                    if implicit_receiver_names
                        .iter()
                        .any(|name| place_base_matches(receiver, name))
                    {
                        out.insert(receiver.clone());
                    }
                }
                if let crate::FlowEvent::Call { args, .. } = event {
                    for arg in args {
                        collect_receiver_state_source_name(
                            &arg.value_text,
                            locals,
                            implicit_receiver_names,
                            out,
                        );
                    }
                }
            }
            crate::FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                if let Some(value) = value_name.as_ref().or(value_text.as_ref()) {
                    collect_receiver_state_source_name(value, locals, implicit_receiver_names, out);
                }
            }
            crate::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_receiver_state_sources_inner(then_events, locals, implicit_receiver_names, out);
                collect_receiver_state_sources_inner(else_events, locals, implicit_receiver_names, out);
            }
            crate::FlowEvent::Loop { body, .. }
            | crate::FlowEvent::Defer { body, .. }
            | crate::FlowEvent::Using { body, .. } => {
                collect_receiver_state_sources_inner(body, locals, implicit_receiver_names, out);
            }
            crate::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_receiver_state_sources_inner(body, locals, implicit_receiver_names, out);
                collect_receiver_state_sources_inner(catch_events, locals, implicit_receiver_names, out);
                collect_receiver_state_sources_inner(finally_events, locals, implicit_receiver_names, out);
            }
            _ => {}
        }
    }
}

fn collect_receiver_state_source_name(
    source: &str,
    locals: &std::collections::HashSet<String>,
    implicit_receiver_names: &[&str],
    out: &mut std::collections::BTreeSet<String>,
) {
    let source = source.trim();
    if source.is_empty() || locals.contains(source) {
        return;
    }
    let base_is_local = normalised_place_base(source).is_some_and(|base| locals.contains(&base));
    if implicit_receiver_names
        .iter()
        .any(|name| place_base_matches(source, name))
        || !source.contains('.')
        || !base_is_local
    {
        out.insert(source.to_string());
    }
}

pub(crate) fn argument_place(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let text = normalize_call_name_whitespace(node_text(node, src));
    if !text.is_empty() && argument_node_is_place(node, text.as_str()) && qualified_place_text(&text) {
        return Some(normalise_qualified_text(&text));
    }
    if let Some(value) = node.child_by_field_name("value") {
        let text = normalize_call_name_whitespace(node_text(&value, src));
        if !text.is_empty() && argument_node_is_place(&value, text.as_str()) {
            return Some(normalise_qualified_text(&text));
        }
    }
    if text.is_empty() || !argument_node_is_place(node, text.as_str()) {
        return None;
    }
    Some(normalise_qualified_text(&text))
}

fn qualified_place_text(text: &str) -> bool {
    text.contains('.') || text.contains("->") || text.contains('[')
}

fn argument_node_is_place(node: &Node<'_>, text: &str) -> bool {
    if looks_like_bare_identifier(text) {
        return true;
    }
    if matches!(
        node.kind(),
        "identifier"
            | "field_identifier"
            | "member_expression"
            | "member_access_expression"
            | "navigation_expression"
            | "attribute"
            | "dot_index_expression"
            | "subscript_expression"
            | "subscript"
            | "element_reference"
            | "array_access"
            | "element_access_expression"
            | "bracket_index_expression"
            | "index_expression"
            | "indexing_expression"
            | "pointer_expression"
            | "unary_expression"
            | "field_expression"
            | "selector_expression"
            | "assignable_selector"
            | "unconditional_assignable_selector"
    ) {
        return true;
    }
    text.trim_start().starts_with(['&', '*'])
}

fn assignment_source_values(
    source_name: Option<&String>,
    source_call_args: &[String],
    source_names: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(source_name) = source_name {
        out.extend(name_variants(source_name));
    }
    for source in source_call_args.iter().chain(source_names.iter()) {
        out.extend(name_variants(source));
    }
    out.sort();
    out.dedup();
    out
}

fn name_variants(name: &str) -> Vec<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let stripped = trimmed.trim_start_matches(['$', '@', '&']);
    if stripped == trimmed || stripped.is_empty() {
        vec![trimmed.to_string()]
    } else {
        vec![trimmed.to_string(), stripped.to_string()]
    }
}

fn place_base_matches(place: &str, expected_base: &str) -> bool {
    let Some(base) = normalised_place_base(place) else {
        return false;
    };
    name_variants(expected_base)
        .iter()
        .any(|candidate| candidate == &base)
}

fn normalised_place_base(place: &str) -> Option<String> {
    let place = place.trim();
    if place.is_empty() {
        return None;
    }
    let normalised = normalise_qualified_text(&place.replace("->", "."));
    let base = normalised
        .split('.')
        .next()
        .map(str::trim)
        .filter(|base| !base.is_empty())?;
    Some(base.to_string())
}

fn call_receiver_from_name(name: &str) -> Option<String> {
    if let Some(receiver) = rust_value_receiver_from_scoped_name(name) {
        return Some(receiver);
    }
    let normalised = normalise_qualified_text(&name.replace("->", "."));
    let (receiver, _) = normalised.rsplit_once('.')?;
    let receiver = receiver.trim();
    (!receiver.is_empty()).then(|| receiver.to_string())
}

fn rust_value_receiver_from_scoped_name(name: &str) -> Option<String> {
    let (head, tail) = name.split_once("::")?;
    if tail.contains("::") {
        return None;
    }
    let head = head.trim();
    let tail = tail.trim();
    if head.is_empty() || tail.is_empty() {
        return None;
    }
    let mut chars = head.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_lowercase()) {
        return None;
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    let mut tail_chars = tail.chars();
    let tail_first = tail_chars.next()?;
    if !(tail_first == '_' || tail_first.is_ascii_lowercase()) {
        return None;
    }
    if !tail_chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(head.to_string())
}

/// One row in a language's lifecycle-transition table.
/// `call_match` is the callee name (bare tail or fully qualified);
/// `transition` is the canonical state (`freed`, `closed`,
/// `unlocked`, `cancelled`, `moved`); `arg_index` selects which
/// positional arg names the binding (used for `free(p)` shapes;
/// receiver-style calls preferentially use the receiver).
#[derive(Clone, Copy, Debug)]
pub struct LifecycleTransition {
    pub call_match: &'static str,
    pub transition: &'static str,
    pub arg_index: usize,
}

/// Append a `FlowEvent::Lifecycle` after every recognised
/// transition call in `events`. Conservative: emits only when the
/// binding reduces to a bare identifier (after stripping `&` / `*`
/// and folding `obj.fd` → `fd`).
pub fn inject_lifecycle_events(events: &mut Vec<crate::FlowEvent>, transitions: &[LifecycleTransition]) {
    use crate::FlowEvent;
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_lifecycle_events(then_events, transitions);
                inject_lifecycle_events(else_events, transitions);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_lifecycle_events(body, transitions);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_lifecycle_events(body, transitions);
                inject_lifecycle_events(catch_events, transitions);
                inject_lifecycle_events(finally_events, transitions);
            }
            _ => {}
        }
    }
    let mut inserts: Vec<(usize, FlowEvent)> = Vec::new();
    for (idx, event) in events.iter().enumerate() {
        let FlowEvent::Call {
            span,
            name,
            receiver,
            args,
            ..
        } = event
        else {
            continue;
        };
        for row in transitions {
            if !lifecycle_call_matches(name, row.call_match) {
                continue;
            }
            // Bare row keys (`close`) target method-style calls —
            // the binding is the receiver. Dotted row keys
            // (`:gen_server.stop`, `os.close`) target namespaced
            // free functions — the binding is the indexed arg.
            // The dotted-name fallback only fires for adapters
            // that fold receiver and method into the call name
            // and emit no args.
            let row_is_dotted = row.call_match.contains(['.', ':', '>']);
            let raw = if !row_is_dotted {
                if let Some(rx) = receiver.as_deref() {
                    rx.trim().to_string()
                } else if let Some(arg) = args.get(row.arg_index) {
                    arg.value_text.trim().to_string()
                } else if let Some((head, _)) = name.rsplit_once(['.', ':', '>']) {
                    head.trim().to_string()
                } else {
                    continue;
                }
            } else if let Some(arg) = args.get(row.arg_index) {
                arg.value_text.trim().to_string()
            } else {
                continue;
            };
            let bare = lifecycle_binding_name(&raw);
            if bare.is_empty() {
                continue;
            }
            inserts.push((
                idx + 1,
                FlowEvent::Lifecycle {
                    span: *span,
                    name: bare,
                    transition: row.transition.to_string(),
                },
            ));
            break;
        }
    }
    for (at, ev) in inserts.into_iter().rev() {
        events.insert(at, ev);
    }
}

/// Bare row keys (`close`) match the call's trailing segment;
/// dotted keys (`os.close`, `std::move`) require an exact match.
fn lifecycle_call_matches(call_name: &str, row_match: &str) -> bool {
    let call = call_name.trim();
    if call == row_match {
        return true;
    }
    if row_match.contains(['.', ':', '>']) {
        return false;
    }
    let tail = call.rsplit_once(['.', ':', '>']).map(|(_, t)| t).unwrap_or(call);
    tail == row_match
}

/// Bare-identifier binding name for the lifecycle lattice.
/// Strips `&` / `*` (C address-of/deref), `$` / `@` / `%`
/// (PHP/Perl sigils), and folds `obj.fd` → `fd`.
fn lifecycle_binding_name(raw: &str) -> String {
    let trimmed = raw.trim_start_matches(['&', '*', '$', '@', '%']).trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let tail = trimmed
        .rsplit_once(['.', ':', '>'])
        .map(|(_, t)| t)
        .unwrap_or(trimmed)
        .trim();
    if tail.is_empty() {
        return String::new();
    }
    if !tail
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return String::new();
    }
    if !tail.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return String::new();
    }
    tail.to_string()
}

/// Scan the tree for decorator / annotation nodes across common grammars.
/// Returns one [`crate::Ref`] per decorator usage (not per definition); the
/// `name` is the decorator's identifier (e.g. `audited` for `@audited`,
/// `Deprecated` for `@Deprecated`). `kind` is always
/// [`crate::RefKind::Decorator`].
pub fn extract_decorators(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::Ref> {
    const DECORATOR_KINDS: &[&str] = &[
        "decorator",
        "annotation",
        "marker_annotation",
        "normal_annotation",
        "single_element_annotation",
        "attribute",
        "attribute_item",
        "attribute_list",
        "property_modifier",
    ];
    let mut out = Vec::new();
    for node in collect_kinds(tree, DECORATOR_KINDS) {
        // Prefer a named-field lookup for the decorator's target name.
        let name_node = node
            .child_by_field_name("name")
            .or_else(|| first_identifier_like_child(&node))
            .or_else(|| first_identifier_descendant(node));
        let Some(name_node) = name_node else { continue };
        let name = node_text(&name_node, src)
            .trim_start_matches('@')
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        out.push(crate::Ref {
            span: span_of(file, &node),
            name,
            kind: crate::RefKind::Decorator,
            scope: None,
            resolved: None,
        });
    }
    out
}

/// Scan the tree for import-like statements across common grammars. The
/// text slice from the node (minus the leading keyword) becomes the
/// `module` string — good enough for reporting and for module-name
/// matching, not precise enough for real resolver use.
pub fn extract_generic_imports(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::ImportSpec> {
    const IMPORT_KINDS: &[&str] = &[
        "import_statement",
        "import_from_statement",
        "import_declaration",
        "import_directive",
        // Kotlin surfaces `import x.y.z` as an `import_header` inside an
        // `import_list`.
        "import_header",
        "preproc_include",
        "use_declaration",
        "use_list",
        "using_directive",
        // C++ `using namespace X;` is a using_declaration node.
        "using_declaration",
        "package_clause",
        "namespace_import",
        "namespace_use_declaration",
        // Perl's `use strict;` form.
        "use_statement",
        // Ruby's `require "x"` is a call-expression, not a dedicated node,
        // so we skip it here — the Ruby test covers it via `refs`.
    ];
    let nodes = collect_kinds(tree, IMPORT_KINDS);
    let mut out = Vec::new();
    for node in nodes {
        let text = node_text(&node, src).trim();
        let stripped = text
            .strip_prefix("import ")
            .or_else(|| text.strip_prefix("use "))
            .or_else(|| text.strip_prefix("#include "))
            .or_else(|| text.strip_prefix("using "))
            .or_else(|| text.strip_prefix("require "))
            .unwrap_or(text)
            .trim_end_matches(';')
            .trim();
        // Handle `from X import Y [as Z]` (Python). The logical module is X;
        // we do NOT split out Y into a separate entry — the file_index refs
        // cover per-symbol lookups and the import entry just points at X.
        // `from_original` records the Y part when an alias renames it
        // (Python `from x import y as z` → original="y", alias="z") so
        // the caller-map can add an edge under the original symbol name.
        let mut from_original: Option<String> = None;
        let (module_raw, from_alias): (String, Option<String>) =
            if let Some(rest) = text.strip_prefix("from ") {
                let rest = rest.trim_end_matches(';').trim();
                if let Some((module, imports)) = rest.split_once(" import ") {
                    let imports_trim = imports.trim();
                    // `from x import y as z` — pick the trailing alias and
                    // also remember the `y` piece that the alias rebinds.
                    let alias = imports_trim.rsplit_once(" as ").map(|(orig, a)| {
                        let orig_name = orig
                            .rsplit(',')
                            .next()
                            .unwrap_or(orig)
                            .trim()
                            .trim_matches('(')
                            .trim()
                            .to_string();
                        if !orig_name.is_empty() {
                            from_original = Some(orig_name);
                        }
                        a.trim().to_string()
                    });
                    (module.trim().to_string(), alias)
                } else {
                    (rest.to_string(), None)
                }
            } else if let Some((_before, tail)) = stripped.rsplit_once(" from ") {
                // JS / TS: `import <binding> from "mod"` or
                // `import { a, b } from "mod"` or
                // `import * as alias from "mod"`. Take the quoted module path
                // after the trailing `from`, strip quotes.
                let module = tail
                    .trim()
                    .trim_matches(|c: char| c == '"' || c == '\'')
                    .to_string();
                (module, None)
            } else {
                (stripped.to_string(), None)
            };
        if module_raw.is_empty() {
            continue;
        }
        let module_raw_s: &str = module_raw.as_str();
        // Parse trailing alias forms:
        //   Rust:   `std::fs as f`               → original = `fs`
        //   Kotlin: `kotlin.io.println as p`      → original = `println`
        //   PHP:    `App\Service as S`            → original = `Service`
        //   Scala 2/3: `x.{a => b}`               → original = `a`
        //   JS / TS: `import { a as b } from "x"` → original = `a`
        //   JS / TS: `import * as fs from "fs"`    → module alias (no symbol)
        //   Go:      `f "fmt"` where `f` is the alias preceding the path
        //                                           → module alias
        let mut original_name: Option<String> = from_original.clone();
        let (module_body, alias) = if let Some((alias, scala_orig)) = scala_brace_alias_pair(module_raw_s) {
            if original_name.is_none() {
                original_name = Some(scala_orig);
            }
            (module_raw.clone(), Some(alias))
        } else if let Some((alias, js_orig)) = js_named_rename_alias(text) {
            if original_name.is_none() {
                original_name = Some(js_orig);
            }
            (module_raw.clone(), Some(alias))
        } else if let Some(js_ns_alias) = js_namespace_alias(text) {
            // `import * as fs from "fs"` — namespace alias, no symbol.
            (module_raw.clone(), Some(js_ns_alias))
        } else if let Some((head, tail)) = module_raw_s.rsplit_once(" as ") {
            // Trailing `X as Y` on the module path. Original = last path
            // segment of head (`std::fs as f` → `fs`,
            // `kotlin.io.println as p` → `println`,
            // `App\Service as S` → `Service`).
            let head_trim = head.trim();
            if original_name.is_none() {
                let seg = head_trim
                    .rsplit_once("::")
                    .map(|(_, s)| s)
                    .or_else(|| head_trim.rsplit_once('.').map(|(_, s)| s))
                    .or_else(|| head_trim.rsplit_once('\\').map(|(_, s)| s))
                    .map(str::trim)
                    .unwrap_or(head_trim);
                if !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    original_name = Some(seg.to_string());
                }
            }
            (head_trim.to_string(), Some(tail.trim().to_string()))
        } else if let Some(from_alias) = from_alias {
            (module_raw.clone(), Some(from_alias))
        } else {
            // Go alias form: `alias "path"` where the alias is a bareword
            // preceding a quoted import path (module alias, no symbol).
            if let Some(quote_idx) = module_raw_s.find('"') {
                let before = module_raw_s[..quote_idx].trim();
                if !before.is_empty()
                    && before
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                    && before != "_"
                {
                    let path_tail = module_raw_s[quote_idx..].trim().trim_matches('"').to_string();
                    (path_tail, Some(before.to_string()))
                } else {
                    (module_raw.clone(), None)
                }
            } else {
                (module_raw.clone(), None)
            }
        };
        // Wildcard detection — covers:
        //   Python  `from x import *`
        //   Java    `import x.*;`
        //   Kotlin  `import x.*`
        //   Rust    `use x::*;`
        //   Scala   `import x._` / `x.*`
        //   PHP     `use X\{A, B};` (braced list — not wildcard, just star)
        let is_wildcard = module_body.ends_with('*')
            || module_body.ends_with("._")
            || module_body.ends_with("::*")
            || from_alias_wildcard_hint(text);
        out.push(crate::ImportSpec {
            span: span_of(file, &node),
            module: module_body,
            alias,
            is_wildcard,
            original_name,
            scope: ImportScope::Module,
        });
    }
    // Post-pass: some languages surface imports as call expressions
    // rather than dedicated statement nodes:
    //   * JavaScript / CommonJS:  `const x = require("mod")`
    //   * Ruby:                   `require "mod"` / `require_relative "./mod"`
    //   * PHP:                    `require "file.php"` / `include "file.php"`
    // Tree-sitter emits these as `call_expression` / `call` nodes whose
    // function name is `require` / `require_relative` / `include` /
    // `include_once` / `require_once`. Walk them out and synthesize
    // ImportSpec entries so the `imports` browse command and alias
    // resolution see them.
    out.extend(scan_call_based_imports(tree, file, src));
    out
}

/// Scan the tree for `require(...)` / `require_relative(...)` /
/// `include(...)` call expressions and synthesize ImportSpec entries.
/// Targets JavaScript (`const x = require("y")`), Ruby (`require 'y'`),
/// and PHP (`require 'y';` / `include 'y';`). These don't surface as
/// dedicated import statement nodes in their Tree-sitter grammars.
fn scan_call_based_imports(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::ImportSpec> {
    const CALL_KINDS: &[&str] = &["call_expression", "call", "function_call_expression"];
    const IMPORT_FN_NAMES: &[&str] = &[
        "require",
        "require_relative",
        "require_once",
        "include",
        "include_once",
    ];
    let mut out: Vec<crate::ImportSpec> = Vec::new();
    let mut seen_spans: ahash::AHashSet<(u64, u64)> = ahash::AHashSet::new();
    for node in collect_kinds(tree, CALL_KINDS) {
        // Look for the function name — either child_by_field_name("function")
        // (JS) or the first identifier descendant (Ruby / PHP call).
        let fn_node = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("method"))
            .or_else(|| first_identifier_descendant(node));
        let Some(fn_node) = fn_node else { continue };
        let fn_name = node_text(&fn_node, src);
        if !IMPORT_FN_NAMES.contains(&fn_name) {
            continue;
        }
        // The FIRST argument must itself be a string literal. This
        // distinguishes Ruby/JS/PHP `require("path")` (string first
        // arg = the module path) from Solidity's
        // `require(cond, "msg")` (boolean first arg, string in
        // position 2 is an assertion message, not an import). Without
        // this guard, Solidity assertion messages get mis-classified
        // as imports.
        let args_node = node.child_by_field_name("arguments").unwrap_or(node);
        let mut arg_cursor = args_node.walk();
        let first_arg = args_node
            .named_children(&mut arg_cursor)
            .find(|c| !matches!(c.kind(), "comment" | "line_comment" | "block_comment"));
        let Some(first_arg) = first_arg else { continue };
        let Some(module) = find_string_literal_text(first_arg, src) else {
            continue;
        };
        let module_clean = module
            .trim()
            .trim_matches(|c: char| c == '"' || c == '\'' || c == '`')
            .to_string();
        if module_clean.is_empty() {
            continue;
        }
        // Dedupe: JS's `const x = require("y")` can surface the same
        // call node twice if captured by multiple kinds.
        let span = span_of(file, &node);
        let key = (span.start, span.end);
        if !seen_spans.insert(key) {
            continue;
        }
        let declarator = node.parent().filter(|p| p.kind() == "variable_declarator");
        let name_node = declarator.and_then(|vd| vd.child_by_field_name("name"));
        let simple_alias = name_node
            .filter(|n| n.kind() == "identifier")
            .map(|n| node_text(&n, src).to_string());
        let mut rename_entries: Vec<(String, String)> = Vec::new();
        let mut shorthand_entries: Vec<String> = Vec::new();
        if let Some(obj) = name_node.filter(|n| n.kind() == "object_pattern") {
            let mut cur = obj.walk();
            for child in obj.named_children(&mut cur) {
                match child.kind() {
                    "pair_pattern" => {
                        let key = child.child_by_field_name("key");
                        let value = child.child_by_field_name("value");
                        if let (Some(k), Some(v)) = (key, value) {
                            let orig = node_text(&k, src).to_string();
                            let local = node_text(&v, src).to_string();
                            if !orig.is_empty() && !local.is_empty() && orig != local {
                                rename_entries.push((orig, local));
                            }
                        }
                    }
                    "shorthand_property_identifier_pattern" => {
                        let name = node_text(&child, src).to_string();
                        if !name.is_empty() {
                            shorthand_entries.push(name);
                        }
                    }
                    "object_assignment_pattern" => {
                        if let Some(left) = child.child_by_field_name("left") {
                            let name = node_text(&left, src).to_string();
                            if !name.is_empty() {
                                shorthand_entries.push(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        out.push(crate::ImportSpec {
            span,
            module: module_clean,
            alias: simple_alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        let module_for_bindings = out.last().map(|spec| spec.module.clone()).unwrap_or_default();
        for (orig, local) in rename_entries {
            out.push(crate::ImportSpec {
                span,
                module: module_for_bindings.clone(),
                alias: Some(local),
                is_wildcard: false,
                original_name: Some(orig),
                scope: ImportScope::Module,
            });
        }
        for name in shorthand_entries {
            out.push(crate::ImportSpec {
                span,
                module: module_for_bindings.clone(),
                alias: Some(name.clone()),
                is_wildcard: false,
                original_name: Some(name),
                scope: ImportScope::Local,
            });
        }
    }
    out
}

fn find_string_literal_text<'a>(node: tree_sitter::Node<'_>, src: &'a [u8]) -> Option<String> {
    // Pre-order DFS for the first string-like descendant.
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        let kind = n.kind();
        if kind == "string"
            || kind == "string_literal"
            || kind == "raw_string_literal"
            || kind == "template_string"
            || kind.ends_with("_string")
        {
            let text = std::str::from_utf8(&src[n.byte_range()]).ok()?;
            return Some(text.to_string());
        }
        let mut cursor = n.walk();
        let children: Vec<tree_sitter::Node<'_>> = n.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    None
}

/// Quick check: `from x import *` surfaces a wildcard flag even though the
/// module text itself doesn't carry the star.
fn from_alias_wildcard_hint(text: &str) -> bool {
    text.contains(" import *") || text.contains("import . \"")
}

/// Scala rename imports use `{orig => alias}` inside the import path.
/// Returns the rightmost alias when the pattern is detected.
/// Scala 2/3 rename imports `import x.{a => b}`. Returns `(alias, original)`.
fn scala_brace_alias_pair(module_raw: &str) -> Option<(String, String)> {
    let open = module_raw.rfind('{')?;
    let close = module_raw[open..].find('}')? + open;
    let body = &module_raw[open + 1..close];
    let (orig, alias) = body.rsplit(',').next()?.split_once("=>")?;
    let alias = alias.trim().to_string();
    let orig = orig.trim().to_string();
    if alias.is_empty() || orig.is_empty() {
        None
    } else {
        Some((alias, orig))
    }
}

/// JS / TS `import * as alias from "mod"` — namespace alias. Returns
/// just the alias; no individual-symbol pair applies (the alias rebinds
/// the whole module, and downstream calls like `alias.foo()` short-tail
/// to `foo` automatically).
fn js_namespace_alias(text: &str) -> Option<String> {
    let rest = text.find("* as ").map(|i| &text[i + 5..])?;
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',' || c == '}')
        .unwrap_or(rest.len());
    let alias = rest[..end].trim();
    if alias.is_empty() {
        None
    } else {
        Some(alias.to_string())
    }
}

/// JS / TS named-rename form `import { a as b } from "mod"` — returns
/// `(alias, original)` for the rightmost rename.
fn js_named_rename_alias(text: &str) -> Option<(String, String)> {
    let open = text.find('{')?;
    let close = text[open..].find('}')? + open;
    let body = &text[open + 1..close];
    let (orig, alias) = body.rsplit(',').find_map(|piece| piece.split_once(" as "))?;
    let alias = alias.trim().to_string();
    let orig = orig.trim().to_string();
    if alias.is_empty() || orig.is_empty() {
        None
    } else {
        Some((alias, orig))
    }
}

/// Collect every string / char literal in the tree with a rough content
/// classification. Used for the CLI `strings` browse command.
pub fn extract_string_literals(
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
) -> Vec<crate::StringLiteral> {
    const STRING_KINDS: &[&str] = &[
        "string",
        "string_literal",
        "interpreted_string_literal",
        "raw_string_literal",
        "heredoc",
        "heredoc_body",
        "string_content",
        "template_string",
        "string_fragment",
        "char_literal",
        "character_literal",
        // Swift string variants.
        "line_string_literal",
        "multi_line_string_literal",
        // Scala interpolated strings: `s"..."`, `f"..."`, raw/etc.
        // Tree-sitter-scala emits `interpolated_string_expression`
        // wrapping a `string` literal. We also recognize the
        // dedicated `interpolated_string_expression` so the outer
        // node's text (which still contains the meaningful literal
        // portion plus interpolation parts) is captured.
        "interpolated_string_expression",
        "interpolated_string_literal",
        // Rust `format!("...")` / `concat!("...")` style — the macro
        // arguments contain regular string_literal nodes which are
        // already covered above; noted here for future grammar-
        // specific variants.
    ];
    let mut out = Vec::new();
    let mut cursor = tree.walk();
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if STRING_KINDS.contains(&node.kind()) {
            let text = node_text(&node, src).to_string();
            if !text.is_empty() && text.len() < 4096 {
                out.push(crate::StringLiteral {
                    span: span_of(file, &node),
                    category: crate::StringCategory::classify(&text),
                    text,
                });
                continue;
            }
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Collect every comment node in the tree, classifying each by its
/// stripped body. Tree-sitter grammars surface comments as one of a
/// small set of node kinds (`comment`, `line_comment`, `block_comment`,
/// Python's `comment`, Ruby's `comment`, Erlang's `comment`, etc.).
/// We accept the union so every supported grammar contributes.
///
/// Doc-comments are detected by grammar-native kinds where available
/// (`doc_comment`, `documentation_comment`, `outer_doc_comment_marker`)
/// and by marker-sniffing (`///`, `/**`, `#'`, `"""..."""` docstrings)
/// as a fallback.
pub fn extract_comments(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::Comment> {
    // Every tree-sitter grammar in the pack emits comments as one of
    // these node kinds. Union is language-agnostic; the adapter
    // doesn't need to opt in.
    const COMMENT_KINDS: &[&str] = &[
        "comment",
        "line_comment",
        "block_comment",
        "shebang",
        "hash_bang_line",
        // Rust grammar distinguishes these.
        "doc_comment",
        "inner_doc_comment_marker",
        "outer_doc_comment_marker",
        // Kotlin / Swift doc comment variants.
        "documentation_comment",
        "multiline_comment",
        // Dart / JS dedicated doc variants.
        "dartdoc_comment",
        "jsdoc_comment",
        // Python docstring — tree-sitter-python surfaces it as a
        // string inside an expression_statement, handled separately
        // below so we don't double-count regular strings.
    ];
    let mut out = Vec::new();
    let mut cursor = tree.walk();
    let root = tree.root_node();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if COMMENT_KINDS.contains(&node.kind()) {
            let text = node_text(&node, src).trim().to_string();
            if !text.is_empty() && text.len() < 4096 {
                let body = strip_comment_markers(&text);
                let is_doc = is_doc_comment_kind_or_text(node.kind(), &text);
                out.push(crate::Comment {
                    span: span_of(file, &node),
                    kind: crate::CommentKind::classify(&body, is_doc),
                    text,
                });
                continue;
            }
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    // Python docstring convention: the first statement of a
    // function / class / module body is a bare string expression.
    // Tree-sitter surfaces it as `expression_statement > string`;
    // treat those as Doc comments so `comments --kind doc` finds
    // them alongside `///` / `/** */` docs in other grammars.
    collect_python_docstrings(tree, src, file, &mut out);
    out
}

/// Strip the syntactic comment markers from a raw comment slice so
/// the classifier sees just the content. Handles `//`, `#`, `--`,
/// `%`, `;`, `/* ... */`, `"""..."""`, `'''...'''`.
fn strip_comment_markers(text: &str) -> String {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix("///") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("//!") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("//") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("#!") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix('#') {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("--") {
        return rest.trim().to_string();
    }
    if let Some(rest) = t.strip_prefix('%') {
        return rest.trim().to_string();
    }
    if t.starts_with("/**") {
        return t
            .trim_start_matches("/**")
            .trim_end_matches("*/")
            .lines()
            .map(|l| l.trim().trim_start_matches('*').trim())
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string();
    }
    if t.starts_with("/*") {
        return t
            .trim_start_matches("/*")
            .trim_end_matches("*/")
            .trim()
            .to_string();
    }
    if t.starts_with("\"\"\"") {
        return t.trim_matches('"').trim().to_string();
    }
    if t.starts_with("'''") {
        return t.trim_matches('\'').trim().to_string();
    }
    t.to_string()
}

fn is_doc_comment_kind_or_text(kind: &str, text: &str) -> bool {
    matches!(
        kind,
        "doc_comment"
            | "documentation_comment"
            | "dartdoc_comment"
            | "jsdoc_comment"
            | "outer_doc_comment_marker"
            | "inner_doc_comment_marker"
    ) || text.starts_with("///")
        || text.starts_with("//!")
        || text.starts_with("/**")
        || text.starts_with("#'")
}

fn collect_python_docstrings(
    tree: &tree_sitter::Tree,
    src: &[u8],
    file: FileId,
    out: &mut Vec<crate::Comment>,
) {
    // Python tree-sitter: function_definition / class_definition /
    // module have a `body` field whose first named child may be an
    // `expression_statement` whose first child is a `string`.
    let mut cursor = tree.walk();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let is_scope = matches!(
            node.kind(),
            "module" | "function_definition" | "class_definition" | "async_function_definition"
        );
        if is_scope {
            let body = node
                .child_by_field_name("body")
                .or_else(|| first_named_child_of_kind(&node, "block"))
                .unwrap_or(node);
            if let Some(first) = body.named_children(&mut body.walk()).next() {
                let target = if first.kind() == "expression_statement" {
                    first.named_children(&mut first.walk()).next().unwrap_or(first)
                } else {
                    first
                };
                if matches!(target.kind(), "string" | "string_literal") {
                    let text = node_text(&target, src).trim().to_string();
                    if (text.starts_with("\"\"\"") || text.starts_with("'''")) && text.len() < 4096 {
                        let body_text = strip_comment_markers(&text);
                        out.push(crate::Comment {
                            span: span_of(file, &target),
                            kind: crate::CommentKind::classify(&body_text, true),
                            text,
                        });
                    }
                }
            }
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Scan the tree for call-site nodes and return them as flat [`crate::Ref`]
/// entries. Kept for legacy consumers; prefer `flow_events` for rich flow.
///
/// Elixir-style macro-syntactic definitions (`def`, `defp`, `defmodule`,
/// `defmacro`, …) parse as `call` nodes whose target identifier is the
/// keyword — semantically they're definitions, not function calls, so
/// emitting them in the ref index as `RefKind::Call` produces noise in
/// the `calls` / `refs` browse output and creates spurious edges in the
/// callgraph. We filter them here at the language-agnostic layer.
///
/// The list is deliberately Elixir-unique: `def`, `defp`, `defmodule`,
/// `defmacro`, `defmacrop`, `defprotocol`, `defimpl`, `defdelegate`,
/// `defstruct`, `defexception`. These identifiers aren't callable
/// functions in any supported language. `alias` / `import` / `require`
/// / `use` deliberately stay OUT of the list — JavaScript / Node uses
/// `require()` as a legitimate function (`const x = require("mod")`);
/// the Elixir import macro-calls are filtered by the Elixir-specific
/// `parse_imports` path, not here.
const MACRO_DEFINITION_NAMES: &[&str] = &[
    "def",
    "defp",
    "defmodule",
    "defmacro",
    "defmacrop",
    "defprotocol",
    "defimpl",
    "defdelegate",
    "defstruct",
    "defexception",
];

pub fn extract_call_refs(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::Ref> {
    let mut out = Vec::new();
    for node in collect_kinds(tree, COMMON_CALL_KINDS) {
        let erlang_remote = erlang_remote_callee(&node, src);
        // Prefer the named expression-like child that names the callee.
        // For dotted calls (`req.getParameter(...)`, `foo.bar.baz(...)`)
        // the callee is a `navigation_expression` / `member_expression`
        // / `field_expression` — taking `first_identifier_like_child`
        // would only grab the leftmost receiver (`req`) and miss the
        // actual method name. Using the full expression subtree gives
        // `req.getParameter` which is what downstream ref-lookup wants.
        let callee_node = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("callee"))
            .or_else(|| erlang_remote.as_ref().map(|(n, _)| *n))
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| first_callee_expression_child(&node))
            .or_else(|| first_identifier_like_child(&node))
            .or_else(|| first_identifier_descendant(node));
        let Some(callee) = callee_node else { continue };
        // Tree-sitter-grammar-grounded callee names. Solidity's
        // `emit_statement` / `revert_statement` are dedicated node
        // kinds — the grammar ALREADY identifies them for us, so
        // we emit TWO Call refs per occurrence: the event / reason
        // name itself (so `callee.name: AdminAction` matches the
        // user-declared rule), PLUS a synthetic `emit` / `revert`
        // ref at the same span so rulepack writers who want to
        // catch "any emit" / "any revert" keep `callee.name: emit`
        // as the matcher. Everything is tree-sitter derived — no
        // regex.
        let mut inner_name = erlang_remote
            .as_ref()
            .map(|(_, name)| normalize_call_name_whitespace(name))
            .unwrap_or_else(|| normalize_call_name_whitespace(node_text(&callee, src)));
        if node.kind() == "macro_invocation" && !inner_name.ends_with('!') {
            let node_src = node_text(&node, src);
            let rest = node_src
                .trim_start()
                .strip_prefix(&inner_name)
                .unwrap_or_default();
            if rest.trim_start().starts_with('!') {
                inner_name.push('!');
            }
        }
        if inner_name.is_empty() {
            continue;
        }
        // Skip Elixir-style macro-syntactic definition / import calls
        // (`def foo do …`, `alias MyApp.X`, …). These parse as `call`
        // nodes but semantically aren't function calls — see
        // `MACRO_DEFINITION_NAMES` for rationale.
        if MACRO_DEFINITION_NAMES.contains(&inner_name.as_str()) {
            continue;
        }
        // Push the synthetic node-kind keyword ref first.
        if node.kind() == "emit_statement" {
            out.push(crate::Ref {
                span: span_of(file, &node),
                name: "emit".to_string(),
                kind: crate::RefKind::Call,
                scope: None,
                resolved: None,
            });
        } else if node.kind() == "revert_statement" {
            out.push(crate::Ref {
                span: span_of(file, &node),
                name: "revert".to_string(),
                kind: crate::RefKind::Call,
                scope: None,
                resolved: None,
            });
        }
        let name = inner_name;
        if name.is_empty() {
            continue;
        }
        out.push(crate::Ref {
            span: span_of(file, &callee),
            name,
            kind: crate::RefKind::Call,
            scope: None,
            resolved: None,
        });
    }
    // Dart-specific: tree-sitter-dart models calls as
    // `identifier selector(argument_part)` rather than a unified
    // call-kind node, so the loop above misses them. Walk
    // `selector` nodes whose first named child is an
    // `argument_part` (confirming the selector is the
    // call-application, not a `.method` access), and reuse the
    // existing Dart selector→callee walker used by the flow-event
    // pass so resolved names match what `calls` shows.
    for node in collect_kinds(tree, &["selector"]) {
        let has_argument_part = first_named_child_of_kind(&node, "argument_part").is_some();
        if !has_argument_part {
            continue;
        }
        if let Some(FlowEvent::Call { name, span, .. }) = build_dart_selector_call_event(node, file, src) {
            out.push(crate::Ref {
                span,
                name: normalize_call_name_whitespace(&name),
                kind: crate::RefKind::Call,
                scope: None,
                resolved: None,
            });
        }
    }
    out
}

/// Resolution target for one local name introduced by an import.
///
/// The two variants correspond to the two ways a local binding can be
/// rewritten in call-site text — they need different expansion logic:
///
/// - [`AliasTarget::Member`] — `local_name` binds a specific export of
///   the module, so a bare `local_name(x)` call site rewrites to
///   `module.member(x)`. Covers destructured imports
///   (`const { exec } = require("child_process")`, shorthand and
///   renamed forms), ES-module named imports (`import { exec } from
///   "child_process"`), and Python / Ruby / PHP equivalents.
///
/// - [`AliasTarget::Namespace`] — `local_name` binds the *entire*
///   module, so `local_name.exec(x)` rewrites to `module.exec(x)`
///   (the `local_name.` prefix is replaced by the module name).
///   Covers default imports (`import x from "y"`), namespace imports
///   (`import * as cp from "child_process"`), and CommonJS's
///   `const cp = require("child_process")` form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AliasTarget {
    /// Local name binds a specific module export; the local name IS
    /// the member within the module. Rewrite `local(x)` →
    /// `module.member(x)` where `member` is typically the same
    /// identifier as the local (shorthand) or a renamed original.
    Member { module: String, member: String },
    /// Local name binds the whole module. Rewrite the `local.` prefix
    /// in the call chain to the `module` name.
    Namespace { module: String },
    /// Local name binds an instance of a type. Populated by
    /// [`extend_alias_map_with_flow_events`] when an assignment's
    /// RHS is a constructor call (PascalCase callee, `new <T>(...)`,
    /// or a known factory). Lets the security matcher rewrite
    /// `recv.method(x)` to `Type.method(x)` so attribute-chain rules
    /// like `[Logger, info]` / `[File, readText]` /
    /// `[HttpClient, GetStringAsync]` fire on real-world instance
    /// receivers.
    Type { type_name: String },
}

/// Synthetic alias-map key prefix for unprefixed wildcard imports.
///
/// Languages such as Dart and Python can import another module's public
/// symbols directly into the local lexical scope. The resolver still keeps
/// those lookups semantic by constraining matches to the imported module.
pub const WILDCARD_IMPORT_ALIAS_PREFIX: &str = "__bonsai_wildcard_import__:";

/// Extend an `import`-derived alias map with intra-procedural
/// variable-reassignment aliases pulled from a function's
/// [`crate::FlowEvent`] tree. Every `FlowEvent::Assign { target,
/// source_name: Some(s)  }` where `s` is already a known alias adds
/// `target -> <same target>` as a transitive alias, so call sites
/// like
///
/// ```text
/// const { exec } = require("child_process");  // alias: exec → Member{child_process, exec}
/// const fn = exec;                              // pulls in fn → Member{child_process, exec}
/// const copy = fn;                              // pulls in copy → Member{child_process, exec}
/// copy(userInput);                              // matches rule
/// ```
///
/// Iterates to fixed-point (bounded at 16 rounds) so chains of
/// reassignments resolve. Walks the full flow tree — branches, loops,
/// try, await/yield, defer, etc. — so aliases introduced inside any
/// control-flow region are visible to call sites elsewhere in the
/// function. Language-agnostic: every adapter's assignment emission
/// lands here.
pub fn extend_alias_map_with_flow_events<S: std::hash::BuildHasher>(
    map: &mut std::collections::HashMap<String, AliasTarget, S>,
    events: &[crate::FlowEvent],
) {
    // Collect (target, source_name, source_call, source_names)
    // tuples from the flow tree. `source_name` carries bare-
    // identifier RHS; `source_call` carries direct-call /
    // constructor RHS; `source_names` is the full attribute chain
    // (e.g. `["Logger", "getLogger"]` for `Logger.getLogger(...)`)
    // — used to detect factory-method patterns where the type lives
    // in the receiver, not the called name.
    type AssignmentAlias = (String, Option<String>, Option<String>, Vec<String>);

    fn collect(out: &mut Vec<AssignmentAlias>, events: &[crate::FlowEvent]) {
        for ev in events {
            match ev {
                crate::FlowEvent::Assign {
                    target,
                    source_name,
                    source_call,
                    source_names,
                    ..
                } if !target.is_empty() => {
                    out.push((
                        target.clone(),
                        source_name.clone(),
                        source_call.clone(),
                        source_names.clone(),
                    ));
                }
                crate::FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect(out, then_events);
                    collect(out, else_events);
                }
                crate::FlowEvent::Loop { body, .. } => collect(out, body),
                crate::FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    collect(out, body);
                    collect(out, catch_events);
                    collect(out, finally_events);
                }
                _ => {}
            }
        }
    }
    let mut triples = Vec::new();
    collect(&mut triples, events);
    if triples.is_empty() {
        return;
    }
    // First pass: bind constructor- and same-receiver factory-style assignments
    // to AliasTarget::Type so the matcher can rewrite
    // `<recv>.<method>` to `<Type>.<method>`. Three structural heuristics:
    //
    //  1. Constructor-style RHS (`val f = File(path)`, `new
    //     HttpClient()`): `source_call` starts with an ASCII
    //     uppercase letter — the PascalCase class-name convention
    //     used in Java, Kotlin, C#, Scala, Swift, Dart, JS, TS,
    //     Python, Ruby. The bound type is the call's bare name.
    //
    //  2. Factory-style RHS (`Logger log = Logger.getLogger("app")`,
    //     `Path p = Path.of(...)`): the attribute chain in
    //     `source_names` is exactly two segments and the leading
    //     segment is PascalCase. The bound type is that leading
    //     segment. This keeps the type fact anchored to an explicit
    //     class-like receiver in the source text.
    //
    //  3. Constructor assignment facts where the adapter emits only
    //     the constructor identifier in `source_names`
    //     (`const client = new GraphQLClient(...)`).
    //
    // Both heuristics are based on class-name code shape, not framework
    // or request-domain vocabulary. Lowercase method names are not mapped
    // through semantic tables here; rulepack/API coverage owns those cases.
    for (target, _, source_call, source_names) in &triples {
        // Don't overwrite an existing import-alias binding.
        if map.contains_key(target) {
            continue;
        }
        let bound_type = if let Some(call) = source_call.as_deref() {
            constructor_type_from_call_name(call).or_else(|| factory_type_from_source_names(source_names))
        } else if source_names.len() == 1
            && source_names[0]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
        {
            // Some grammars emit `const x = new Type(...)` as an
            // assignment with only the constructor identifier in
            // `source_names`; keep the same PascalCase type inference
            // the `source_call` path uses.
            Some(source_names[0].clone())
        } else {
            None
        };
        let Some(type_name) = bound_type else { continue };
        map.insert(target.clone(), AliasTarget::Type { type_name });
    }
    // Fixpoint: keep propagating bare-name aliases until no new ones
    // appear. Bounded iterations — worst case is a long chain
    // `a = b; b = c; …` which converges in ≤ N rounds where N =
    // chain length. Cap at 16 so pathological test cases can't loop
    // forever.
    for _ in 0..16 {
        let mut changed = false;
        for (target, src, _, _) in &triples {
            let Some(src) = src.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };
            // Only alias when the source is a known alias AND the
            // target isn't already in the map with a different
            // target.
            let Some(resolved) = map.get(src).cloned() else {
                continue;
            };
            match map.get(target) {
                Some(existing) if existing == &resolved => continue,
                Some(_) => continue,
                _ => {
                    map.insert(target.clone(), resolved);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

fn constructor_type_from_call_name(call: &str) -> Option<String> {
    let normalized = call.trim().trim_start_matches("new ").trim();
    let constructor_receiver = [".new", "::new", "->new", "\\new", "::__construct"]
        .iter()
        .find_map(|suffix| normalized.strip_suffix(suffix))
        .map(str::trim)
        .filter(|receiver| !receiver.is_empty());
    if let Some(receiver) = constructor_receiver {
        return Some(receiver.to_string());
    }

    let bare = normalized
        .rsplit(&['.', ':', '\\'][..])
        .next()
        .unwrap_or(normalized);
    if bare.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        Some(bare.to_string())
    } else {
        None
    }
}

fn factory_type_from_source_names(source_names: &[String]) -> Option<String> {
    if source_names.len() == 2
        && source_names[0]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
    {
        // Same-name-as-receiver factory: `Path.of(...)` →
        // source_names = ["Path", "of"]. The receiver class itself
        // is the only inferred type fact.
        Some(source_names[0].clone())
    } else {
        None
    }
}

/// Build the canonical `local_name -> AliasTarget` map directly from
/// an [`crate::ImportIndex`]. This is the ONE alias-resolution entry
/// point — every consumer (resolver, security matcher, chain-filter
/// tokens) goes through it so there is a single source of truth for
/// "what module does this local name resolve to".
///
/// Adapters own language-specific import syntax via `parse_imports`
/// and emit uniform `ImportSpec` entries (including shorthand
/// destructures tagged `ImportScope::Local`). This helper is
/// adapter-agnostic: it walks the uniform structure and classifies
/// each binding.
///
/// Examples:
///
/// | ImportSpec                                                       | local → target                                |
/// |------------------------------------------------------------------|-----------------------------------------------|
/// | `import { exec } from "child_process"`                           | `exec → Member{ child_process, exec }`        |
/// | `const { exec } = require("child_process")`                      | `exec → Member{ child_process, exec }`        |
/// | `from os import system`                                          | `system → Member{ os, system }`               |
/// | `import { exec as doExec } from "child_process"`                 | `doExec → Member{ child_process, exec }`      |
/// | `import os as o`                                                 | `o → Namespace{ os }`                         |
/// | `import * as cp from "child_process"`                            | `cp → Namespace{ child_process }`             |
/// | `const cp = require("child_process")`                            | `cp → Namespace{ child_process }`             |
#[must_use]
pub fn alias_map_from_imports(
    imports: &crate::ImportIndex,
) -> std::collections::HashMap<String, AliasTarget> {
    alias_map_from_import_specs(&imports.imports)
}

#[must_use]
pub fn alias_map_from_import_specs(
    imports: &[crate::ImportSpec],
) -> std::collections::HashMap<String, AliasTarget> {
    let mut map = std::collections::HashMap::new();
    for spec in imports {
        if spec.is_wildcard {
            // `import * as ns from "x"` / Python `from x import *`.
            // Namespace-bound if there's an alias; wildcard imports
            // without an alias import the module's public symbols
            // unqualified; encode them under a synthetic key so
            // resolvers can constrain bare lookups to this module
            // without falling back to workspace-wide name matching.
            if let Some(alias) = spec.alias.clone() {
                if !alias.is_empty() {
                    map.insert(
                        alias,
                        AliasTarget::Namespace {
                            module: spec.module.clone(),
                        },
                    );
                }
            } else if !spec.module.is_empty() {
                map.insert(
                    format!("{WILDCARD_IMPORT_ALIAS_PREFIX}{}", spec.module),
                    AliasTarget::Namespace {
                        module: spec.module.clone(),
                    },
                );
            }
            continue;
        }
        match (spec.alias.as_deref(), spec.original_name.as_deref()) {
            // Renamed member binding: `import { exec as doExec }` —
            // the local name resolves to the module's `exec` member.
            (Some(local), Some(original)) if !local.is_empty() && !original.is_empty() => {
                map.insert(
                    local.to_string(),
                    AliasTarget::Member {
                        module: spec.module.clone(),
                        member: original.to_string(),
                    },
                );
            }
            // Shorthand member binding (JS/TS `{ exec }`). Python `from
            // os import system` lands here via original_name being set
            // to `system` while alias is None.
            (None, Some(original)) if !original.is_empty() => {
                map.insert(
                    original.to_string(),
                    AliasTarget::Member {
                        module: spec.module.clone(),
                        member: original.to_string(),
                    },
                );
            }
            // Namespace binding — `import os as o` / `const cp =
            // require("x")` / default import. The local name stands
            // for the whole module.
            (Some(local), None) if !local.is_empty() => {
                map.insert(
                    local.to_string(),
                    AliasTarget::Namespace {
                        module: spec.module.clone(),
                    },
                );
            }
            // Unaliased module import. Derive a local module binding
            // from the module path so qualified calls are gated by
            // semantic alias-target resolution instead of bare-tail
            // lookup. Side-effect-only imports that do not actually
            // bind this name become harmless unresolved alias heads.
            (None, None) => {
                if let Some(local) = module_local_binding(&spec.module) {
                    map.entry(local).or_insert_with(|| AliasTarget::Namespace {
                        module: spec.module.clone(),
                    });
                }
            }
            _ => {}
        }
    }
    map
}

fn module_local_binding(module: &str) -> Option<String> {
    let trimmed = module
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'))
        .trim_end_matches(['/', '\\'])
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    let path_like = trimmed.contains('/') || trimmed.contains('\\') || trimmed.starts_with('.');
    let mut candidate = if path_like {
        trimmed
            .rsplit(['/', '\\'])
            .next()
            .and_then(strip_known_import_extension)
            .or_else(|| trimmed.rsplit(['/', '\\']).next())
            .unwrap_or(trimmed)
    } else if let Some(stem) = strip_known_import_extension(trimmed) {
        stem.rsplit(['.', ':']).next().unwrap_or(stem)
    } else if let Some((_, tail)) = trimmed.rsplit_once("::") {
        tail
    } else if let Some((_, tail)) = trimmed.rsplit_once(':') {
        tail
    } else if let Some((_, tail)) = trimmed.rsplit_once('.') {
        tail
    } else {
        trimmed
    };
    candidate = candidate.trim();
    let mut chars = candidate.chars();
    let first = chars.next()?;
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic()) {
        return None;
    }
    if !chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(candidate.to_string())
}

fn strip_known_import_extension(module: &str) -> Option<&str> {
    let (stem, ext) = module.rsplit_once('.')?;
    let ext = ext.trim();
    if matches!(
        ext,
        "c" | "cc"
            | "cpp"
            | "cs"
            | "cxx"
            | "dart"
            | "erl"
            | "ex"
            | "exs"
            | "h"
            | "hh"
            | "hpp"
            | "hrl"
            | "java"
            | "js"
            | "kt"
            | "kts"
            | "lua"
            | "m"
            | "mm"
            | "php"
            | "pl"
            | "pm"
            | "py"
            | "rb"
            | "rs"
            | "scala"
            | "sol"
            | "swift"
            | "ts"
    ) {
        Some(stem)
    } else {
        None
    }
}

// --- attribute-chain / subscript ref emission -------------------------------
//
// The following const tables + helpers back `extract_read_write_refs`. They
// are intentionally kept private — every grammar-specific kind listed here
// is an implementation detail of how this file surfaces `RefKind::Read` /
// `RefKind::Write` facts for attribute chains, subscript access, and
// sigil'd variable reads. Adapter crates should not depend on them.

/// Member / field / attribute expression kinds across every supported
/// grammar — `obj.prop`, `ns::name`, `struct.field`, `request.args`. The
/// full dotted text is what the security matcher looks for; nested chains
/// emit one Ref per level so both `[req, query]` and `[req, query, token]`
/// rule shapes can match.
const MEMBER_EXPR_KINDS: &[&str] = &[
    "member_expression",                 // javascript, typescript, php, solidity
    "nullsafe_member_access_expression", // php `$obj?->prop` (H13)
    "member_access_expression",          // c#
    "field_access",                      // java
    "field_expression",                  // rust, c, c++, objc, scala, go (some grammars)
    "selector_expression",               // go
    "navigation_expression",             // kotlin, swift
    "attribute",                         // python
    "dot_index_expression",              // lua
    "qualified_access_expression",       // swift (newer grammar variants)
    "qualified_identifier",              // dart / c++ rare forms
    "scoped_identifier",                 // rust ns::name (optional)
    "property_access_expression",        // c# / typescript (older grammar)
    "assignable_expression",             // dart `target.innerHtml = x` LHS
    "assignable_selector",               // dart selector piece `.innerHtml`
    "unconditional_assignable_selector", // dart `.innerHtml` non-null form
    "conditional_assignable_selector",   // dart `?.innerHtml` null-aware form
];

/// Subscript / index-access expression kinds — `arr[i]`, `$_GET['x']`,
/// `map["key"]`. Normalised to the bare base expression text (the object
/// being indexed), stripped of any `$` sigil. Supplies the PHP
/// `_GET`/`_POST`-style rule surface and the Ruby/Python `params[:x]`
/// controller DSL surface.
const SUBSCRIPT_KINDS: &[&str] = &[
    "subscript_expression",      // javascript, typescript, php, swift, c, cpp
    "subscript",                 // python
    "element_reference",         // ruby
    "array_access",              // java
    "element_access_expression", // c#
    "bracket_index_expression",  // lua
    "index_expression",          // go, rust, elixir
    "indexing_expression",       // kotlin
    "indexing_suffix",           // kotlin (selector form)
];

/// PHP-style sigil'd variables (`$_GET`, `$argv`). Surfaced as bare-name
/// reads stripped of the leading `$` so rules written as `name: _GET`
/// match the source.
const SIGIL_VARIABLE_KINDS: &[&str] = &["variable_name"];

/// Global / special-variable forms that some grammars surface as their own
/// kind rather than as an identifier (e.g. Ruby's `$stdin`).
const GLOBAL_VARIABLE_KINDS: &[&str] = &["global_variable"];

/// True when `node` is the callee of an enclosing call expression. The
/// callee slot is a `Call` ref already (emitted by `extract_call_refs`),
/// so we skip it here to avoid emitting a duplicate `Read` at the same
/// span that would wrongly satisfy a `kind: read` rule against a
/// callee's dotted name.
fn is_call_callee(node: &Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    const CALL_PARENTS: &[&str] = &[
        "call_expression",
        "call",
        "method_invocation",
        "method_call",
        "method_call_expression",
        "member_call_expression",
        "nullsafe_member_call_expression",
        "invocation_expression",
        "function_call",
        "function_call_expression",
        "new_expression",
        "constructor_invocation",
        "object_creation_expression",
    ];
    if !CALL_PARENTS.contains(&parent.kind()) {
        return false;
    }
    for field in ["function", "callee", "name", "target", "method", "invocation"] {
        if let Some(callee) = parent.child_by_field_name(field) {
            if callee.id() == node.id() {
                return true;
            }
        }
    }
    // Ruby's `call { receiver, method }` node — the bare method name is a
    // plain identifier inside; skipping is handled by parent kind only.
    false
}

/// True when `node` is the LHS of an assignment / compound assignment.
/// In that position the ref is a write, not a read. Nested receivers
/// still count as reads (handled by the outer walk emitting per-level
/// reads).
fn is_write_target(node: &Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    const ASSIGN_PARENTS: &[&str] = &[
        "assignment_expression",
        "assignment",
        "augmented_assignment_expression",
        "augmented_assignment",
        "compound_assignment_expr",
        "simple_assignment_expression",
    ];
    if !ASSIGN_PARENTS.contains(&parent.kind()) {
        return false;
    }
    for field in ["left", "target", "name"] {
        if let Some(lhs) = parent.child_by_field_name(field) {
            if lhs.id() == node.id() {
                return true;
            }
        }
    }
    // Grammars without a named `left` field: the LHS is the first named
    // child. Fall back to position check.
    if let Some(first) = first_named_child(&parent) {
        if first.id() == node.id() {
            return true;
        }
    }
    false
}

/// Build the dotted chain name for a member/field/attribute expression.
/// Walks the object/operand side down to the leftmost identifier and
/// joins every property with '.'. Returns `None` if the chain can't be
/// reduced to a single meaningful dotted string (e.g. parenthesised
/// subexpressions, call returns, computed property access).
fn normalize_member_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = Some(*node);
    while let Some(n) = cur {
        if !MEMBER_EXPR_KINDS.contains(&n.kind()) {
            // Base of the chain — include its text and stop.
            let text = node_text(&n, src).trim().to_string();
            if !text.is_empty() {
                parts.push(text.trim_start_matches('$').to_string());
            }
            break;
        }
        // Extract the property/field/name identifier for this level.
        let field = n
            .child_by_field_name("property")
            .or_else(|| n.child_by_field_name("field"))
            .or_else(|| n.child_by_field_name("name"))
            .or_else(|| n.child_by_field_name("attribute"))
            .or_else(|| n.child_by_field_name("right"))
            .or_else(|| n.child_by_field_name("member"))
            .or_else(|| {
                n.child_by_field_name("suffix")
                    .and_then(|suffix| first_identifier_descendant(suffix))
            });
        if let Some(f) = field {
            let text = node_text(&f, src).trim().to_string();
            if !text.is_empty() {
                parts.push(text);
            }
        }
        cur = n
            .child_by_field_name("object")
            .or_else(|| n.child_by_field_name("expression"))
            .or_else(|| n.child_by_field_name("operand"))
            .or_else(|| n.child_by_field_name("value"))
            .or_else(|| n.child_by_field_name("argument"))
            .or_else(|| n.child_by_field_name("left"))
            .or_else(|| n.child_by_field_name("target"))
            .or_else(|| n.child_by_field_name("table"))
            .or_else(|| n.child_by_field_name("receiver"));
        // Guard: if the object field is missing or already non-member with
        // no readable text, stop.
        if cur.is_none() {
            break;
        }
    }
    if parts.is_empty() {
        return None;
    }
    parts.reverse();
    let joined = parts
        .iter()
        .filter(|s| !s.is_empty() && !s.contains('\n'))
        .cloned()
        .collect::<Vec<_>>()
        .join(".");
    if joined.is_empty() || !joined.contains('.') {
        // Single-segment chains aren't useful as attribute-chain reads —
        // bare identifiers are emitted elsewhere (sigil'd / global).
        return None;
    }
    Some(joined)
}

/// True when a subscript expression's base is a plain identifier (no
/// dotted path, no function call, no other subscript). Used to decide
/// whether to emit the companion `Call` ref for DSL-style
/// implicit-receiver subscripts.
fn is_bare_identifier_base(node: &Node<'_>) -> bool {
    let base = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("argument"))
        .or_else(|| node.child_by_field_name("operand"))
        .or_else(|| first_named_child(node));
    let Some(base) = base else {
        return false;
    };
    matches!(
        base.kind(),
        "identifier" | "simple_identifier" | "constant" | "type_identifier"
    )
}

/// Extract the base expression's text for a subscript / element-access
/// node — the thing being indexed. `$_GET['x']` → `_GET`, `arr[i]` → `arr`.
fn normalize_subscript_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let base = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("argument"))
        .or_else(|| node.child_by_field_name("operand"))
        .or_else(|| first_named_child(node))?;
    let text = node_text(&base, src).trim().to_string();
    if text.is_empty() {
        return None;
    }
    let cleaned = text.trim_start_matches('$').to_string();
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned)
}

/// Scan the tree for attribute-chain and subscript reads (and their
/// assignment-LHS writes) and return them as flat `crate::Ref` entries
/// with `RefKind::Read` / `RefKind::Write`.
///
/// Why this exists: rules shaped like
/// ```yaml
/// match:
///   kind: read
///   target:
///     attribute: [req, query]
/// ```
/// rely on the adapter surfacing `req.query`-style reads. Without this
/// walker, `extract_call_refs` only emits callee refs — every
/// `kind: read target.attribute: [...]` rule in the pack (Express
/// `req.query`, Flask `request.args`, PHP `_GET`, Rails `params`, …)
/// would silently never match, regardless of what the rulepack says.
pub fn extract_read_write_refs(tree: &tree_sitter::Tree, file: FileId, src: &[u8]) -> Vec<crate::Ref> {
    let mut out = Vec::new();

    // Attribute chains — `req.query`, `request.args`, `Runtime.getRuntime`…
    for node in collect_kinds(tree, MEMBER_EXPR_KINDS) {
        if is_call_callee(&node) {
            continue;
        }
        let Some(name) = normalize_member_name(&node, src) else {
            continue;
        };
        let kind = if is_write_target(&node) {
            crate::RefKind::Write
        } else {
            crate::RefKind::Read
        };
        out.push(crate::Ref {
            span: span_of(file, &node),
            name,
            kind,
            scope: None,
            resolved: None,
        });
    }

    // Subscript reads — `$_GET['x']`, `arr[i]`, `params[:token]`.
    for node in collect_kinds(tree, SUBSCRIPT_KINDS) {
        if is_call_callee(&node) {
            continue;
        }
        let Some(name) = normalize_subscript_name(&node, src) else {
            continue;
        };
        let kind = if is_write_target(&node) {
            crate::RefKind::Write
        } else {
            crate::RefKind::Read
        };
        out.push(crate::Ref {
            span: span_of(file, &node),
            name: name.clone(),
            kind,
            scope: None,
            resolved: None,
        });
        // DSL idiom (Ruby / Python controller frameworks): a bare
        // identifier used as a subscript receiver — `params[:token]`,
        // `params['x']`, `session['user']` — is semantically an
        // implicit-receiver method call in Ruby / a framework DSL in
        // Python. Emit a matching `Call` ref so rules shaped as
        // `kind: call callee.name: params` fire — without this, rules
        // that target Rack/Sinatra/Rails/Flask controller params never
        // see the access at all.
        if !name.contains('.') && !name.contains("::") && is_bare_identifier_base(&node) {
            out.push(crate::Ref {
                span: span_of(file, &node),
                name,
                kind: crate::RefKind::Call,
                scope: None,
                resolved: None,
            });
        }
    }

    // PHP `$_GET` / `$argv` style superglobals: surface the bare name
    // (minus leading `$`) so rules like `name: _GET` match.
    for node in collect_kinds(tree, SIGIL_VARIABLE_KINDS) {
        if is_call_callee(&node) {
            continue;
        }
        let raw = node_text(&node, src).trim().to_string();
        let name = raw.trim_start_matches('$').to_string();
        if name.is_empty() {
            continue;
        }
        let kind = if is_write_target(&node) {
            crate::RefKind::Write
        } else {
            crate::RefKind::Read
        };
        out.push(crate::Ref {
            span: span_of(file, &node),
            name,
            kind,
            scope: None,
            resolved: None,
        });
    }

    // Ruby-style `$stdin` / `$stdout` globals.
    for node in collect_kinds(tree, GLOBAL_VARIABLE_KINDS) {
        let raw = node_text(&node, src).trim().to_string();
        let name = raw.trim_start_matches('$').to_string();
        if name.is_empty() {
            continue;
        }
        out.push(crate::Ref {
            span: span_of(file, &node),
            name,
            kind: crate::RefKind::Read,
            scope: None,
            resolved: None,
        });
    }

    // Assignment-LHS dotted writes — `target.innerHtml = x`,
    // `el.outerHTML = html`, `obj.cmd = tainted`. Some grammars
    // (notably tree-sitter-dart) wrap member-access LHS shapes in
    // grammar-specific node kinds (assignable_expression /
    // assignable_selector / unconditional_assignable_selector)
    // that aren't reliably reachable from a single MEMBER_EXPR_KINDS
    // walk. Walk the assignment_expression nodes directly, take the
    // LHS source text, and emit a Write ref keyed on the last
    // dotted segment so rules shaped as `kind: write target.name = X`
    // fire on the canonical `<recv>.<X> = ...` idiom regardless of
    // grammar-specific LHS encoding.
    const ASSIGN_KINDS: &[&str] = &[
        "assignment_expression",
        "assignment",
        "augmented_assignment_expression",
        "augmented_assignment",
        "compound_assignment_expr",
        "simple_assignment_expression",
    ];
    for node in collect_kinds(tree, ASSIGN_KINDS) {
        let lhs = node
            .child_by_field_name("left")
            .or_else(|| node.child_by_field_name("target"))
            .or_else(|| first_named_child(&node));
        let Some(lhs) = lhs else { continue };
        let lhs_text = node_text(&lhs, src).trim().to_string();
        // Only fire on dotted member writes; bare-identifier writes
        // (`x = y`) are already covered by the Assign FlowEvent's
        // target field and don't need a separate Write ref.
        if !lhs_text.contains('.') && !lhs_text.contains("->") {
            continue;
        }
        // Take the last dotted/arrow segment as the canonical write name.
        let last = lhs_text
            .rsplit(['.', '>'])
            .next()
            .unwrap_or(&lhs_text)
            .trim_matches(|c: char| matches!(c, '-' | ' ' | '\t'))
            .to_string();
        if last.is_empty() {
            continue;
        }
        // Skip subscript-shape last-segments like `arr[0]` — the
        // SUBSCRIPT_KINDS walker already covers those.
        if last.contains('[') || last.contains(']') {
            continue;
        }
        out.push(crate::Ref {
            span: span_of(file, &lhs),
            name: last,
            kind: crate::RefKind::Write,
            scope: None,
            resolved: None,
        });
    }

    out
}

/// Pull `(name_node, "receiver<sep>method")` out of a method-invocation
/// node when the grammar exposes separate receiver + name fields.
/// Covers Ruby (`receiver` + `method`, separator `.`), Java
/// (`object` + `name`, separator `.`), PHP arrow-call (`object` +
/// `name`, separator `->`), and similar shapes in other grammars.
/// Returns `None` when the shape doesn't match — the caller falls
/// back to the generic callee extraction.
fn method_receiver_name<'tree>(node: &Node<'tree>, src: &[u8]) -> Option<(Node<'tree>, String)> {
    // Elixir `Module.func(args)` parses as `call { target: dot { left,
    // right } }`. Unwrap the `target` field's dot node to pick up the
    // module-qualified name before falling back to simpler shapes.
    if node.kind() == "call" {
        if let Some(target) = node.child_by_field_name("target") {
            if target.kind() == "dot" {
                if let (Some(l), Some(r)) = (
                    target.child_by_field_name("left"),
                    target.child_by_field_name("right"),
                ) {
                    return Some((r, format!("{}.{}", node_text(&l, src), node_text(&r, src))));
                }
            }
        }
    }
    // PHP static calls: `Request::input(...)` parses as
    // `scoped_call_expression { scope, name }`.
    if let (Some(scope), Some(name)) = (
        node.child_by_field_name("scope"),
        node.child_by_field_name("name"),
    ) {
        return Some((
            name,
            format!("{}::{}", node_text(&scope, src), node_text(&name, src)),
        ));
    }
    // Ruby / Objective-C: `receiver` + `method`.
    if let (Some(r), Some(m)) = (
        node.child_by_field_name("receiver"),
        node.child_by_field_name("method"),
    ) {
        let receiver_raw = node_text(&r, src).trim();
        let receiver = if node.kind() == "member_call_expression" {
            receiver_raw
        } else {
            receiver_raw.trim_start_matches('$')
        };
        return Some((m, format!("{}.{}", receiver, node_text(&m, src))));
    }
    // Perl: `$dbh->prepare(...)` exposes `invocant` + `method`.
    if let (Some(r), Some(m)) = (
        node.child_by_field_name("invocant"),
        node.child_by_field_name("method"),
    ) {
        let receiver = node_text(&r, src).trim().trim_start_matches('$');
        return Some((m, format!("{}->{}", receiver, node_text(&m, src))));
    }
    // Java / PHP / Kotlin: `object` + `name`.
    if let (Some(obj), Some(nm)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("name"),
    ) {
        // PHP arrow-calls (`$obj->method()`) use `->` as the
        // semantic separator; detect this by the node kind so the
        // reconstructed text matches the source idiom.
        let sep = if matches!(
            node.kind(),
            "member_call_expression" | "nullsafe_member_call_expression"
        ) {
            "->"
        } else {
            "."
        };
        let receiver_raw = node_text(&obj, src).trim();
        let receiver = if matches!(
            node.kind(),
            "member_call_expression" | "nullsafe_member_call_expression"
        ) {
            receiver_raw
        } else {
            receiver_raw.trim_start_matches('$')
        };
        return Some((nm, format!("{}{sep}{}", receiver, node_text(&nm, src))));
    }
    // Solidity: `object` + `property`. member_expression wraps the
    // dotted access inside a function-field expression for calls, so
    // we also unwrap one level of `expression` / `member_expression`
    // if the call's `function` field is what we were handed.
    if let (Some(obj), Some(prop)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("property"),
    ) {
        return Some((
            prop,
            format!("{}.{}", node_text(&obj, src), node_text(&prop, src)),
        ));
    }
    // Solidity `call_expression.function: expression > member_expression`.
    // Walk one step down through a single `expression` or `member_expression`
    // wrapper attached to the `function` field.
    if let Some(func) = node.child_by_field_name("function") {
        let inner = if func.kind() == "expression" {
            first_named_child(&func).unwrap_or(func)
        } else {
            func
        };
        if inner.kind() == "member_expression" {
            if let (Some(obj), Some(prop)) = (
                inner.child_by_field_name("object"),
                inner.child_by_field_name("property"),
            ) {
                return Some((
                    prop,
                    format!("{}.{}", node_text(&obj, src), node_text(&prop, src)),
                ));
            }
        }
    }
    None
}

/// True when a Scala `field_expression` is actually a postfix method
/// call on an operator-named method: `foo.!`, `xs.>>`, etc. Detected
/// by the presence of an `operator_identifier` child — a dotted
/// access to a regular identifier is NOT considered a method call
/// here (the downstream `call_expression` for parenthesized calls
/// handles those).
/// Synthesize a `FlowEvent::Call` for Dart's split call grammar.
///
/// tree-sitter-dart emits `identifier selector(argument_part)` as two
/// sibling nodes rather than a unified call. Given the `selector`
/// node, walk backward through named siblings to collect the callee
/// text — a simple identifier is the base case; `receiver.method`
/// calls appear as `identifier "." identifier selector`, so we join
/// dot-separated identifiers into a qualified callee. Returns `None`
/// if no identifier-like prev sibling exists (selector appearing in
/// an unexpected position).
fn build_dart_selector_call_event(node: Node<'_>, file: FileId, src: &[u8]) -> Option<FlowEvent> {
    first_named_child_of_kind(&node, "argument_part")?;
    // Walk back through named siblings to assemble the dotted callee.
    // Shape in the Dart grammar:
    //   - plain call: `identifier selector(argument_part)`
    //   - method chain: `identifier selector(.b) selector(.c) …
    //     selector(argument_part)`
    // The first identifier we encounter is the *base* — everything
    // before it (LHS of an assignment, operator, etc.) is NOT part
    // of this call expression. The old walker accepted any number of
    // bare identifiers, which is how
    //   `var user = getUser(token)`
    // ended up emitting callee `user.getUser` — it treated the
    // assignment LHS as a receiver. Mark `have_base` after the first
    // bare identifier and bail if we see a second one; method-access
    // selectors can still precede or follow.
    let mut parts: Vec<String> = Vec::new();
    let mut cursor = node.prev_named_sibling();
    let mut have_base = false;
    while let Some(prev) = cursor {
        let k = prev.kind();
        if k == "identifier" || k == "type_identifier" || k == "super" || k == "this" {
            if have_base {
                break;
            }
            parts.push(node_text(&prev, src).to_string());
            have_base = true;
            cursor = prev.prev_named_sibling();
        } else if k == "selector" {
            // `.method` access selector: drill down to the identifier.
            let inner = first_named_child(&prev)?;
            if inner.kind() == "unconditional_assignable_selector"
                || inner.kind() == "conditional_assignable_selector"
            {
                let id = first_identifier_like_child(&inner)?;
                parts.push(node_text(&id, src).to_string());
                cursor = prev.prev_named_sibling();
            } else {
                break;
            }
        } else if k == "unconditional_assignable_selector" || k == "conditional_assignable_selector" {
            let id = first_identifier_like_child(&prev)?;
            parts.push(node_text(&id, src).to_string());
            cursor = prev.prev_named_sibling();
        } else {
            break;
        }
    }
    if parts.is_empty() {
        return None;
    }
    parts.reverse();
    let name = parts.join(".");

    // Build arg list from `selector > argument_part > arguments`.
    // Dart splits named args (`runInShell: true`) into a sibling
    // `named_argument` node with a `label` child; we surface those
    // with `name` populated so `keyword_arg_equals` constraints fire.
    let mut args: Vec<CallArg> = Vec::new();
    if let Some(arg_part) = first_named_child_of_kind(&node, "argument_part") {
        if let Some(arg_list) = first_named_child_of_kind(&arg_part, "arguments") {
            let mut cursor = arg_list.walk();
            for arg in arg_list.named_children(&mut cursor) {
                if arg.kind() == "named_argument" {
                    // Named (labeled) argument: `name: value`.
                    let mut lbl_cursor = arg.walk();
                    let label_node = arg.named_children(&mut lbl_cursor).find(|c| c.kind() == "label");
                    let name = label_node.and_then(|lbl| {
                        lbl.named_children(&mut lbl.walk())
                            .next()
                            .map(|id| node_text(&id, src).to_string())
                    });
                    // The value is the first named sibling AFTER the
                    // label (tree-sitter-dart named_argument is
                    // `label expr` — value has no field name). Dart splits
                    // a member value like `AESMode.ecb` into a base
                    // identifier plus trailing `selector` siblings, so the
                    // base alone truncates to `AESMode`; extend the value
                    // span through any trailing selectors to capture the
                    // whole chain (so `keyword_arg_equals: AESMode.ecb`
                    // can distinguish ECB from CBC/CTR).
                    let (value_node, value_text) = {
                        let mut kids = arg.walk();
                        let all: Vec<_> = arg.named_children(&mut kids).collect();
                        let label_idx = all.iter().position(|c| c.kind() == "label").unwrap_or(0);
                        let base = all.get(label_idx + 1).copied().unwrap_or(arg);
                        let mut chain_end = base.end_byte();
                        for sib in all.iter().skip(label_idx + 2) {
                            if sib.kind() == "selector" {
                                chain_end = sib.end_byte();
                            } else {
                                break;
                            }
                        }
                        let text = if chain_end > base.end_byte() {
                            normalize_call_name_whitespace(
                                std::str::from_utf8(&src[base.start_byte()..chain_end]).unwrap_or(""),
                            )
                        } else {
                            normalize_call_name_whitespace(node_text(&base, src))
                        };
                        (base, text)
                    };
                    if value_text.is_empty() {
                        continue;
                    }
                    args.push(CallArg {
                        span: span_of(file, &arg),
                        name,
                        place: argument_place(&value_node, src),
                        source_names: extract_rhs_expr_operands(&value_node, src),
                        value_text,
                    });
                    continue;
                }
                let value_text = normalize_call_name_whitespace(node_text(&arg, src));
                if value_text.is_empty() {
                    continue;
                }
                args.push(CallArg {
                    span: span_of(file, &arg),
                    name: None,
                    place: argument_place(&arg, src),
                    source_names: extract_rhs_expr_operands(&arg, src),
                    value_text,
                });
            }
        }
    }

    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: call_receiver_from_name(&name),
        receiver_types: Vec::new(),
        name,
        call_kind: if parts.len() > 1 {
            CallKind::Method
        } else {
            CallKind::Function
        },
        args,
    })
}

/// Unwrap Elixir's `def foo(x, y) do ... end` macro-call into its
/// signature pieces: the real function name node, the signature-call
/// node (whose `arguments` holds the params), and the body
/// expression — either a `do_block` child of the outer call (long
/// form) OR the `value` of a `do:` keyword pair in the outer call's
/// arguments (short form `def foo, do: expr`). Returns `None` when
/// `node` is an ordinary call (e.g. `IO.puts("hi")`).
struct ElixirDef<'tree> {
    name: Node<'tree>,
    signature_call: Node<'tree>,
    /// Body expression for `def foo, do: expr` short form. `None` for
    /// the long form (`do ... end`) — the kit's body fallback finds
    /// the `do_block` child of the outer call directly.
    short_form_body: Option<Node<'tree>>,
}

fn elixir_unwrap_def<'tree>(node: &Node<'tree>, src: &[u8]) -> Option<ElixirDef<'tree>> {
    // The outer call's target is an identifier like `def` or `defp`.
    let target = node.child_by_field_name("target")?;
    let target_text = node_text(&target, src).trim();
    if !matches!(
        target_text,
        "def" | "defp" | "defmacro" | "defmacrop" | "defguard" | "defguardp"
    ) {
        return None;
    }
    // The outer call's arguments container is a child node of kind
    // `arguments` (tree-sitter-elixir uses the kind name, not a field
    // name). Its first named child is the signature call.
    let outer_args = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "arguments"))?;
    let mut cursor = outer_args.walk();
    let sig_call = outer_args
        .named_children(&mut cursor)
        .find(|c| c.kind() == "call" || c.kind() == "identifier")?;
    let name_node = if sig_call.kind() == "identifier" {
        // Zero-arg def: `def foo do ... end` parses with the signature
        // as a bare identifier rather than a call. The identifier IS
        // the name.
        sig_call
    } else {
        sig_call.child_by_field_name("target")?
    };
    // Detect short-form body: outer_args contains a `keywords` child
    // whose first `pair` has a `do:` key. The pair's `value` field is
    // the body expression.
    let short_form_body = first_named_child_of_kind(&outer_args, "keywords")
        .and_then(|kws| first_named_child_of_kind(&kws, "pair"))
        .and_then(|pair| {
            let key = pair.child_by_field_name("key")?;
            let key_text = node_text(&key, src).trim().trim_end_matches(':');
            if key_text == "do" {
                pair.child_by_field_name("value")
            } else {
                None
            }
        });
    Some(ElixirDef {
        name: name_node,
        signature_call: sig_call,
        short_form_body,
    })
}

fn is_scala_operator_method_call(node: &Node<'_>) -> bool {
    let mut cursor = node.walk();
    let mut has_op = false;
    for child in node.named_children(&mut cursor) {
        if child.kind() == "operator_identifier" {
            has_op = true;
            break;
        }
    }
    has_op
}

/// True when a Swift `call_expression` looks like the `defer {...}`
/// form. Detected by callee text == "defer" AND a `lambda_literal`
/// reachable directly or via a `call_suffix` wrapper (tree-sitter-
/// swift nests the trailing closure inside `call_suffix`, so a direct
/// children scan misses it).
fn is_swift_defer_call(node: &Node<'_>, src: &[u8]) -> bool {
    let callee = node
        .child_by_field_name("function")
        .or_else(|| first_identifier_like_child(node));
    let Some(callee) = callee else { return false };
    if node_text(&callee, src).trim() != "defer" {
        return false;
    }
    fn find_lambda(n: Node<'_>, depth: usize) -> bool {
        if depth > 3 {
            return false;
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            if child.kind() == "lambda_literal" {
                return true;
            }
            if child.kind() == "call_suffix" && find_lambda(child, depth + 1) {
                return true;
            }
        }
        false
    }
    find_lambda(*node, 0)
}

/// True when an Elixir `binary_operator` node's operator token equals `op`.
fn elixir_binary_operator_is(node: &Node<'_>, src: &[u8], op: &str) -> bool {
    if let Some(operator) = node.child_by_field_name("operator") {
        return node_text(&operator, src).trim() == op;
    }
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    children
        .iter()
        .any(|child| !child.is_named() && node_text(child, src).trim() == op)
}

/// Elixir `for x <- enum` (H20) and `with pat <- expr` (M14) generator
/// clauses bind a new variable to the enumerable / matched expression.
/// Each clause is a `binary_operator` arg whose operator is `<-`.
/// Synthesize an Assign per binding target so taint flows into the
/// comprehension body / with-chain. Filters and the do-block are ignored.
fn extract_elixir_generator_binding_assigns(file: FileId, node: &Node<'_>, src: &[u8]) -> Vec<FlowEvent> {
    let Some(args) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "arguments"))
    else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    let arg_nodes: Vec<Node<'_>> = args.named_children(&mut cursor).collect();
    let mut out = Vec::new();
    for arg in arg_nodes {
        if arg.kind() != "binary_operator" || !elixir_binary_operator_is(&arg, src, "<-") {
            continue;
        }
        let (Some(pattern), Some(rhs)) = (arg.child_by_field_name("left"), arg.child_by_field_name("right"))
        else {
            continue;
        };
        let rhs_text = node_text(&rhs, src);
        for target in binding_targets_from_pattern_node(&pattern, src) {
            if let Some(assign) = pattern_binding_assign(file, &pattern, &target, rhs_text) {
                out.push(assign);
            }
        }
    }
    dedup_assign_events(out)
}

fn emit_elixir_control_flow_call(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) -> bool {
    let Some(name) = elixir_call_name(node, src) else {
        return false;
    };
    match name.as_str() {
        "if" | "unless" | "case" | "cond" | "with" => {
            let mut then_events = Vec::new();
            let mut else_events = Vec::new();
            if let Some(condition) = elixir_condition_arg(node) {
                walk_into(condition, file, src, handler, class_names, out, false);
            }
            if let Some(value) = elixir_keyword_value(node, src, "do") {
                walk_into(value, file, src, handler, class_names, &mut then_events, false);
            }
            if let Some(value) = elixir_keyword_value(node, src, "else") {
                walk_into(value, file, src, handler, class_names, &mut else_events, false);
            }
            if let Some(do_block) = first_named_child_of_kind(node, "do_block") {
                walk_elixir_do_block_as_branch(
                    do_block,
                    file,
                    src,
                    handler,
                    class_names,
                    &mut then_events,
                    &mut else_events,
                );
            }
            if name == "case" {
                let match_bindings = extract_elixir_case_stab_clause_bindings(file, node, src);
                if !match_bindings.is_empty() {
                    let mut prefixed = match_bindings.clone();
                    prefixed.extend(then_events);
                    then_events = prefixed;
                    if !else_events.is_empty() {
                        let mut prefixed_else = match_bindings;
                        prefixed_else.extend(else_events);
                        else_events = prefixed_else;
                    }
                }
            }
            if name == "with" {
                let with_bindings = extract_elixir_generator_binding_assigns(file, node, src);
                if !with_bindings.is_empty() {
                    let mut prefixed = with_bindings.clone();
                    prefixed.extend(then_events);
                    then_events = prefixed;
                    if !else_events.is_empty() {
                        let mut prefixed_else = with_bindings;
                        prefixed_else.extend(else_events);
                        else_events = prefixed_else;
                    }
                }
            }
            let condition = elixir_condition_arg(node)
                .map(|condition| node_text(&condition, src).trim().to_string())
                .filter(|condition| !condition.is_empty());
            out.push(FlowEvent::Branch {
                span: span_of(file, node),
                condition,
                then_events,
                else_events,
            });
            true
        }
        "try" => {
            let mut body = Vec::new();
            let mut catch_events = Vec::new();
            let mut finally_events = Vec::new();
            if let Some(do_block) = first_named_child_of_kind(node, "do_block") {
                let mut events = ElixirTryEventBuckets {
                    body: &mut body,
                    catch_events: &mut catch_events,
                    finally_events: &mut finally_events,
                };
                walk_elixir_do_block_as_try(do_block, file, src, handler, class_names, &mut events);
            }
            let (catch_param, catch_types) = elixir_rescue_binding(node, src);
            out.push(FlowEvent::Try {
                span: span_of(file, node),
                body,
                catch_events,
                finally_events,
                catch_param: catch_param.or_else(|| extract_catch_param(node, src)),
                catch_types,
            });
            true
        }
        "for" => emit_elixir_loop_call(node, file, src, handler, class_names, out),
        _ if matches!(
            name.as_str(),
            "Enum.each" | "Enum.map" | "Enum.flat_map" | "Enum.reduce" | "Stream.each" | "Stream.map"
        ) =>
        {
            emit_elixir_loop_call(node, file, src, handler, class_names, out)
        }
        _ => false,
    }
}

fn emit_elixir_loop_call(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) -> bool {
    let mut body = Vec::new();
    // H20: a plain `for x <- enum, do: ...` comprehension binds `x` to the
    // enumerable; the closure-param path below only covers Enum.each/map
    // closures, so synthesize the generator bindings up front.
    body.extend(extract_elixir_generator_binding_assigns(file, node, src));
    let sources = non_closure_arg_source_names(node, src, &["arguments"]);
    if let Some(args) = first_named_child_of_kind(node, "arguments") {
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            if arg.kind() == "anonymous_function" || is_closure_arg(arg.kind(), handler) {
                emit_inline_closure_param_bindings(arg, file, src, &sources, &mut body);
                walk_lambda_body(arg, file, src, handler, class_names, &mut body);
            }
        }
    }
    if let Some(do_block) = first_named_child_of_kind(node, "do_block") {
        walk_elixir_do_block_as_branch(
            do_block,
            file,
            src,
            handler,
            class_names,
            &mut body,
            &mut Vec::new(),
        );
    }
    if body.is_empty() {
        return false;
    }
    if let Some(event) = build_call_event(*node, file, src, handler, class_names) {
        out.push(event);
    }
    out.push(FlowEvent::Loop {
        span: span_of(file, node),
        loop_kind: LoopKind::ForEach,
        body,
    });
    true
}

fn emit_erlang_functional_loop_call(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) -> bool {
    let Some(call_event) = build_call_event(*node, file, src, handler, class_names) else {
        return false;
    };
    let FlowEvent::Call { name, .. } = &call_event else {
        return false;
    };
    if !matches!(
        name.as_str(),
        "lists:foreach" | "lists:map" | "lists:filter" | "lists:foldl" | "lists:foldr"
    ) {
        return false;
    }
    let Some(args) = node
        .child_by_field_name("args")
        .or_else(|| erlang_remote_args_node(node))
    else {
        return false;
    };
    let sources = non_closure_arg_source_names_from_container(args, src);
    let mut body = Vec::new();
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if arg.kind() == "anonymous_fun" || handler.is_lambda(arg.kind()) {
            emit_inline_closure_param_bindings(arg, file, src, &sources, &mut body);
            walk_lambda_body(arg, file, src, handler, class_names, &mut body);
        }
    }
    if body.is_empty() {
        return false;
    }
    out.push(call_event);
    out.push(FlowEvent::Loop {
        span: span_of(file, node),
        loop_kind: LoopKind::ForEach,
        body,
    });
    true
}

fn emit_ruby_block_loop_call(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) -> bool {
    let Some(call_event) = build_call_event(*node, file, src, handler, class_names) else {
        return false;
    };
    let FlowEvent::Call { name, .. } = &call_event else {
        return false;
    };
    if !matches!(
        short_name_of(name),
        "each" | "each_with_index" | "map" | "flat_map" | "collect" | "select" | "filter" | "reject"
    ) {
        return false;
    }
    let block =
        first_named_child_of_kind(node, "do_block").or_else(|| first_named_child_of_kind(node, "block"));
    let Some(block) = block else {
        return false;
    };

    let sources = call_event_value_source_names(&call_event);
    let mut body = Vec::new();
    emit_inline_closure_param_bindings(block, file, src, &sources, &mut body);
    walk_lambda_body(block, file, src, handler, class_names, &mut body);
    if body.is_empty() {
        return false;
    }

    out.push(call_event);
    out.push(FlowEvent::Loop {
        span: span_of(file, node),
        loop_kind: LoopKind::ForEach,
        body,
    });
    true
}

/// Extract the rescue/catch binding from an Elixir `try` call:
/// `rescue e -> ...` binds `e`; `rescue e in RuntimeError -> ...`
/// binds `e` and names `RuntimeError` as the caught type; Erlang-style
/// `catch :exit, reason -> ...` binds `reason` (the atom is the kind
/// tag, not a binding). The rescue arms live inside the `do_block`,
/// so the generic [`extract_catch_param`] walk over the call node's
/// direct children cannot see them.
fn elixir_rescue_binding(node: &Node<'_>, src: &[u8]) -> (Option<String>, Vec<String>) {
    let Some(do_block) = first_named_child_of_kind(node, "do_block") else {
        return (None, Vec::new());
    };
    let mut cursor = do_block.walk();
    for child in do_block.named_children(&mut cursor) {
        if !matches!(child.kind(), "rescue_block" | "catch_block") {
            continue;
        }
        let Some(stab) = first_named_child_of_kind(&child, "stab_clause") else {
            continue;
        };
        // Clause head = every named child before the `->` body.
        let mut head_cursor = stab.walk();
        let Some(head) = stab.named_children(&mut head_cursor).find(|n| n.kind() != "body") else {
            continue;
        };
        let param = first_identifier_descendant(head).map(|id| node_text(&id, src).trim().to_string());
        let mut types = Vec::new();
        collect_elixir_alias_texts(&head, src, &mut types);
        if param.is_some() || !types.is_empty() {
            return (param, types);
        }
    }
    (None, Vec::new())
}

/// Collect `alias` node texts (module names such as `RuntimeError`)
/// under an Elixir rescue clause head.
fn collect_elixir_alias_texts(node: &Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if node.kind() == "alias" {
        let text = node_text(node, src).trim().to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push(text);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_elixir_alias_texts(&child, src, out);
    }
}

fn elixir_call_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "call" {
        return None;
    }
    let target = node.child_by_field_name("target")?;
    let name = normalize_call_name_whitespace(node_text(&target, src));
    (!name.is_empty()).then_some(name)
}

fn elixir_condition_arg<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    let args = first_named_child_of_kind(node, "arguments")?;
    let mut cursor = args.walk();
    let condition = args
        .named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "keywords" | "pair"));
    condition
}

fn elixir_keyword_value<'tree>(node: &Node<'tree>, src: &[u8], key: &str) -> Option<Node<'tree>> {
    fn visit<'tree>(node: Node<'tree>, src: &[u8], key: &str) -> Option<Node<'tree>> {
        if node.kind() == "pair" {
            let pair_key = node.child_by_field_name("key")?;
            let pair_key = node_text(&pair_key, src)
                .trim()
                .trim_end_matches(':')
                .trim()
                .to_string();
            if pair_key == key {
                return node.child_by_field_name("value");
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(found) = visit(child, src, key) {
                return Some(found);
            }
        }
        None
    }
    visit(*node, src, key)
}

fn walk_elixir_do_block_as_branch(
    do_block: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    then_events: &mut Vec<FlowEvent>,
    else_events: &mut Vec<FlowEvent>,
) {
    let mut cursor = do_block.walk();
    for child in do_block.named_children(&mut cursor) {
        match child.kind() {
            "else_block" => walk_named_children(child, file, src, handler, class_names, else_events),
            "rescue_block" | "catch_block" | "after_block" => {}
            _ => walk_into(child, file, src, handler, class_names, then_events, false),
        }
    }
}

struct ElixirTryEventBuckets<'a> {
    body: &'a mut Vec<FlowEvent>,
    catch_events: &'a mut Vec<FlowEvent>,
    finally_events: &'a mut Vec<FlowEvent>,
}

fn walk_elixir_do_block_as_try(
    do_block: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    events: &mut ElixirTryEventBuckets<'_>,
) {
    let mut cursor = do_block.walk();
    for child in do_block.named_children(&mut cursor) {
        match child.kind() {
            "rescue_block" | "catch_block" => {
                walk_named_children(child, file, src, handler, class_names, events.catch_events);
            }
            "after_block" => {
                walk_named_children(child, file, src, handler, class_names, events.finally_events);
            }
            _ => walk_into(child, file, src, handler, class_names, events.body, false),
        }
    }
}

fn walk_named_children(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_into(child, file, src, handler, class_names, out, false);
    }
}

fn call_argument_containers(node: Node<'_>) -> Vec<Node<'_>> {
    let mut v: Vec<Node<'_>> = Vec::new();
    if let Some(n) = node.child_by_field_name("arguments") {
        v.push(n);
    }
    // Grammars that don't expose `arguments` as a field (Kotlin wraps it
    // in `call_suffix`; Scala / Swift may place it inline): also collect
    // direct children that look like argument lists or trailing-lambda
    // wrappers.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "arguments" | "argument_list" | "value_arguments" | "call_suffix" | "expr_args" => {
                v.push(child);
            }
            _ => {}
        }
    }
    let mut seen = std::collections::HashSet::new();
    v.retain(|n| seen.insert(n.id()));
    v
}

fn walk_call_argument_expressions(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) {
    for container in call_argument_containers(node) {
        if is_comprehension_kind(container.kind()) {
            walk_into(container, file, src, handler, class_names, out, false);
            continue;
        }
        let mut cursor = container.walk();
        for arg in container.named_children(&mut cursor) {
            if !is_closure_arg(arg.kind(), handler) {
                walk_into(arg, file, src, handler, class_names, out, false);
            }
        }
    }
}

fn immediately_invoked_lambda_callee<'tree>(
    call: &Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    let callee = call
        .child_by_field_name("function")
        .or_else(|| call.child_by_field_name("callee"))?;
    unwrap_invoked_lambda_callee(callee, handler)
}

fn unwrap_invoked_lambda_callee<'tree>(
    mut node: Node<'tree>,
    handler: &GrammarHandler,
) -> Option<Node<'tree>> {
    for _ in 0..6 {
        if handler.is_lambda(node.kind()) {
            return Some(node);
        }
        if !is_transparent_lambda_callee_wrapper(node.kind()) {
            return None;
        }
        node = node
            .child_by_field_name("expression")
            .or_else(|| node.child_by_field_name("value"))
            .or_else(|| first_named_child(&node))?;
    }
    None
}

fn is_transparent_lambda_callee_wrapper(kind: &str) -> bool {
    matches!(
        kind,
        "parenthesized_expression"
            | "primary_expression"
            | "expression"
            | "postfix_expression"
            | "unary_expression"
    )
}

fn non_closure_arg_source_names(node: &Node<'_>, src: &[u8], arg_container_kinds: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if arg_container_kinds.contains(&child.kind()) {
            out.extend(non_closure_arg_source_names_from_container(child, src));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn non_closure_arg_source_names_from_container(container: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = container.walk();
    for arg in container.named_children(&mut cursor) {
        if matches!(
            arg.kind(),
            "anonymous_function" | "anonymous_fun" | "keywords" | "pair"
        ) || arg.kind().contains("lambda")
            || arg.kind().contains("closure")
        {
            continue;
        }
        out.extend(extract_rhs_expr_operands(&arg, src));
        if let Some(place) = argument_place(&arg, src) {
            push_value_text_source_name(&mut out, &place);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// A call-argument node that should have its body inlined into the
/// enclosing function's flow. This is broader than `handler.is_lambda`
/// because some languages (notably Ruby) use the generic `block` node
/// kind to mean "the closure passed to this method", and the generic
/// `block` kind can't be in lambda_kinds globally — it also serves as
/// "compound statement" in most other grammars.
fn is_closure_arg(kind: &str, handler: &GrammarHandler) -> bool {
    if handler.is_lambda(kind) {
        return true;
    }
    // Ruby `method { |x| ... }` and `method do |x| ... end`.
    matches!(kind, "block" | "do_block")
}

fn emit_invoked_lambda_param_bindings(
    lambda: Node<'_>,
    file: FileId,
    src: &[u8],
    call_event: &FlowEvent,
    out: &mut Vec<FlowEvent>,
) {
    let FlowEvent::Call { args, .. } = call_event else {
        return;
    };
    if args.is_empty() {
        return;
    }
    for (idx, param) in extract_param_names(&lambda, src).into_iter().enumerate() {
        if param.is_empty() {
            continue;
        }
        let arg = args
            .iter()
            .find(|arg| arg.name.as_deref() == Some(param.as_str()))
            .or_else(|| args.get(idx));
        let Some(arg) = arg else {
            continue;
        };
        let mut source_names = arg.source_names.clone();
        if let Some(place) = arg.place.as_deref() {
            push_value_text_source_name(&mut source_names, place);
        }
        push_value_text_source_name(&mut source_names, &arg.value_text);
        source_names.sort();
        source_names.dedup();
        if source_names.is_empty() {
            continue;
        }
        out.push(FlowEvent::Assign {
            span: span_of(file, &lambda),
            target: param,
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names,
            declares_new_binding: false,
            value_kind: None,
        });
    }
}

fn emit_inline_closure_param_bindings(
    lambda: Node<'_>,
    file: FileId,
    src: &[u8],
    source_names: &[String],
    out: &mut Vec<FlowEvent>,
) {
    emit_inline_closure_param_bindings_with_extra_sources(lambda, file, src, source_names, &[], out);
}

fn emit_inline_closure_param_bindings_with_extra_sources(
    lambda: Node<'_>,
    file: FileId,
    src: &[u8],
    source_names: &[String],
    extra_param_sources: &[(String, Vec<String>)],
    out: &mut Vec<FlowEvent>,
) {
    let params = extract_param_names(&lambda, src);
    // H11: a single-param Kotlin lambda omits the param list and refers to
    // the implicit `it`. Synthesize it so `xs.forEach { sink(it) }` and
    // `tainted.let { sink(it) }` seed `it` from the receiver/source.
    let params = if params.is_empty() {
        if matches!(lambda.kind(), "lambda_literal" | "annotated_lambda") {
            vec!["it".to_string()]
        } else {
            return;
        }
    } else {
        params
    };
    for param in params {
        if param.is_empty() {
            continue;
        }
        let mut sources = source_names.to_vec();
        if let Some((_, extra_sources)) = extra_param_sources
            .iter()
            .find(|(extra_param, _)| extra_param == &param)
        {
            sources.extend(extra_sources.iter().cloned());
        }
        sources.sort();
        sources.dedup();
        if sources.is_empty() {
            continue;
        }
        out.push(FlowEvent::Assign {
            span: span_of(file, &lambda),
            target: param,
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: sources.clone(),
            declares_new_binding: false,
            value_kind: None,
        });
    }
}

fn inline_closure_param_extra_sources(
    call_event: Option<&FlowEvent>,
    lambda: Node<'_>,
    src: &[u8],
) -> Vec<(String, Vec<String>)> {
    let Some(FlowEvent::Call { name, .. }) = call_event else {
        return Vec::new();
    };
    if !call_is_trpc_procedure_handler(name) {
        return Vec::new();
    }
    extract_param_names(&lambda, src)
        .into_iter()
        .filter(|param| param == "input")
        .map(|param| (param, vec!["trpc.input".to_string()]))
        .collect()
}

fn call_is_trpc_procedure_handler(name: &str) -> bool {
    let compact: String = name.chars().filter(|ch| !ch.is_whitespace()).collect();
    (compact.ends_with(".query") || compact.ends_with(".mutation") || compact.ends_with(".subscription"))
        && compact.contains(".procedure")
        && compact.contains(".input(")
}

fn emit_inline_closure_param_bindings_from_yield_call(
    lambda: Node<'_>,
    file: FileId,
    src: &[u8],
    call_event: Option<&FlowEvent>,
    out: &mut Vec<FlowEvent>,
) {
    let Some(FlowEvent::Call { name, args, .. }) = call_event else {
        return;
    };
    let params = extract_param_names(&lambda, src);
    if params.is_empty() {
        return;
    }
    let source_call_args: Vec<String> = args.iter().map(|arg| arg.value_text.clone()).collect();
    for param in params {
        if param.is_empty() {
            continue;
        }
        out.push(FlowEvent::Assign {
            span: span_of(file, &lambda),
            target: param,
            source_name: None,
            source_call: Some(name.clone()),
            source_call_args: source_call_args.clone(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(crate::AssignValueKind::YieldResult),
        });
    }
}

fn ruby_call_block_uses_yield_result(call: &Node<'_>, block: &Node<'_>, src: &[u8]) -> bool {
    call.kind() == "call"
        && matches!(block.kind(), "block" | "do_block")
        && elixir_call_name(call, src).is_none()
}

fn call_event_value_source_names(event: &FlowEvent) -> Vec<String> {
    let FlowEvent::Call { receiver, args, .. } = event else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(receiver) = receiver.as_deref().and_then(receiver_base_from_text) {
        push_receiver_base_variants(&mut out, &receiver);
    }
    for arg in args {
        if let Some(place) = arg.place.as_deref() {
            push_value_text_source_name(&mut out, place);
        }
        push_value_text_source_name(&mut out, &arg.value_text);
        for source in &arg.source_names {
            push_value_text_source_name(&mut out, source);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn push_value_text_source_name(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    if let Some(base) = receiver_base_from_text(value) {
        push_receiver_base_variants(out, &base);
        return;
    }
    let cleaned = value.trim_start_matches('$');
    if looks_like_bare_identifier(cleaned) {
        out.push(cleaned.to_string());
        if cleaned != value {
            out.push(value.to_string());
        }
    }
}

/// Walk a lambda-like node's body into `out`. Bypasses the is_lambda
/// short-circuit so callers can inline closures passed as higher-order
/// function arguments (e.g. `xs.forEach { x -> body }` — the body's
/// calls belong to the enclosing function's flow).
///
/// Handles wrapper kinds that nest the real body: Kotlin's
/// `annotated_lambda` wraps a `lambda_literal`; Ruby's `block` /
/// `do_block` is the body itself.
fn walk_lambda_body(
    lambda: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
    out: &mut Vec<FlowEvent>,
) {
    // If this wrapper contains an inner lambda_literal / closure_expression,
    // descend into it.
    let inner = {
        let mut cursor = lambda.walk();
        let mut inner: Option<Node<'_>> = None;
        for child in lambda.named_children(&mut cursor) {
            match child.kind() {
                "lambda_literal" | "closure_expression" | "lambda_expression" => {
                    inner = Some(child);
                    break;
                }
                _ => {}
            }
        }
        inner
    };
    let body_node = inner.unwrap_or(lambda);
    let mut cursor = body_node.walk();
    for child in body_node.named_children(&mut cursor) {
        // Skip parameter lists / capture specs; walk body statements.
        if child.kind().contains("parameter") || child.kind().contains("capture") {
            continue;
        }
        walk_into(child, file, src, handler, class_names, out, false);
    }
}

/// Last named child of a node, optionally excluding a specific node
/// (typically the already-identified target). Used as a fallback RHS
/// finder when the grammar doesn't expose `right`/`value` fields.
fn last_named_child_excluding<'tree>(
    node: &Node<'tree>,
    exclude: Option<Node<'tree>>,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let mut last: Option<Node<'tree>> = None;
    for child in node.named_children(&mut cursor) {
        if let Some(ex) = exclude {
            if child.id() == ex.id() {
                continue;
            }
        }
        last = Some(child);
    }
    last
}

fn assignment_wrapper_has_variable_declarator(kind: &str, node: &Node<'_>) -> bool {
    if kind == "variable_declaration" {
        return first_named_child_of_kind(node, "variable_declarator").is_some();
    }
    if kind == "local_declaration_statement" {
        return first_named_child_of_kind(node, "variable_declaration")
            .and_then(|decl| first_named_child_of_kind(&decl, "variable_declarator"))
            .is_some();
    }
    false
}

/// First named child whose text isn't a binding-declaration keyword
/// (`val` / `var` / `let` / `const` / `auto`). Kotlin / Swift /
/// etc. emit those keywords as visible named nodes — picking the
/// literal keyword as a target name would be wrong.
fn first_non_keyword_named_child<'tree>(node: &Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    const KEYWORDS: &[&str] = &["val", "var", "let", "const", "auto", "type"];
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let text = node_text(&child, src).trim();
        if KEYWORDS.contains(&text) {
            continue;
        }
        return Some(child);
    }
    None
}

/// For an anonymous C/C++ struct inside `typedef struct { ... } Name;`
/// the struct_specifier itself has no name child — the typedef's
/// name sits on a sibling `type_identifier` at the parent
/// `type_definition` level. Walk up and find that sibling so the
/// anonymous-struct typedef form is still indexed as a class.
fn anonymous_struct_typedef_name<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    let parent = node.parent()?;
    let parent_kind = parent.kind();
    if parent_kind != "type_definition" && parent_kind != "typedef_declaration" {
        return None;
    }
    let mut cursor = parent.walk();
    for child in parent.named_children(&mut cursor) {
        if child.kind() == "type_identifier" || child.kind() == "identifier" {
            return Some(child);
        }
    }
    None
}

fn nearest_class_owner_span<'tree>(node: &Node<'tree>, handler: &GrammarHandler) -> Option<Node<'tree>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        let kind = candidate.kind();
        if handler.class_kinds.contains(&kind) {
            return Some(candidate);
        }
        if handler.fn_kinds.contains(&kind) || handler.lambda_kinds.contains(&kind) {
            return None;
        }
        parent = candidate.parent();
    }
    None
}

fn lambda_is_inlined_call_argument(node: &Node<'_>, handler: &GrammarHandler) -> bool {
    // Collection / property-literal containers that hold the lambda as a
    // VALUE rather than passing it directly as a call argument. A lambda
    // nested inside one of these — e.g. a config-object route handler
    // `server.route({ handler: (request) => { ... } })` (Hapi), or a
    // callback stored in an array literal — is NOT inlined by the
    // direct-call-argument path (`walk_lambda_body`), so it must keep its
    // own Pass-2b decl; otherwise its body is never walked and every
    // source/sink inside it is invisible. Stop the upward scan here and
    // report "not an inlined argument" so the decl survives.
    const VALUE_CONTAINER_KINDS: &[&str] = &["object", "pair", "array", "object_literal", "array_literal"];
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        let kind = candidate.kind();
        if VALUE_CONTAINER_KINDS.contains(&kind) {
            return false;
        }
        if handler.is_call(kind) {
            return true;
        }
        if handler.fn_kinds.contains(&kind)
            || handler.class_kinds.contains(&kind)
            || handler.lambda_kinds.contains(&kind)
        {
            return false;
        }
        parent = candidate.parent();
    }
    false
}

/// Find the first named child of a call-expression node that names the
/// callee — typically a `navigation_expression`, `member_expression`,
/// `field_expression`, `scoped_identifier`, or bare `identifier`. Skips
/// argument-list children (`arguments`, `value_arguments`, etc.) and
/// type-argument children so dotted method calls surface as the whole
/// dotted path rather than the leftmost receiver.
fn first_callee_expression_child<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    const SKIP_KINDS: &[&str] = &[
        "arguments",
        "argument_list",
        "value_arguments",
        "type_arguments",
        "type_argument_list",
        "lambda_literal",
        "annotated_lambda",
        "call_suffix",
    ];
    const CALLEE_KINDS: &[&str] = &[
        // Dotted / member accesses across grammars:
        "navigation_expression",    // kotlin
        "member_expression",        // js/ts
        "member_access_expression", // php / c# (sometimes)
        "field_expression",         // rust / go / c / c++
        "field_access",             // java
        "selector_expression",      // go
        "scoped_identifier",        // rust / c++
        "scoped_call_expression",
        "qualified_identifier",
        "dotted_name",        // python
        "attribute",          // python `a.b`
        "prefix_expression",  // swift
        "postfix_expression", // swift — often wraps dotted chains
        "generic_type",
        // Bare identifiers:
        "identifier",
        "simple_identifier", // kotlin
        "type_identifier",
        "property_identifier", // js/ts
    ];
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let kind = child.kind();
        if SKIP_KINDS.contains(&kind) {
            continue;
        }
        if CALLEE_KINDS.contains(&kind) || kind.ends_with("identifier") || kind.ends_with("expression") {
            return Some(child);
        }
    }
    None
}

fn erlang_remote_callee<'tree>(node: &Node<'tree>, src: &[u8]) -> Option<(Node<'tree>, String)> {
    if node.kind() != "remote" {
        return None;
    }
    let module = node.child_by_field_name("module")?;
    let fun = node.child_by_field_name("fun")?;
    let callee_node = fun
        .child_by_field_name("expr")
        .or_else(|| fun.child_by_field_name("name"))
        .or_else(|| first_identifier_like_child(&fun))
        .or_else(|| first_identifier_descendant(fun))
        .unwrap_or(fun);
    let module_text = node_text(&module, src).trim_end_matches(':').trim();
    let fun_text = node_text(&callee_node, src).trim();
    if module_text.is_empty() || fun_text.is_empty() {
        return None;
    }
    Some((callee_node, format!("{module_text}:{fun_text}")))
}

fn erlang_remote_args_node<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    if node.kind() != "remote" {
        return None;
    }
    let fun = node.child_by_field_name("fun")?;
    let call = if fun.kind() == "call" {
        fun
    } else {
        first_named_child_of_kind(&fun, "call")?
    };
    call.child_by_field_name("args")
}

/// Apply file-path-based qualified_name and module_path to every
/// Decl in `idx` that hasn't already had them populated. This is
/// the simple form of the semantic-identity contract for languages
/// without a real module / namespace boundary (C, C++ outside named
/// namespaces, Lua, Bash) — see
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
///
/// Adapters with real module syntax (Java packages, Rust crates,
/// Go packages, Python modules) should compute qualified_name and
/// module_path from real syntax instead of calling this helper.
pub fn apply_file_stem_semantic_identity(idx: &mut crate::DeclIndex, ctx: &AdapterContext<'_>) {
    // Prefer the full workspace-relative path (extension stripped)
    // so `a/executor.c` and `b/executor.c` remain different
    // semantic modules. Fall back to the absolute path for adapter
    // unit tests that do not provide a workspace root.
    let Some(module_segments) = file_module_segments(idx.file, ctx) else {
        return;
    };
    let module_path = crate::ModulePath::from_segments(module_segments.iter().cloned());
    let prefix = module_segments.join("::");
    for decl in &mut idx.defs {
        if decl.qualified_name.is_none() {
            decl.qualified_name = Some(format!("{prefix}::{}", decl.name));
        }
        if decl.module_path.is_empty() {
            decl.module_path = module_path.clone();
        }
    }
}

fn file_module_segments(file: FileId, ctx: &AdapterContext<'_>) -> Option<Vec<String>> {
    let path = ctx
        .workspace_relative_path(file)
        .or_else(|| ctx.vfs.path(file).ok().map(|p| (*p).clone()))?;
    let mut segments = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        let text = part.to_string_lossy();
        if text.is_empty() {
            continue;
        }
        segments.push(text.into_owned());
    }
    let last = segments.last_mut()?;
    let stripped = strip_extension(last);
    *last = stripped.to_string();
    segments.retain(|segment| !segment.is_empty());
    (!segments.is_empty()).then_some(segments)
}

/// Prefix package/namespace module identity with the workspace-relative
/// project path when one is present. Imports still resolve because the
/// resolver suffix-matches package targets, while same-package visibility
/// remains scoped to the concrete sibling project.
#[must_use]
pub fn package_module_segments_with_workspace_prefix<I, S>(
    file: FileId,
    ctx: &AdapterContext<'_>,
    package_segments: I,
) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let package_segments = package_segments
        .into_iter()
        .map(Into::into)
        .collect::<Vec<String>>();
    if package_segments.is_empty() {
        return Vec::new();
    }
    let Some(relative) = ctx.workspace_relative_path(file) else {
        return package_segments;
    };
    let mut prefix = relative.parent().map(path_components).unwrap_or_default();
    strip_suffix_segments(&mut prefix, &package_segments);
    strip_known_source_root_suffix(&mut prefix);
    let mut out = prefix
        .into_iter()
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    out.extend(package_segments);
    out
}

fn path_components(path: &std::path::Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => {
                let text = part.to_string_lossy();
                (!text.is_empty()).then(|| text.into_owned())
            }
            _ => None,
        })
        .collect()
}

fn strip_suffix_segments(segments: &mut Vec<String>, suffix: &[String]) {
    if suffix.is_empty() || suffix.len() > segments.len() {
        return;
    }
    let start = segments.len() - suffix.len();
    if segments[start..]
        .iter()
        .zip(suffix.iter())
        .all(|(left, right)| left == right)
    {
        segments.truncate(start);
    }
}

fn strip_known_source_root_suffix(segments: &mut Vec<String>) {
    const SOURCE_ROOTS: &[&[&str]] = &[
        &["src", "main", "java"],
        &["src", "test", "java"],
        &["src", "main", "kotlin"],
        &["src", "test", "kotlin"],
        &["src", "main", "scala"],
        &["src", "test", "scala"],
        &["src", "java"],
        &["src", "kotlin"],
        &["src", "scala"],
    ];
    for root in SOURCE_ROOTS {
        if root.len() > segments.len() {
            continue;
        }
        let start = segments.len() - root.len();
        if segments[start..]
            .iter()
            .zip(root.iter())
            .all(|(left, right)| left == right)
        {
            segments.truncate(start);
            return;
        }
    }
}

fn strip_extension(part: &str) -> &str {
    part.rsplit_once('.').map_or(part, |(stem, _)| stem)
}

/// Apply dotted-segment qualified_name and module_path to every
/// Decl in `idx` that hasn't already had them populated. Used by
/// languages with a real module syntax: callers compute the
/// dotted module path (e.g. `["foo", "bar"]` for `foo.bar`) from
/// language-specific syntax (Java `package`, Python module from
/// file path under workspace, Go `package`, Rust crate + `mod`
/// chain) and the helper handles the rest.
///
/// `qualified_name` becomes `<module_segments_joined_by_dot>.<name>`
/// when segments are non-empty, else just `<name>`.
pub fn apply_module_path_semantic_identity(idx: &mut crate::DeclIndex, module_segments: Vec<String>) {
    let module_path = crate::ModulePath::from_segments(module_segments.iter().cloned());
    let prefix = module_segments.join(".");
    for decl in &mut idx.defs {
        if decl.qualified_name.is_none() {
            decl.qualified_name = Some(if prefix.is_empty() {
                decl.name.clone()
            } else {
                format!("{prefix}.{}", decl.name)
            });
        }
        if decl.module_path.is_empty() {
            decl.module_path = module_path.clone();
        }
    }
}

/// Derive `self.<field> → Type` bindings from each class's
/// constructor / setter `receiver_field_writes` and propagate them
/// to every sibling method's `type_aliases`. Runs at index time so
/// the resolver's per-call `type_alias_for_receiver` lookup is O(1)
/// against the method's own `type_aliases` instead of re-walking the
/// constructor every time a `self.<field>.method()` call needs to
/// dispatch.
///
/// Adapters call this AFTER the per-method type_aliases have been
/// populated (parameter types, etc.) — the helper consumes those to
/// resolve each `receiver_field_write`'s source-parameter index to
/// a type name. Idempotent: re-applying produces no new bindings.
///
/// Example: for Python `class Transaction: def __init__(self,
/// runner: CommandRunner): self.runner = runner`, the helper records
/// `{name: "self.runner", type_name: "CommandRunner"}` on every
/// method of `Transaction`, including `__init__` itself. The
/// resolver's `type_alias_for_receiver(perform_decl, "self.runner")`
/// then returns `CommandRunner` directly.
pub fn apply_class_field_type_aliases(idx: &mut crate::DeclIndex) {
    use std::collections::{HashMap, HashSet};
    let mut by_class: HashMap<bonsai_common::SymbolId, Vec<crate::TypeAliasBinding>> = HashMap::new();
    let mut seen: HashMap<bonsai_common::SymbolId, HashSet<(String, String)>> = HashMap::new();
    for decl in &idx.defs {
        let Some(parent_sym) = decl.parent else { continue };
        if !matches!(
            decl.kind,
            crate::DeclKind::Function | crate::DeclKind::Method | crate::DeclKind::Constructor
        ) {
            continue;
        }
        for field_write in &decl.receiver_field_writes {
            for &param_idx in &field_write.source_param_indices {
                let Some(param_name) = decl.params.get(param_idx) else {
                    continue;
                };
                let Some(alias) = decl.type_aliases.iter().find(|a| a.name == *param_name) else {
                    continue;
                };
                let key = (field_write.target.clone(), alias.type_name.clone());
                if seen.entry(parent_sym).or_default().insert(key.clone()) {
                    by_class
                        .entry(parent_sym)
                        .or_default()
                        .push(crate::TypeAliasBinding {
                            name: key.0,
                            type_name: key.1,
                        });
                }
            }
        }
    }
    if by_class.is_empty() {
        return;
    }
    for decl in &mut idx.defs {
        let Some(parent_sym) = decl.parent else { continue };
        if !matches!(
            decl.kind,
            crate::DeclKind::Function | crate::DeclKind::Method | crate::DeclKind::Constructor
        ) {
            continue;
        }
        let Some(class_aliases) = by_class.get(&parent_sym) else {
            continue;
        };
        for alias in class_aliases {
            if !decl.type_aliases.contains(alias) {
                decl.type_aliases.push(alias.clone());
            }
        }
    }
}

/// Heuristically classify the RHS shape of every
/// `FlowEvent::Assign` whose `value_kind` is still `None`. Engine-
/// driven Phase-5 const-propagation reads `value_kind` to decide
/// whether the write is a "clean overwrite" (literal RHS — no
/// identifier carriers reach it) or a name-bridging carrier
/// (anything that references an identifier).
///
/// Adapters can set `value_kind` themselves at construction time
/// when their CST surface gives them exact info; this pass is the
/// safety net for adapters that don't. The classification is
/// conservative — when the adapter recorded no `source_name`,
/// `source_call`, `source_names`, or `source_call_args`, the RHS
/// has no identifier carriers and is treated as `Literal`. When
/// `source_call` is set, the RHS is a call (`CallResult`).
/// Everything else is `Compound`. The pass runs after
/// `apply_call_receiver_types` so the classification reflects
/// the post-stitch event tree.
pub fn apply_assign_value_kind(idx: &mut crate::DeclIndex) {
    for decl in &mut idx.defs {
        classify_assign_value_kinds(&mut decl.flow_events);
    }
}

/// Adapter-independent enforcement that flow facts come only from
/// syntactically correct code. `error_spans` are the parser's ERROR /
/// MISSING node spans for this file; every decl that overlaps one
/// loses its flow events (and the receiver facts derived from them).
/// The synthetic `__module__` decl spans the whole file, so it is
/// gated only by errors OUTSIDE every real decl — a broken function
/// must not strip valid module-scope facts, and vice versa.
///
/// The shared kit walker already skips broken callables during
/// extraction; this backstop covers adapter-specific augment passes
/// that synthesize events from their own tree walks.
pub fn strip_syntax_broken_flow_events(idx: &mut crate::DeclIndex, error_spans: &[Span]) {
    if error_spans.is_empty() {
        return;
    }
    let contains = |outer: Span, err: Span| outer.start <= err.start && err.end <= outer.end;
    let decl_spans: Vec<Span> = idx
        .defs
        .iter()
        .filter(|decl| decl.name != MODULE_DECL_NAME)
        .map(|decl| decl.span)
        .collect();
    for decl in &mut idx.defs {
        let broken = if decl.name == MODULE_DECL_NAME {
            error_spans
                .iter()
                .any(|err| !decl_spans.iter().any(|span| contains(*span, *err)))
        } else {
            // Overlap, not containment: zero-width MISSING spans sit
            // between tokens and recovered ERROR nodes can extend past
            // a decl's recognized boundary.
            error_spans.iter().any(|err| {
                err.start < decl.span.end && decl.span.start < err.end || contains(decl.span, *err)
            })
        };
        if broken {
            decl.flow_events.clear();
            decl.receiver_field_writes.clear();
            decl.receiver_state_sources.clear();
        }
    }
}

/// Name of the synthetic module-scope decl emitted in Pass 4 of
/// [`decl_index_with_handler`].
const MODULE_DECL_NAME: &str = "__module__";

/// Emit exact local callable-alias facts for C-family function-pointer
/// declarations such as `void (*cb)(char*) = helper;`.
///
/// The generic assignment walker must stay conservative because
/// declaration nodes often include type/declarator identifiers in
/// `source_names`. Here the CST proves the LHS is a function-pointer
/// declarator and the RHS is a bare identifier, so the alias fact is a
/// precise callable binding rather than a name-only fallback.
pub fn inject_c_family_function_pointer_aliases(
    idx: &mut crate::DeclIndex,
    tree: &tree_sitter::Tree,
    src: &[u8],
    file: FileId,
) {
    let aliases = collect_kinds(tree, &["init_declarator"])
        .into_iter()
        .filter_map(|node| c_family_function_pointer_alias(&node, src, file))
        .collect::<Vec<_>>();
    if aliases.is_empty() {
        return;
    }

    for (span, target, source) in aliases {
        for decl in &mut idx.defs {
            let owner_span = decl.body_span.unwrap_or(decl.span);
            if !span_contains(owner_span, span) && !span_contains(decl.span, span) {
                continue;
            }
            if flow_events_contain_callable_alias(&decl.flow_events, span, &target, &source) {
                break;
            }
            decl.flow_events.push(FlowEvent::Assign {
                span,
                target,
                source_name: Some(source),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: true,
                value_kind: Some(crate::AssignValueKind::Compound),
            });
            break;
        }
    }
}

fn c_family_function_pointer_alias(
    node: &Node<'_>,
    src: &[u8],
    file: FileId,
) -> Option<(Span, String, String)> {
    let declarator = node.child_by_field_name("declarator")?;
    if !c_family_declarator_is_function_pointer(&declarator) {
        return None;
    }
    let target = first_identifier_descendant(declarator)
        .map(|n| node_text(&n, src).trim().to_string())
        .filter(|name| !name.is_empty())?;
    let value = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("right"))?;
    let source = node_text(&value, src).trim().to_string();
    if !looks_like_bare_identifier(&source) || same_identifier_name(&target, &source) {
        return None;
    }
    Some((span_of(file, node), target, source))
}

/// Rewrite syntax-proven callable-reference assignments into the
/// canonical local callable-alias shape consumed by the callgraph and
/// taint engines.
///
/// This is intentionally syntax-only. It recognizes language surfaces
/// that pass a callable value instead of invoking it (`this::helper`,
/// `&helper/1`, `method(:helper)`, qualified callable paths, etc.) and
/// leaves resolution to the semantic resolver. Plain identifier aliases
/// such as `cb = helper` already come from the generic assignment
/// walker, so this helper only fills gaps where the original HIR looks
/// like a literal or call-result despite being a callable value.
pub fn inject_callable_reference_aliases_from_source(events: &mut [FlowEvent], source: &str) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } => {
                let Some(rhs) = assignment_rhs_from_span(source, *span) else {
                    continue;
                };
                if !rhs_is_non_bare_callable_reference(rhs) {
                    continue;
                }
                *source_name = Some(rhs.to_string());
                *source_call = None;
                source_call_args.clear();
                source_names.clear();
                *value_kind = Some(crate::AssignValueKind::Compound);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_callable_reference_aliases_from_source(then_events, source);
                inject_callable_reference_aliases_from_source(else_events, source);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_callable_reference_aliases_from_source(body, source);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_callable_reference_aliases_from_source(body, source);
                inject_callable_reference_aliases_from_source(catch_events, source);
                inject_callable_reference_aliases_from_source(finally_events, source);
            }
            _ => {}
        }
    }
}

/// Extract formal parameter names from common anonymous callable
/// surface syntax. This is intentionally syntax-level and
/// language-agnostic: it recognizes lambda/closure delimiters such as
/// `x => ...`, `{ x: T -> ... }`, `{ (x: T) in ... }`, `|x| ...`,
/// `function(x) { ... }`, and `^(T x) { ... }`.
pub fn callable_param_names_from_text(text: &str) -> Vec<String> {
    let text = text.trim().trim_end_matches(';').trim();
    if text.is_empty() {
        return Vec::new();
    }

    let segment = if let Some(rest) = text.strip_prefix("lambda ") {
        rest.split_once(':').map(|(params, _)| params)
    } else if let Some(rest) = text.strip_prefix("fn ") {
        rest.split_once("->").map(|(params, _)| params)
    } else if text.starts_with("function")
        || text.starts_with("func ")
        || text.starts_with("sub ")
        || text.starts_with("->")
        || text.starts_with('^')
    {
        first_parenthesized_segment(text)
    } else if let Some(rest) = text.strip_prefix('|') {
        rest.split_once('|').map(|(params, _)| params)
    } else if text.starts_with('{') {
        text.split_once("->")
            .map(|(params, _)| params.trim_start_matches('{').trim())
            .or_else(|| {
                text.split_once(" in ")
                    .map(|(params, _)| params.trim_start_matches('{').trim())
            })
    } else {
        text.split_once("=>")
            .map(|(params, _)| params)
            .or_else(|| text.split_once("->").map(|(params, _)| params))
            .or_else(|| {
                text.starts_with('(')
                    .then(|| first_parenthesized_segment(text))
                    .flatten()
            })
    };

    segment.map(param_names_from_segment).unwrap_or_default()
}

fn first_parenthesized_segment(text: &str) -> Option<&str> {
    let open = text.find('(')?;
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text[open..].char_indices() {
        let absolute = open + idx;
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return text.get(open + 1..absolute);
                }
            }
            _ => {}
        }
    }
    None
}

fn param_names_from_segment(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    for piece in split_top_level_commas(segment) {
        if let Some(name) = param_name_from_piece(&piece) {
            if !out.iter().any(|existing| existing == &name) {
                out.push(name);
            }
        }
    }
    out
}

fn split_top_level_commas(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(text[start..idx].to_string());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(text[start..].to_string());
    parts
}

fn param_name_from_piece(piece: &str) -> Option<String> {
    if piece.trim() == "..." {
        return Some(SYNTHETIC_VARARGS_PARAM.to_string());
    }
    let mut piece = piece
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .trim_start_matches("mut ")
        .trim_start_matches("ref ")
        .trim_start_matches("inout ")
        .trim_start_matches("required ")
        .trim()
        .trim_start_matches("...")
        .trim();
    if piece.is_empty() || piece == "_" {
        return None;
    }
    if let Some((before, _)) = piece.split_once('=') {
        piece = before.trim();
    }
    if let Some((before, _)) = piece.split_once(':') {
        piece = before.trim();
    }
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in piece.chars() {
        if ch == '$' || ch == '_' || ch.is_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens.into_iter().rev().find(|token| {
        let bare = token.trim_start_matches('$');
        !bare.is_empty()
            && bare != "_"
            && looks_like_bare_identifier(bare)
            && !matches!(
                bare,
                "const" | "var" | "let" | "final" | "void" | "func" | "function"
            )
    })
}

fn assignment_rhs_from_span(source: &str, span: Span) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?.min(source.len());
    let end = usize::try_from(span.end).ok()?.min(source.len());
    if start >= end || !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return None;
    }
    let text = source.get(start..end)?;
    let rhs = assignment_rhs_text(text)?.trim();
    Some(rhs.trim_end_matches(';').trim())
}

fn rhs_is_non_bare_callable_reference(rhs: &str) -> bool {
    let rhs = rhs.trim();
    if rhs.is_empty() {
        return false;
    }
    // A quoted bare word is first a data literal. Treating every
    // `"abc"` / `'abc'` assignment as a callable alias pollutes
    // FlowEvent source slots and prevents literal overwrites from
    // being classified as clean writes. Quoted callback strings in
    // actual call arguments are still handled by
    // `callable_reference_variants` at the call site; assignment-level
    // aliasing requires explicit callable-reference syntax.
    if quoted_bare_word(rhs) {
        return false;
    }
    if !rhs_has_explicit_callable_reference_syntax(rhs) {
        return false;
    }
    let variants = bonsai_common::callable_reference_variants(rhs);
    variants
        .iter()
        .any(|variant| variant.trim() != rhs && looks_like_bare_identifier(variant.trim()))
}

fn rhs_has_explicit_callable_reference_syntax(rhs: &str) -> bool {
    let rhs = rhs.trim();
    rhs.starts_with('&')
        || rhs.starts_with("\\&")
        || rhs.starts_with("fun ")
        || rhs.starts_with("method(")
        || rhs.contains("::")
        || rhs.ends_with('.')
        || rhs.ends_with("->")
}

fn quoted_bare_word(value: &str) -> bool {
    let value = value.trim();
    let Some(quote) = value.as_bytes().first().copied() else {
        return false;
    };
    if !matches!(quote, b'\'' | b'"' | b'`') || value.as_bytes().last().copied() != Some(quote) {
        return false;
    }
    let Some(inner) = value.get(1..value.len().saturating_sub(1)) else {
        return false;
    };
    looks_like_bare_identifier(inner.trim())
}

fn c_family_declarator_is_function_pointer(node: &Node<'_>) -> bool {
    if node.kind() == "function_declarator" && subtree_has_kind(node, "pointer_declarator") {
        return true;
    }
    let mut cursor = node.walk();
    let found = node
        .named_children(&mut cursor)
        .any(|child| c_family_declarator_is_function_pointer(&child));
    found
}

fn subtree_has_kind(node: &Node<'_>, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    let found = node
        .named_children(&mut cursor)
        .any(|child| subtree_has_kind(&child, kind));
    found
}

fn flow_events_contain_callable_alias(events: &[FlowEvent], span: Span, target: &str, source: &str) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Assign {
            span: existing_span,
            target: existing_target,
            source_name: Some(existing_source),
            source_call,
            source_names,
            value_kind,
            ..
        } => {
            *existing_span == span
                && existing_target == target
                && existing_source == source
                && source_call.is_none()
                && source_names.is_empty()
                && !matches!(
                    value_kind,
                    Some(crate::AssignValueKind::Literal | crate::AssignValueKind::CallResult)
                )
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            flow_events_contain_callable_alias(then_events, span, target, source)
                || flow_events_contain_callable_alias(else_events, span, target, source)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            flow_events_contain_callable_alias(body, span, target, source)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            flow_events_contain_callable_alias(body, span, target, source)
                || flow_events_contain_callable_alias(catch_events, span, target, source)
                || flow_events_contain_callable_alias(finally_events, span, target, source)
        }
        _ => false,
    })
}

/// Populate `Decl.return_type` for function-shaped decls by reading
/// the tree-sitter `return_type` / `type` field of the corresponding
/// CST node. Most grammars expose a named field for the return-type
/// annotation; this helper walks the function-node kinds declared by
/// `handler.fn_kinds` and assigns `return_type` when the field
/// resolves to a non-empty type node. Pure adapter facts — the
/// engine never interprets them. Idempotent: existing non-empty
/// return_type values are preserved.
pub fn populate_decl_return_types(
    decl_index: &mut crate::DeclIndex,
    tree: &tree_sitter::Tree,
    src: &[u8],
    handler: &GrammarHandler,
) {
    // Build a span → return_type map by walking the tree once.
    let mut by_span: std::collections::HashMap<bonsai_common::Span, String> =
        std::collections::HashMap::new();
    let mut stack = vec![tree.root_node()];
    let is_fn_kind = |k: &str| handler.fn_kinds.contains(&k) || GENERIC_HANDLER.fn_kinds.contains(&k);
    while let Some(node) = stack.pop() {
        if is_fn_kind(node.kind()) {
            if let Some(ty_node) = node
                .child_by_field_name("return_type")
                .or_else(|| node.child_by_field_name("type"))
                .or_else(|| node.child_by_field_name("result"))
            {
                let text = node_text(&ty_node, src).trim().to_string();
                if !text.is_empty() {
                    let span = bonsai_common::Span::new(
                        decl_index.file,
                        u64::try_from(node.start_byte()).unwrap_or(u64::MAX),
                        u64::try_from(node.end_byte()).unwrap_or(u64::MAX),
                    );
                    by_span.insert(span, canonical_simple_type_name(&text));
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    if by_span.is_empty() {
        return;
    }
    for decl in &mut decl_index.defs {
        if decl.return_type.is_some() {
            continue;
        }
        if let Some(rt) = by_span.get(&decl.span) {
            if !rt.is_empty() {
                decl.return_type = Some(rt.clone());
            }
        }
    }
}

/// The class name an assignment's RHS constructs, if its callee is
/// constructor-shaped: the bare tail after the last `.`/`::` separator
/// (dropping a leading `new`/generic args) when that tail is
/// `PascalCase`. `ldap3.Connection` → `Connection`, `new Foo<T>` →
/// `Foo`, `socket.socket` → `None` (lowercase tail, not a constructor),
/// `obj.method` → `None`. This is the language-agnostic convention used
/// for lightweight local type inference (`x = Pkg.Class(...)`), distinct
/// from the `new`-only `receiver_type_from_constructor_expr` used for
/// inline receiver expressions.
fn constructor_call_type_name(callee: &str) -> Option<String> {
    let expr = callee.trim().strip_prefix("new ").unwrap_or(callee.trim());
    let without_generics = expr.split('<').next().unwrap_or(expr);
    // Ruby / Crystal / Smalltalk-family `Foo.new` (and `Foo::new`):
    // the constructor is the `new` method ON the class, so the type is
    // the qualifier before `.new`, not the bare `new` tail. Only strip
    // it when a qualifier remains (the uppercase check below then
    // confirms it names a class), so a bare `new(...)` is unaffected.
    let constructor_target = without_generics
        .strip_suffix(".new")
        .or_else(|| without_generics.strip_suffix("::new"))
        .filter(|head| !head.is_empty())
        .unwrap_or(without_generics);
    let bare = constructor_target
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(constructor_target)
        .trim();
    if bare.is_empty() || !bare.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    // Reject SHOUTY_CONSTANT tails (`Foo.BAR(...)`) — those are not
    // constructor calls. A real class name has at least one lowercase
    // letter after the leading uppercase.
    if bare
        .chars()
        .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
    {
        return None;
    }
    Some(bare.to_string())
}

/// Collect `local -> ConstructedType` aliases from constructor-shaped
/// assignments (`conn = ldap3.Connection(server)`) in a callable's flow
/// events, so subsequent `conn.method(...)` calls carry a resolved
/// receiver type and `receiver_type_in` / `[Type, method]` rules match
/// without loosening any package gate. Walks branch / loop / try bodies
/// so a connection constructed inside control flow is still typed.
/// Language-agnostic; adapters opt in by merging the result into
/// `Decl.type_aliases` before the central receiver-type pass runs.
pub fn collect_constructor_result_type_aliases(
    events: &[crate::FlowEvent],
    out: &mut Vec<crate::TypeAliasBinding>,
) {
    for (index, event) in events.iter().enumerate() {
        match event {
            FlowEvent::Assign {
                target,
                source_call: Some(callee),
                ..
            } => {
                if target.is_empty() {
                    continue;
                }
                if let Some(type_name) = constructor_call_type_name(callee) {
                    out.push(crate::TypeAliasBinding {
                        name: target.clone(),
                        type_name,
                    });
                }
            }
            // JS/TS shape: `const client = new ApolloClient({})` reaches
            // the kit as an `Assign` with NO `source_call` (the grammar
            // emits `new_expression` as its own `Call` event) plus a
            // sibling `Call` for the constructor. Recover the receiver
            // type by matching a constructor `Call` whose span lies
            // inside the assignment's RHS, so `client.query(...)` carries
            // a resolved `ApolloClient` receiver type just like the
            // `source_call` languages.
            FlowEvent::Assign {
                target,
                source_call: None,
                source_name: None,
                span,
                ..
            } => {
                if target.is_empty() {
                    continue;
                }
                if let Some(type_name) = adjacent_constructor_call_type(events, index, *span) {
                    out.push(crate::TypeAliasBinding {
                        name: target.clone(),
                        type_name,
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_constructor_result_type_aliases(then_events, out);
                collect_constructor_result_type_aliases(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_constructor_result_type_aliases(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_constructor_result_type_aliases(body, out);
                collect_constructor_result_type_aliases(catch_events, out);
                collect_constructor_result_type_aliases(finally_events, out);
            }
            _ => {}
        }
    }
}

/// Find the constructor type for a `new`-expression RHS that the
/// grammar surfaced as a sibling `Call` event rather than the
/// assignment's `source_call` (the JS/TS shape). Scans `events` for a
/// constructor `Call` whose span lies strictly inside `assign_span`'s
/// RHS, preferring the leftmost (outermost) one so
/// `x = new Foo(new Bar())` resolves to `Foo`. Returns `None` when no
/// contained constructor call exists, so unrelated adjacent statements
/// (`x = compute(); Helper();`) never mistype `x`.
fn adjacent_constructor_call_type(
    events: &[crate::FlowEvent],
    assign_index: usize,
    assign_span: Span,
) -> Option<String> {
    let mut best: Option<(u64, String)> = None;
    for (idx, event) in events.iter().enumerate() {
        if idx == assign_index {
            continue;
        }
        let FlowEvent::Call { name, span, .. } = event else {
            continue;
        };
        // The constructor call must be the assignment's RHS: its span
        // sits within the assign span and starts after the LHS target.
        if span.file != assign_span.file || span.start <= assign_span.start || span.end > assign_span.end {
            continue;
        }
        if let Some(type_name) = constructor_call_type_name(name) {
            match &best {
                Some((best_start, _)) if *best_start <= span.start => {}
                _ => best = Some((span.start, type_name)),
            }
        }
    }
    best.map(|(_, type_name)| type_name)
}

/// Apply local constructor-result type inference across every decl in
/// an index: `conn = ldap3.Connection(server)` types `conn` as
/// `Connection`, `client = new ApolloClient()` types `client` as
/// `ApolloClient`, so subsequent `conn.search(...)` / `client.query(...)`
/// calls carry a resolved receiver type and `receiver_type_in` /
/// `[Type, method]` rules match semantically — the proper alternative to
/// loosening the package gate for receiver-variable calls. Runs
/// centrally (in the db/index decl-index builders) so every language
/// gets it without per-adapter wiring. Existing aliases (param
/// annotations, resolved call-result return types) take precedence over
/// an inferred constructor type for the same name.
pub fn apply_constructor_result_type_aliases(idx: &mut crate::DeclIndex) {
    for decl in &mut idx.defs {
        let mut ctor_aliases = Vec::new();
        collect_constructor_result_type_aliases(&decl.flow_events, &mut ctor_aliases);
        for binding in ctor_aliases {
            if !decl.type_aliases.iter().any(|alias| alias.name == binding.name) {
                decl.type_aliases.push(binding);
            }
        }
    }
}

/// Propagate adapter-extracted `Decl.return_type` onto LHS
/// type_aliases for `let y = f()` shaped assignments. Phase-6
/// lightweight type inference — when the callee's return type is
/// known, the LHS gains a type alias entry so subsequent
/// `y.method()` calls resolve to the right class's method set
/// without re-walking the source. Only fires when:
///   * The assignment is a direct call (`source_call: Some(callee)`).
///   * The callee resolves to a Decl with a non-empty `return_type`.
///   * The LHS has no existing alias for `target` (don't clobber
///     adapter-supplied annotations).
///
/// The lookup is name-based (callee shortname matched against decl
/// names in the same index). Out-of-file callees fall through —
/// cross-file inference is a future deliverable.
pub fn apply_assign_call_result_types(idx: &mut crate::DeclIndex) {
    use std::collections::HashMap;
    // Build callee_name → return_type map.
    let mut returns: HashMap<String, String> = HashMap::new();
    // M9: fail closed on ambiguity. Two same-named functions/overloads with
    // differing return types make a name-only `let y = make()` type lookup
    // unknowable; drop the name entirely rather than stamp a last-writer-
    // wins (wrong) alias that drives bogus [Type, method] matching.
    let mut ambiguous: std::collections::HashSet<String> = std::collections::HashSet::new();
    for decl in &idx.defs {
        if let Some(rt) = &decl.return_type {
            if !rt.is_empty() {
                match returns.get(decl.name.as_str()) {
                    Some(existing) if existing != rt => {
                        ambiguous.insert(decl.name.clone());
                    }
                    _ => {
                        returns.insert(decl.name.clone(), rt.clone());
                    }
                }
            }
        }
    }
    for name in &ambiguous {
        returns.remove(name);
    }
    if returns.is_empty() {
        return;
    }
    // Drive per-decl rewriting. We can't simply mutate the
    // `flow_events` because `type_aliases` lives on the Decl itself
    // — we accumulate proposed (target, type_name) entries from the
    // events, then add them to the decl's `type_aliases` if absent.
    for decl in &mut idx.defs {
        let mut proposed: Vec<crate::TypeAliasBinding> = Vec::new();
        propose_call_result_type_aliases(&decl.flow_events, &returns, &mut proposed);
        if proposed.is_empty() {
            continue;
        }
        for binding in proposed {
            let already = decl
                .type_aliases
                .iter()
                .any(|existing| existing.name == binding.name);
            if !already {
                decl.type_aliases.push(binding);
            }
        }
    }
}

fn propose_call_result_type_aliases(
    events: &[FlowEvent],
    returns: &std::collections::HashMap<String, String>,
    out: &mut Vec<crate::TypeAliasBinding>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_call: Some(callee),
                ..
            } => {
                if target.is_empty() {
                    continue;
                }
                if let Some(rt) = returns.get(callee.as_str()) {
                    out.push(crate::TypeAliasBinding {
                        name: target.clone(),
                        type_name: rt.clone(),
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                propose_call_result_type_aliases(then_events, returns, out);
                propose_call_result_type_aliases(else_events, returns, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                propose_call_result_type_aliases(body, returns, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                propose_call_result_type_aliases(body, returns, out);
                propose_call_result_type_aliases(catch_events, returns, out);
                propose_call_result_type_aliases(finally_events, returns, out);
            }
            _ => {}
        }
    }
}

fn classify_assign_value_kinds(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                source_name,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                ..
            } => {
                if value_kind.is_some() {
                    continue;
                }
                let kind = if source_call.is_some() {
                    crate::AssignValueKind::CallResult
                } else if source_name.is_none() && source_names.is_empty() && source_call_args.is_empty() {
                    crate::AssignValueKind::Literal
                } else {
                    crate::AssignValueKind::Compound
                };
                *value_kind = Some(kind);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                classify_assign_value_kinds(then_events);
                classify_assign_value_kinds(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                classify_assign_value_kinds(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                classify_assign_value_kinds(body);
                classify_assign_value_kinds(catch_events);
                classify_assign_value_kinds(finally_events);
            }
            _ => {}
        }
    }
}

/// Populate `FlowEvent::Call::receiver_types` from adapter-emitted
/// semantic declaration facts. Adapters already attach
/// `Decl.type_aliases` for typed parameters, locals, fields, and
/// language-specific receiver bindings; this pass copies the relevant
/// type binding onto each method-call fact so callgraph, taint,
/// security matching, inspect, and export consume the same receiver
/// type evidence without receiver-name allowlists.
pub fn apply_call_receiver_types(idx: &mut crate::DeclIndex) {
    apply_call_receiver_types_with_super_tokens(idx, crate::capabilities::NO_SUPER_RECEIVER_TOKENS);
}

pub fn apply_call_receiver_types_with_super_tokens(
    idx: &mut crate::DeclIndex,
    super_receiver_tokens: &[&str],
) {
    // Two parallel indexes over the file's class-like decls:
    //
    //   * `by_symbol` keys on the SymbolId so the implicit-receiver
    //     lookup against `decl.parent` is O(1) instead of a linear
    //     scan per decl.
    //   * `by_canonical_name` keys on the canonicalised type-name so
    //     `receiver_projected_type_name` and the base-class walker
    //     can resolve "what class facts back this type name?" in O(1)
    //     too. The canonical key strips array suffixes / nullable
    //     marks so `Foo[]` and `Foo?` both hit the `Foo` entry.
    //
    // Pre-computing these once per file replaces what was previously
    // an O(call events × classes × inheritance levels) scan inside
    // every receiver-type derivation. Hot on Java / Kotlin /
    // TypeScript files where one class can hold hundreds of method
    // calls and the workspace has hundreds of class decls.
    let mut by_symbol: ahash::AHashMap<bonsai_common::SymbolId, (String, Vec<String>)> =
        ahash::AHashMap::new();
    let mut by_canonical_name: ahash::AHashMap<String, (String, Vec<String>)> = ahash::AHashMap::new();
    for decl in &idx.defs {
        if !matches!(
            decl.kind,
            crate::DeclKind::Class
                | crate::DeclKind::Struct
                | crate::DeclKind::Trait
                | crate::DeclKind::Interface
        ) {
            continue;
        }
        let entry = (decl.name.clone(), decl.bases.clone());
        by_symbol.insert(decl.symbol, entry.clone());
        // Multiple decls may share a canonical name (per-file shadow
        // classes in tests, for example) — first writer wins; the
        // existing linear `iter().find()` had the same first-match
        // semantic.
        by_canonical_name
            .entry(canonical_simple_type_name(&decl.name))
            .or_insert(entry);
    }
    let class_facts = ClassFactsIndex {
        by_symbol: &by_symbol,
        by_canonical_name: &by_canonical_name,
    };

    for decl in &mut idx.defs {
        let aliases = decl.type_aliases.clone();
        let implicit_receiver_types = decl.parent.and_then(|parent| {
            class_facts.by_symbol.get(&parent).map(|(name, bases)| {
                let mut types = Vec::with_capacity(1 + bases.len());
                push_unique_receiver_type(&mut types, name.clone());
                for base in bases {
                    push_unique_receiver_type(&mut types, base.clone());
                }
                types
            })
        });
        apply_call_receiver_types_to_events(
            &mut decl.flow_events,
            &aliases,
            implicit_receiver_types.as_deref(),
            &class_facts,
            super_receiver_tokens,
        );
    }
}

/// Index over a file's class-like decls, keyed both by `SymbolId`
/// (for parent-link lookups) and by canonicalised type name (for
/// receiver-expr matching). Built once per file in
/// [`apply_call_receiver_types`] and threaded through the
/// FlowEvent walk.
struct ClassFactsIndex<'a> {
    by_symbol: &'a ahash::AHashMap<bonsai_common::SymbolId, (String, Vec<String>)>,
    by_canonical_name: &'a ahash::AHashMap<String, (String, Vec<String>)>,
}

fn apply_call_receiver_types_to_events(
    events: &mut [FlowEvent],
    aliases: &[crate::TypeAliasBinding],
    implicit_receiver_types: Option<&[String]>,
    class_facts: &ClassFactsIndex<'_>,
    super_receiver_tokens: &[&str],
) {
    for event in events {
        match event {
            FlowEvent::Call {
                receiver,
                receiver_types,
                ..
            } => {
                if let Some(receiver) = receiver.as_deref() {
                    for ty in receiver_types_for_expr(
                        receiver,
                        aliases,
                        implicit_receiver_types,
                        class_facts,
                        super_receiver_tokens,
                    ) {
                        push_unique_receiver_type(receiver_types, ty);
                    }
                } else if let Some(types) = implicit_receiver_types {
                    // Bare-name call inside a class method body
                    // (`foo()` instead of `this.foo()`) is an
                    // implicit-self call across Java / Kotlin /
                    // C# / Scala / Swift / Python / Ruby. We fill
                    // `receiver_types` with the enclosing class
                    // and its bases so the resolver narrows
                    // dispatch the same way it does for explicit
                    // `this.foo()`. The narrowing isn't always
                    // accurate (free top-level functions called
                    // from within a method body inherit the
                    // class's type incorrectly), but the
                    // downstream resolver checks whether the
                    // callee actually exists on the class
                    // via Visibility + module_path gating, so
                    // over-fill at the receiver-type layer is
                    // bounded by that semantic check.
                    for ty in types {
                        push_unique_receiver_type(receiver_types, ty.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                apply_call_receiver_types_to_events(
                    then_events,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    super_receiver_tokens,
                );
                apply_call_receiver_types_to_events(
                    else_events,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    super_receiver_tokens,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_call_receiver_types_to_events(
                    body,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    super_receiver_tokens,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                apply_call_receiver_types_to_events(
                    body,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    super_receiver_tokens,
                );
                apply_call_receiver_types_to_events(
                    catch_events,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    super_receiver_tokens,
                );
                apply_call_receiver_types_to_events(
                    finally_events,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    super_receiver_tokens,
                );
            }
            FlowEvent::Assign { .. }
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

fn receiver_types_for_expr(
    receiver: &str,
    aliases: &[crate::TypeAliasBinding],
    implicit_receiver_types: Option<&[String]>,
    class_facts: &ClassFactsIndex<'_>,
    super_receiver_tokens: &[&str],
) -> Vec<String> {
    let normalized = normalize_receiver_type_expr(receiver);
    let tail = short_name_of(&normalized);
    let mut out = Vec::new();
    if let Some(inner) = receiver_class_object_inner_expr(&normalized) {
        for ty in receiver_types_for_expr(
            inner,
            aliases,
            implicit_receiver_types,
            class_facts,
            super_receiver_tokens,
        ) {
            push_unique_receiver_type(&mut out, ty);
        }
        if !out.is_empty() {
            return out;
        }
    }
    if let Some(projected_type) = receiver_projected_type_name(&normalized, class_facts) {
        push_receiver_type_and_bases(&mut out, projected_type, class_facts);
        return out;
    }
    if let Some(type_name) = receiver_type_from_constructor_expr(&normalized) {
        push_receiver_type_and_bases(&mut out, type_name, class_facts);
    }
    let has_member_projection = normalized.contains('.')
        || normalized.contains("->")
        || normalized.contains("::")
        || normalized.contains('\\');
    let projection_base = receiver_projection_base(&normalized);
    let base_is_implicit = matches!(projection_base, "this" | "self" | "super")
        || super_receiver_tokens.contains(&projection_base);
    // H7: an unguarded `alias.name == tail` types `pool.conn` (tail `conn`)
    // as whatever an unrelated local/param named `conn` is, a name-only FP.
    // Only fall back to the bare tail when there is no member projection, OR
    // the projection base is an implicit receiver (`this.field`/`self.field`)
    // where the tail genuinely names a field the alias map can resolve.
    let allow_bare_tail = !has_member_projection || base_is_implicit;
    for alias in aliases {
        if alias.name == normalized || (allow_bare_tail && alias.name == tail) {
            push_receiver_type_and_bases(&mut out, alias.type_name.clone(), class_facts);
        }
    }
    for alias in aliases {
        if receiver_projected_alias_matches(&normalized, &alias.name) {
            push_receiver_type_and_bases(&mut out, alias.type_name.clone(), class_facts);
        }
    }
    if matches!(tail, "self" | "this") {
        if let Some(types) = implicit_receiver_types {
            for ty in types {
                push_receiver_type_and_bases(&mut out, ty.clone(), class_facts);
            }
        }
    } else if super_receiver_tokens.contains(&tail) {
        if let Some(types) = implicit_receiver_types {
            for ty in types.iter().skip(1) {
                push_receiver_type_and_bases(&mut out, ty.clone(), class_facts);
            }
        }
    }
    out
}

fn receiver_class_object_inner_expr(receiver: &str) -> Option<&str> {
    let expr = receiver.trim();
    if let Some(inner) = expr.strip_prefix("type(").and_then(|rest| rest.strip_suffix(')')) {
        let inner = inner.trim();
        if !inner.is_empty() {
            return Some(inner);
        }
    }
    for suffix in [".__class__", ".class", ".constructor"] {
        if let Some(inner) = expr.strip_suffix(suffix) {
            let inner = inner.trim();
            if !inner.is_empty() {
                return Some(inner);
            }
        }
    }
    None
}

/// The leftmost token of a (possibly projected) receiver expression:
/// `this` for `this.conn`, `pool` for `pool.conn`, the whole string for a
/// bare identifier. Used to detect implicit-receiver bases so the bare-tail
/// alias fallback stays available for `this.field` / `self.field`.
fn receiver_projection_base(receiver: &str) -> &str {
    let receiver = receiver.trim();
    let mut end = receiver.len();
    for sep in [".", "->", "::", "\\"] {
        if let Some(idx) = receiver.find(sep) {
            end = end.min(idx);
        }
    }
    receiver[..end].trim()
}

fn receiver_projected_alias_matches(receiver: &str, alias_name: &str) -> bool {
    let receiver = receiver.trim();
    let alias_name = alias_name.trim();
    if receiver.is_empty() || alias_name.is_empty() || receiver == alias_name {
        return false;
    }
    let Some(tail) = receiver.strip_prefix(alias_name) else {
        return false;
    };
    let Some(rest) = tail.strip_prefix('.') else {
        return false;
    };
    let projection = rest.split('.').next().unwrap_or(rest);
    !projection.is_empty() && projection.chars().all(|ch| ch.is_ascii_digit())
}

fn receiver_projected_type_name(receiver: &str, class_facts: &ClassFactsIndex<'_>) -> Option<String> {
    let has_member_projection = receiver.contains('.')
        || receiver.contains("->")
        || receiver.contains("::")
        || receiver.contains('\\');
    if !has_member_projection {
        return None;
    }
    let tail = short_name_of(receiver)
        .trim_end_matches("()")
        .trim_matches(['&', '*', '$', '@', '%'])
        .to_string();
    if tail.is_empty() {
        return None;
    }
    let canonical_tail = canonical_simple_type_name(&tail);
    class_facts
        .by_canonical_name
        .get(&canonical_tail)
        .map(|(name, _)| name.clone())
}

fn push_receiver_type_and_bases(out: &mut Vec<String>, ty: String, class_facts: &ClassFactsIndex<'_>) {
    let mut seen = std::collections::BTreeSet::new();
    push_receiver_type_and_bases_inner(out, ty, class_facts, &mut seen);
}

fn push_receiver_type_and_bases_inner(
    out: &mut Vec<String>,
    ty: String,
    class_facts: &ClassFactsIndex<'_>,
    seen: &mut std::collections::BTreeSet<String>,
) {
    let canonical = canonical_simple_type_name(&ty);
    if canonical.is_empty() {
        return;
    }
    let first_canonical_visit = seen.insert(canonical.clone());
    if first_canonical_visit {
        push_unique_receiver_type(out, canonical.clone());
    }
    if let Some(qualified) = qualified_receiver_type_evidence(&ty, &canonical) {
        push_unique_receiver_type(out, qualified);
    }
    if !first_canonical_visit {
        return;
    }
    let Some((_, bases)) = class_facts.by_canonical_name.get(&canonical) else {
        return;
    };
    for base in bases {
        push_receiver_type_and_bases_inner(out, base.clone(), class_facts, seen);
    }
}

fn qualified_receiver_type_evidence(raw: &str, canonical: &str) -> Option<String> {
    let qualified = raw
        .trim()
        .trim_start_matches(['&', '*', '$', '@', '%'])
        .trim_end_matches("()")
        .trim();
    if qualified.is_empty() || qualified == canonical {
        return None;
    }
    let has_qualifier = qualified.contains('.')
        || qualified.contains("::")
        || qualified.contains('\\')
        || qualified.contains('/');
    has_qualifier.then(|| qualified.to_string())
}

fn receiver_type_from_constructor_expr(receiver: &str) -> Option<String> {
    let expr = receiver.trim();
    let rest = expr.strip_prefix("new ")?;
    let without_args = rest.split('(').next().unwrap_or(rest);
    let without_generics = without_args.split('<').next().unwrap_or(without_args);
    let bare = without_generics
        .rsplit('.')
        .next()
        .unwrap_or(without_generics)
        .trim();
    if bare.is_empty() || !bare.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    Some(without_generics.trim().to_string())
}

fn normalize_receiver_type_expr(receiver: &str) -> String {
    normalise_qualified_text(receiver)
        .trim()
        .trim_start_matches(['&', '*', '$', '@', '%'])
        .trim_end_matches("()")
        .trim_matches('.')
        .to_string()
}

fn push_unique_receiver_type(out: &mut Vec<String>, ty: String) {
    let trimmed = ty.trim();
    if trimmed.is_empty() {
        return;
    }
    if !out.iter().any(|existing| existing == trimmed) {
        out.push(trimmed.to_string());
    }
}

/// Per-language modifier-keyword vocabulary for the generic
/// `collect_modifier_visibility` helper. Adapters supply the
/// declaration node kinds to walk and the keyword-to-visibility
/// mapping their language uses.
pub struct ModifierVocabulary {
    /// Decl node kinds that may carry a `modifiers` child block.
    pub decl_kinds: &'static [&'static str],
    /// Modifier child kinds inside the decl that contain keywords
    /// (e.g. `modifiers`, `modifier`, `accessibility_modifier`).
    /// Walked recursively so nested `modifiers` blocks are covered.
    pub modifier_container_kinds: &'static [&'static str],
    /// `(keyword, Visibility)` mappings — first match wins.
    pub keyword_to_visibility: &'static [(&'static str, crate::Visibility)],
    /// Default visibility when no keyword is present (Java
    /// package-private, C# member private, Kotlin public, etc.).
    pub default_visibility: crate::Visibility,
}

/// Walk the tree once and collect (Span -> Visibility) for every
/// declaration that matches `vocab.decl_kinds`. Adapters use the
/// returned map to patch their existing DeclIndex entries.
///
/// Mirrors the per-language collect_*_visibility helpers used by
/// `lang_java` / `lang_rust` / `lang_c` and friends. Each adapter
/// supplies its language's modifier vocabulary; the walking logic
/// is identical.
#[must_use]
pub fn collect_modifier_visibility(
    root: tree_sitter::Node<'_>,
    file: bonsai_common::FileId,
    src: &[u8],
    vocab: &ModifierVocabulary,
) -> std::collections::HashMap<bonsai_common::Span, crate::Visibility> {
    let mut out = std::collections::HashMap::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if vocab.decl_kinds.contains(&node.kind()) {
            let visibility = node_modifier_visibility(&node, src, vocab);
            out.insert(span_of(file, &node), visibility);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn node_modifier_visibility(
    node: &tree_sitter::Node<'_>,
    src: &[u8],
    vocab: &ModifierVocabulary,
) -> crate::Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if vocab.modifier_container_kinds.contains(&child.kind()) {
            let mut sub = child.walk();
            for modifier in child.children(&mut sub) {
                let text = node_text(&modifier, src);
                for (kw, vis) in vocab.keyword_to_visibility {
                    if text == *kw {
                        return *vis;
                    }
                }
            }
        }
        // Some grammars expose modifiers as direct keyword nodes
        // (e.g. tree-sitter-cpp's `field_declaration` has direct
        // `private`/`public` siblings rather than a `modifiers`
        // wrapper). Cover that shape too.
        let text = node_text(&child, src);
        for (kw, vis) in vocab.keyword_to_visibility {
            if text == *kw {
                return *vis;
            }
        }
    }
    vocab.default_visibility
}

/// Per-language vocabulary for collecting `name: Type` parameter
/// bindings into `Decl.type_aliases`. Used by typed languages
/// (Java, Kotlin, Swift, C#, TS, Scala, Rust, PHP) so the resolver
/// can narrow `[Type, method]` rule dispatch through receiver-type
/// facts. See `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
pub struct TypeAliasVocabulary {
    /// Function/method node kinds whose parameters contain
    /// `name: Type` bindings worth indexing.
    pub fn_kinds: &'static [&'static str],
    /// Parameter node kinds inside each function body.
    pub param_kinds: &'static [&'static str],
    /// Field name on the parameter node that names the binding's
    /// identifier (`name`, or `pattern` on grammars where the binding
    /// is wrapped in a pattern node).
    pub name_field: &'static str,
    /// Field name on the parameter node that holds the type (`type`,
    /// `type_annotation`, etc.).
    pub type_field: &'static str,
}

/// Walk function declarations in `tree` and collect parameter
/// `name: Type` bindings as `TypeAliasBinding`. Returns a map from
/// function span to its bindings — the adapter patches matching
/// `Decl.type_aliases` entries by span equality.
#[must_use]
pub fn collect_param_type_aliases(
    tree: &tree_sitter::Tree,
    file: bonsai_common::FileId,
    src: &[u8],
    vocab: &TypeAliasVocabulary,
) -> std::collections::HashMap<bonsai_common::Span, Vec<crate::TypeAliasBinding>> {
    let mut out = std::collections::HashMap::new();
    for fn_node in collect_kinds(tree, vocab.fn_kinds) {
        let mut aliases: Vec<crate::TypeAliasBinding> = Vec::new();
        let mut stack = vec![fn_node];
        while let Some(node) = stack.pop() {
            if vocab.param_kinds.contains(&node.kind()) {
                if let Some(b) = param_alias_from_node(node, src, vocab) {
                    if !aliases.contains(&b) {
                        aliases.push(b);
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        if !aliases.is_empty() {
            out.insert(span_of(file, &fn_node), aliases);
        }
    }
    out
}

fn param_alias_from_node(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    vocab: &TypeAliasVocabulary,
) -> Option<crate::TypeAliasBinding> {
    let type_node = node
        .child_by_field_name(vocab.type_field)
        // Kotlin / Dart / Scala expose the type as an unnamed
        // child of a known kind, not under a `type` field.
        .or_else(|| first_named_type_descendant(node))?;
    let name_node = node
        .child_by_field_name(vocab.name_field)
        // C / C++ / Objective-C wrap the binding identifier inside
        // a `declarator` field rather than `name`. Try that as a
        // secondary lookup so the helper covers them too.
        .or_else(|| node.child_by_field_name("declarator"))
        // Final fallback: walk named children until we hit an
        // identifier-like leaf. Languages with field-less parameter
        // shapes (Kotlin's `parameter` carries `simple_identifier`
        // and `user_type` as unnamed children, Dart's
        // `formal_parameter` mixes `type_identifier` + named-field
        // `name`) participate without per-language helpers. Skip any
        // identifier that lives inside the type node so a type-first
        // local declaration (`Foo c`, C#/Dart `variable_declaration`)
        // binds `c`, not the leading `Foo`.
        .or_else(|| first_param_identifier_descendant_outside(node, type_node))?;
    let name = leaf_identifier_text(name_node, src)?;
    let type_short = canonical_short_type_name(node_text(&type_node, src))?;
    if name.is_empty() || name == type_short {
        return None;
    }
    Some(crate::TypeAliasBinding {
        name,
        type_name: type_short,
    })
}

/// Find the first identifier-like leaf inside a parameter / binding
/// wrapper node, skipping any node inside `exclude` (the resolved type
/// node) — its identifiers are the type's, not the binding's. This lets
/// a type-first declaration (`Foo c`, C#/Dart `variable_declaration`)
/// bind the trailing `c` instead of the leading type identifier, while
/// name-first shapes (`c: Foo`) are unaffected. For parameter shapes the
/// wrapper IS the binding root, so an identifier-kind start node is
/// accepted directly.
fn first_param_identifier_descendant_outside<'a>(
    node: tree_sitter::Node<'a>,
    exclude: tree_sitter::Node<'_>,
) -> Option<tree_sitter::Node<'a>> {
    let ex_start = exclude.start_byte();
    let ex_end = exclude.end_byte();
    fn rec<'a>(node: tree_sitter::Node<'a>, ex_start: usize, ex_end: usize) -> Option<tree_sitter::Node<'a>> {
        // Inside the type node's subtree — its identifiers are the
        // type's, not the binding's.
        if node.start_byte() >= ex_start && node.end_byte() <= ex_end {
            return None;
        }
        if matches!(
            node.kind(),
            "identifier"
                | "simple_identifier"
                | "shorthand_property_identifier_pattern"
                | "type_identifier"
                | "variable_name"
                | "name"
        ) {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(found) = rec(child, ex_start, ex_end) {
                return Some(found);
            }
        }
        None
    }
    rec(node, ex_start, ex_end)
}

fn first_named_type_descendant<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "type_identifier"
                | "user_type"
                | "predefined_type"
                | "primitive_type"
                | "simple_type"
                | "type"
                | "type_annotation"
                | "type_descriptor"
                | "function_type"
                | "type_name"
        ) {
            return Some(child);
        }
        if let Some(found) = first_named_type_descendant(child) {
            return Some(found);
        }
    }
    None
}

/// Recursively dig for the first identifier-like leaf so wrapper
/// nodes like `simple_pattern`, `binding_pattern`, PHP `variable_name`
/// (which holds a `name` child for the binding identifier), C/C++
/// `pointer_declarator`, etc. don't hide the actual name.
fn leaf_identifier_text(node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    if matches!(
        node.kind(),
        "identifier" | "simple_identifier" | "shorthand_property_identifier_pattern" | "type_identifier"
    ) {
        let raw = node_text(&node, src).trim();
        // PHP variable names start with `$`; strip so the alias map
        // keys match the bare-name resolution path the matcher uses.
        return Some(raw.trim_start_matches('$').to_string());
    }
    if node.kind() == "variable_name" {
        // PHP `variable_name` wraps `$name` → child `name`. Take the
        // raw text and strip the `$` so the binding key matches the
        // unqualified identifier the matcher sees.
        let raw = node_text(&node, src).trim().trim_start_matches('$').to_string();
        if !raw.is_empty() {
            return Some(raw);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(t) = leaf_identifier_text(child, src) {
            return Some(t);
        }
    }
    None
}

/// Strip generics, array brackets, nullability, and qualifying
/// dotted prefixes so `User?` / `User<T>` / `pkg.User` all collapse
/// to `"User"`. Accepts both uppercase user types (`User`, `Request`)
/// and lowercase primitive type names (`string`, `int`, `bool`,
/// `void`, `char`, `number`, `boolean`) — TypeScript / C / C++ /
/// PHP / C# all use lowercase primitives that are still valid
/// receiver types in `[Type, method]` rules. Returns None only
/// when the canonical form is empty or starts with a non-letter
/// (digit, punctuation, etc.).
fn canonical_short_type_name(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_start_matches(':').trim();
    let no_generics = raw.split('<').next().unwrap_or(raw);
    let no_arrays = no_generics.split('[').next().unwrap_or(no_generics);
    let stripped = no_arrays.trim().trim_end_matches('?').trim_end_matches('!');
    let short = stripped.rsplit('.').next().unwrap_or(stripped);
    let short = short.rsplit("::").next().unwrap_or(short).trim();
    let short = short.trim_start_matches('*').trim_start_matches('&').trim();
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
