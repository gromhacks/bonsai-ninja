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
//! ## Module navigation
//!
//! Grammar-specific lowering is split across the sibling `kit/*` modules:
//! `walker` drives event emission; `bindings`, `param_extraction`,
//! `return_extraction`, and `receiver_writes` lower syntax into compiler
//! facts; `direct_calls`, `pseudo_call`, and `qualified` normalize call and
//! place shapes. This module retains the shared handler configuration,
//! public façade, and orchestration pipeline. See
//! `docs/contributing/adapter-contract.mdx` for the formal contract.

mod bindings;
mod branch_conditions;
mod branch_repair;
mod call_results;
mod comments;
mod decorators;
mod direct_calls;
mod elixir;
mod expression_flow;
mod flow_render;
mod identifiers;
mod param_extraction;
mod pseudo_call;
mod qualified;
mod receiver_writes;
mod return_extraction;
mod runtime_types;
mod syntax_errors;
mod walker;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

use bindings::{
    binding_targets_from_pattern_node, dedup_assign_events, extract_comprehension_for_clause_assigns,
    extract_elixir_case_stab_clause_bindings, extract_foreach_binding_assigns, extract_match_binding_assigns,
    extract_rust_let_condition_bindings, pattern_binding_assign,
};
pub use branch_conditions::extract_branch_condition_facts;
pub use call_results::normalize_call_result_assignment_sources;
pub use comments::extract_comments;
use comments::is_comment_node_kind;
pub use decorators::extract_decorators;
use elixir::{
    elixir_call_name, elixir_unwrap_def, emit_elixir_control_flow_call, emit_erlang_functional_loop_call,
    emit_ruby_block_loop_call,
};
#[cfg(test)]
pub use expression_flow::expression_flow_from_node;
pub use expression_flow::expression_flow_from_node_with_handler;
pub use flow_render::{assignment_trace_message, collect_return_spans, for_each_flow_event};
pub use identifiers::{
    first_identifier_descendant, first_identifier_like_child, first_named_child, first_named_child_of_kind,
    looks_like_bare_identifier, looks_like_identifier, looks_like_literal_value,
};
pub use param_extraction::extract_param_annotations;
pub use receiver_writes::{
    collect_assign_targets, collect_receiver_field_writes, collect_receiver_state_sources,
    insert_flow_field_assignments, qualify_implicit_member_assign_targets,
    qualify_implicit_member_reads_in_index, qualify_receiver_field_expression_flows,
    rewrite_implicit_member_reads, FlowFieldAssignInsertion, ImplicitMemberReadCall,
};
pub use return_extraction::{extract_catch_param, extract_return_value_text, extract_throw_value_name};
#[cfg(test)]
pub use return_extraction::{extract_return_value_flow, extract_return_value_name, extract_yield_value_flow};
use return_extraction::{
    extract_return_value_flow_with_handler, extract_return_value_name_with_handler,
    extract_yield_value_flow_with_handler,
};
pub use runtime_types::extract_runtime_type_narrowing_facts;

pub(crate) use direct_calls::extract_direct_call_info;
use direct_calls::{
    extract_dart_selector_call_info, first_call_descendant, next_named_sibling_within,
    parameter_list_is_variadic, qualified_method_name_node, synthetic_function_name,
    transparent_direct_call_child,
};
use identifiers::has_direct_child_kind;
use param_extraction::extract_param_names;
use pseudo_call::pseudo_call_event;
use qualified::{
    binary_operator_is_assignment, normalise_qualified_text, qualified_assign_target,
    type_only_declaration_without_initializer,
};
pub(crate) use receiver_writes::argument_place;
use syntax_errors::{
    callable_has_syntax_error, has_direct_large_literal_initializer_child, is_initializer_list_kind,
    is_large_data_declaration_node, is_large_literal_initializer_node, retain_flow_events_outside_errors,
    syntax_error_spans,
};
use walker::walk_into;

use crate::{AdapterContext, AdapterError, CallArg, CallKind, DeclIndex, DeclKind, FlowEvent, LoopKind};
use bonsai_common::{FileId, Span};
use bonsai_vfs::FileSnapshot;
use std::sync::Arc;
use tree_sitter::{Language, Node, Tree};

use branch_repair::{looks_like_branch_arm_node, repair_branch_events_by_else_keyword};

/// Internal carrier name for language-level rest/varargs values that
/// have no user-visible identifier, such as Lua `...` and C-family
/// `...` parameters. This is syntax semantics, not a security rule.
pub const SYNTHETIC_VARARGS_PARAM: &str = "__bonsai_varargs";
pub const SYNTHETIC_TUPLE_RESULT_PREFIX: &str = "__bonsai_tuple_result_";

/// Read the compiler-owned tuple projection attached to one assignment.
///
/// This decodes an internal IR carrier, never source text. Consumers use the
/// helper instead of depending on the synthetic spelling.
#[must_use]
pub fn tuple_result_projection_index(source_names: &[String]) -> Option<usize> {
    source_names.iter().find_map(|source| {
        source
            .strip_prefix(SYNTHETIC_TUPLE_RESULT_PREFIX)
            .and_then(|index| index.parse().ok())
    })
}

/// Lower adapter-declared variadic ABI builtins into ordinary assignment
/// facts while they are still in the language-semantic layer. The IDG then
/// sees only `varargs -> list` and `list -> extracted value` dataflow and
/// carries no builtin-name inventory.
pub fn normalize_variadic_builtin_flow(
    events: &mut Vec<FlowEvent>,
    has_variadic_param: bool,
    start_builtins: &[&str],
    read_builtins: &[&str],
) {
    let original = std::mem::take(events);
    for mut event in original {
        match &mut event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_variadic_builtin_flow(
                    then_events,
                    has_variadic_param,
                    start_builtins,
                    read_builtins,
                );
                normalize_variadic_builtin_flow(
                    else_events,
                    has_variadic_param,
                    start_builtins,
                    read_builtins,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_variadic_builtin_flow(body, has_variadic_param, start_builtins, read_builtins);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_variadic_builtin_flow(body, has_variadic_param, start_builtins, read_builtins);
                normalize_variadic_builtin_flow(
                    catch_events,
                    has_variadic_param,
                    start_builtins,
                    read_builtins,
                );
                normalize_variadic_builtin_flow(
                    finally_events,
                    has_variadic_param,
                    start_builtins,
                    read_builtins,
                );
            }
            _ => {}
        }

        if let FlowEvent::Assign {
            source_name,
            source_call,
            source_call_args,
            source_names,
            value_kind,
            ..
        } = &mut event
        {
            if source_call
                .as_deref()
                .is_some_and(|name| adapter_builtin_matches(name, read_builtins))
            {
                let list = source_call_args.first().cloned();
                source_name.clone_from(&list);
                *source_call = None;
                source_call_args.clear();
                source_names.clear();
                source_names.extend(list);
                *value_kind = Some(crate::AssignValueKind::Compound);
            }
        }

        if has_variadic_param {
            if let FlowEvent::Call { span, name, args, .. } = &event {
                if adapter_builtin_matches(name, start_builtins) {
                    if let Some(target) = args.first().and_then(|arg| arg.place.as_deref()) {
                        if !target.trim().is_empty() {
                            events.push(FlowEvent::Assign {
                                span: *span,
                                target: target.trim().to_string(),
                                source_name: Some(SYNTHETIC_VARARGS_PARAM.to_string()),
                                source_call: None,
                                source_call_args: Vec::new(),
                                source_names: vec![SYNTHETIC_VARARGS_PARAM.to_string()],
                                declares_new_binding: false,
                                value_kind: Some(crate::AssignValueKind::Compound),
                            });
                        }
                    }
                }
            }
        }
        events.push(event);
    }
}

fn adapter_builtin_matches(name: &str, declared_names: &[&str]) -> bool {
    declared_names.contains(&short_name_of(name.trim()))
}

/// Normalize hierarchy-owned bare member calls to explicit receiver calls.
///
/// Java/Kotlin CSTs encode `cmd()` exactly like a free function call even
/// inside an instance method. Once declarations and `bases` are indexed, the
/// adapter can prove that a bare name belongs to the caller's class hierarchy.
/// Rewrite only those proven names to `this.cmd`/`CallKind::Method`, giving
/// downstream graph construction an explicit receiver operand without a
/// method/API allowlist.
pub fn qualify_bare_hierarchy_member_calls(index: &mut DeclIndex) {
    let mut classes_by_name: ahash::AHashMap<String, Vec<bonsai_common::SymbolId>> = ahash::AHashMap::new();
    let mut bases_by_class: ahash::AHashMap<bonsai_common::SymbolId, Vec<String>> = ahash::AHashMap::new();
    let mut methods_by_class: ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> =
        ahash::AHashMap::new();
    for decl in &index.defs {
        if matches!(
            decl.kind,
            DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
        ) {
            classes_by_name
                .entry(decl.name.clone())
                .or_default()
                .push(decl.symbol);
            bases_by_class.insert(decl.symbol, decl.bases.clone());
        }
        if matches!(decl.kind, DeclKind::Method) {
            if let Some(parent) = decl.parent {
                methods_by_class
                    .entry(parent)
                    .or_default()
                    .insert(decl.name.clone());
            }
        }
    }

    let mut rewrites: ahash::AHashMap<bonsai_common::SymbolId, (String, ahash::AHashSet<String>)> =
        ahash::AHashMap::new();
    for decl in &index.defs {
        let (Some(parent), Some(receiver)) = (decl.parent, decl.implicit_receiver_names.first()) else {
            continue;
        };
        let mut names = ahash::AHashSet::new();
        let mut seen = ahash::AHashSet::new();
        let mut pending = vec![parent];
        while let Some(class_symbol) = pending.pop() {
            if !seen.insert(class_symbol) {
                continue;
            }
            if let Some(methods) = methods_by_class.get(&class_symbol) {
                names.extend(methods.iter().cloned());
            }
            for base in bases_by_class.get(&class_symbol).into_iter().flatten() {
                let short = bonsai_common::short_qualified_tail(base).trim();
                if let Some(candidates) = classes_by_name.get(short) {
                    pending.extend(candidates.iter().copied());
                }
            }
        }
        if !names.is_empty() {
            rewrites.insert(decl.symbol, (receiver.clone(), names));
        }
    }

    for decl in &mut index.defs {
        let Some((receiver, names)) = rewrites.get(&decl.symbol) else {
            continue;
        };
        qualify_bare_hierarchy_member_events(&mut decl.flow_events, receiver, names);
    }
}

fn qualify_bare_hierarchy_member_events(
    events: &mut [FlowEvent],
    receiver_name: &str,
    method_names: &ahash::AHashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                call_kind,
                ..
            } if receiver.is_none()
                && *call_kind == CallKind::Function
                && looks_like_bare_identifier(name)
                && method_names.contains(name) =>
            {
                let member = std::mem::take(name);
                *name = format!("{receiver_name}.{member}");
                *receiver = Some(receiver_name.to_string());
                *call_kind = CallKind::Method;
            }
            FlowEvent::Assign {
                source_call: Some(source_call),
                ..
            } if looks_like_bare_identifier(source_call) && method_names.contains(source_call) => {
                *source_call = format!("{receiver_name}.{source_call}");
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                qualify_bare_hierarchy_member_events(then_events, receiver_name, method_names);
                qualify_bare_hierarchy_member_events(else_events, receiver_name, method_names);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                qualify_bare_hierarchy_member_events(body, receiver_name, method_names);
                qualify_bare_hierarchy_member_events(catch_events, receiver_name, method_names);
                qualify_bare_hierarchy_member_events(finally_events, receiver_name, method_names);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                qualify_bare_hierarchy_member_events(body, receiver_name, method_names);
            }
            _ => {}
        }
    }
}

/// Annotate destructured tuple call-result assignments with their parsed
/// positional result index. Some grammars lower `{a, b} = call()` into
/// separate Assign events that otherwise carry identical call metadata.
pub fn annotate_tuple_call_result_bindings(events: &mut [FlowEvent], tree: &Tree, src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call: Some(_),
                source_names,
                ..
            } => {
                if let Some(index) = tuple_call_result_binding_index(tree, src, *span, target) {
                    let marker = format!("{SYNTHETIC_TUPLE_RESULT_PREFIX}{index}");
                    if !source_names.iter().any(|source| source == &marker) {
                        source_names.push(marker);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                annotate_tuple_call_result_bindings(then_events, tree, src);
                annotate_tuple_call_result_bindings(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                annotate_tuple_call_result_bindings(body, tree, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                annotate_tuple_call_result_bindings(body, tree, src);
                annotate_tuple_call_result_bindings(catch_events, tree, src);
                annotate_tuple_call_result_bindings(finally_events, tree, src);
            }
            _ => {}
        }
    }
}

fn tuple_call_result_binding_index(tree: &Tree, src: &[u8], span: Span, target: &str) -> Option<usize> {
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    let mut current = tree.root_node().descendant_for_byte_range(start, end)?;
    loop {
        if let Some(lhs) = assignment_lhs_node(&current) {
            if let Some(index) = positional_pattern_binding_index(lhs, target, src) {
                return Some(index);
            }
        }
        current = current.parent()?;
    }
}

fn positional_pattern_binding_index(pattern: Node<'_>, target: &str, src: &[u8]) -> Option<usize> {
    const POSITIONAL_PATTERNS: &[&str] = &[
        "tuple_pattern",
        "pattern_list",
        "array_pattern",
        "list_pattern",
        "left_assignment_list",
        "expression_list",
        "list_expression",
        "tuple",
        "list_literal",
        "pattern",
    ];
    if POSITIONAL_PATTERNS.contains(&pattern.kind()) {
        let mut cursor = pattern.walk();
        let children: Vec<Node<'_>> = pattern.named_children(&mut cursor).collect();
        if children.len() > 1 {
            return children.iter().position(|child| {
                binding_targets_from_pattern_node(child, src)
                    .iter()
                    .any(|binding| same_identifier_name(binding, target))
            });
        }
    }
    let mut cursor = pattern.walk();
    for child in pattern.named_children(&mut cursor) {
        if let Some(index) = positional_pattern_binding_index(child, target, src) {
            return Some(index);
        }
    }
    None
}

/// Look up a language from the pack and wrap any error nicely.
pub fn language_from_pack(name: &str) -> Result<Language, AdapterError> {
    tree_sitter_language_pack::get_language(name)
        .map_err(|e| AdapterError::GrammarUnavailable(format!("{name}: {e}")))
}

/// Parse a single file using the given pack name. Returns `None` if the
/// file is unknown to the VFS.
pub fn parse_with(name: &str, file: FileId, ctx: &AdapterContext<'_>) -> Option<(FileSnapshot, Arc<Tree>)> {
    let snapshot = ctx.vfs.snapshot(file).ok()?;
    if let Some(tree) = ctx
        .tree_provider
        .and_then(|provider| provider.tree_for_snapshot(name, &snapshot))
    {
        return Some((snapshot, tree));
    }
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
                    value_flow: crate::ExpressionFlow::from_place(field.clone()),
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

/// Relate an adapter-proven finite selection expression to its enclosing
/// compiler assignment or call argument. The callback owns all
/// language-syntax validation.
pub fn finite_literal_selection_fact_for_span<F>(
    index: &DeclIndex,
    tree: &Tree,
    selection_span: Span,
    validate_selection: F,
) -> Option<crate::FiniteLiteralSelectionFact>
where
    F: FnOnce(Node<'_>) -> bool,
{
    let assignment = index
        .assignment_values
        .iter()
        .filter(|fact| {
            fact.target.is_some()
                && fact.value_span.file == selection_span.file
                && fact.value_span.start <= selection_span.start
                && selection_span.end <= fact.value_span.end
        })
        .min_by_key(|fact| fact.value_span.end.saturating_sub(fact.value_span.start));
    let argument = index
        .call_argument_values
        .iter()
        .filter(|fact| {
            fact.argument_span.file == selection_span.file
                && fact.argument_span.start <= selection_span.start
                && selection_span.end <= fact.argument_span.end
        })
        .min_by_key(|fact| fact.argument_span.len());
    let value_span = assignment
        .map(|fact| fact.value_span)
        .or_else(|| argument.map(|fact| fact.argument_span))?;
    let value_node = node_at_span(tree.root_node(), value_span, &[])?;
    validate_selection(value_node).then(|| crate::FiniteLiteralSelectionFact {
        selection_span,
        assignment_span: assignment.map(|fact| fact.assignment_span),
        target: assignment.and_then(|fact| fact.target.clone()),
        call_span: argument.map(|fact| fact.call_span),
        argument_index: argument.map(|fact| fact.argument_index),
    })
}

/// Sort and deduplicate adapter-emitted finite-selection facts by their
/// compiler-owned enclosing span.
pub fn sort_dedup_finite_literal_selections(facts: &mut Vec<crate::FiniteLiteralSelectionFact>) {
    facts.sort_by_key(|fact| {
        let owner = fact
            .assignment_span
            .or(fact.call_span)
            .unwrap_or(fact.selection_span);
        (
            owner.start,
            owner.end,
            fact.selection_span.start,
            fact.selection_span.end,
        )
    });
    facts.dedup();
}

/// Return the final identifier-shaped segment of the outer type constructor.
///
/// The input is already an adapter-classified type node. This helper is
/// deliberately structural: it stops before nested generic/aggregate syntax
/// and finds identifier runs without recognizing any language keyword,
/// qualifier spelling, pointer prefix, or nullable suffix. Adapters therefore
/// retain ownership of deciding which Tree-sitter node is a type.
#[must_use]
pub fn canonical_simple_type_name(text: &str) -> String {
    let outer = text
        .trim()
        .split_once(['<', '['])
        .map_or_else(|| text.trim(), |(head, _)| head);
    let mut last = None;
    let mut start = None;
    for (index, ch) in outer.char_indices() {
        if ch == '_' || ch.is_alphanumeric() {
            start.get_or_insert(index);
        } else if let Some(segment_start) = start.take() {
            last = outer.get(segment_start..index);
        }
    }
    if let Some(segment_start) = start {
        last = outer.get(segment_start..);
    }
    last.unwrap_or_default().to_string()
}

// ---------------------------------------------------------------------------
// Grammar-driven flow extraction
// ---------------------------------------------------------------------------

/// Per-language classification of Tree-sitter node kinds. Adapter crates
/// supply one of these. The defaults cover the most common kind names
/// across Tree-sitter grammars; language-specific kinds are layered on top.
///
/// Fields are grouped logically below. The struct is intentionally
/// flat rather than nested structs so adapter declarations stay ergonomic
/// with `..EMPTY_HANDLER` while every non-empty syntax list remains local.
/// New fields land in their group with a comment.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SyntaxSpecialForm {
    /// A call is split across a callee sibling and a selector node.
    SplitSelectorCall,
    /// A remote-call expression is split into module and function children.
    RemoteCallExpression,
    /// Builder cascades encode calls/writes as cascade-section nodes.
    CascadeSection,
    /// Explicit object construction is not classified as an ordinary call.
    ObjectConstructionExpression,
    /// A call-shaped node with a trailing closure represents deferred work.
    TrailingClosureDefer,
    /// Control-flow constructs are encoded as call nodes with structured bodies.
    CallEncodedControlFlow,
    /// A functional call represents a loop and must lower to `FlowEvent::Loop`.
    FunctionalLoopCall,
    /// A call block represents an iterator loop with a structured body.
    BlockLoopCall,
    /// Call arguments are direct children rather than an argument container.
    DirectCallArguments,
    /// A call's structured control body is stored in a direct `do_block` child.
    DirectDoBlockBody,
}

/// Adapter-owned recognizer for a Tree-sitter expression that denotes a
/// callable value without invoking it. The callback receives only the parsed
/// node and immutable source bytes; it must return the compiler identity of
/// the referenced callable or `None`.
pub type CallableReferenceExtractor = for<'tree> fn(Node<'tree>, &[u8]) -> Option<String>;

/// Adapter-owned lowering for grammar constructs that execute like calls but
/// are not represented by the grammar's ordinary call nodes.
pub type PseudoCallExtractor =
    for<'tree> fn(Node<'tree>, FileId, &[u8], &GrammarHandler) -> Option<FlowEvent>;

/// Adapter-owned lowering for one grammar construct that already has a
/// language-neutral [`FlowEvent`] meaning but cannot be classified by a
/// unique node kind. The callback is additive: shared walking still descends
/// into the node so nested calls and value operands remain visible.
pub type SyntaxEventExtractor =
    for<'tree> fn(Node<'tree>, FileId, &[u8], &GrammarHandler) -> Option<FlowEvent>;

/// Adapter-owned receiver-node extractor for pseudo calls. Returning the CST
/// node, rather than rendered text, lets shared indexing build exact value
/// dependencies without learning the language's pseudo-call grammar.
pub type PseudoCallReceiverExtractor = for<'tree> fn(Node<'tree>, &[u8]) -> Option<Node<'tree>>;

/// Adapter-owned classifier for caller-visible argument write-back syntax.
/// Shared analysis consumes the resulting language-neutral mode and never
/// recognizes source tokens such as an address-of or `out` marker.
pub type ArgumentPassingModeExtractor = for<'tree> fn(Node<'tree>, Node<'tree>) -> crate::ArgumentPassingMode;

#[derive(Clone, Debug, Default)]
pub struct GrammarHandler {
    // === Decl shapes ===
    /// Function-like declarations. The walker creates one `Decl` per
    /// match.
    pub fn_kinds: &'static [&'static str],
    /// Class-like declarations (struct, trait, enum, interface, ...).
    pub class_kinds: &'static [&'static str],
    /// Exact declaration kind for each class-like grammar node. The
    /// Tree-sitter adapter owns this mapping because `interface`, `trait`,
    /// `struct`, and `enum` are language syntax, not names the shared
    /// compiler should infer from a language id.
    pub class_decl_kinds: &'static [(&'static str, crate::DeclKind)],
    /// Whether a class-like declaration nested directly inside another
    /// class-like declaration is a lexical member of that type. C tag
    /// declarations opt out because they do not form `Outer::Inner`
    /// identities.
    pub nested_type_ownership: bool,
    /// Method declarations. Subset of `fn_kinds` for grammars that
    /// distinguish methods from free functions.
    pub method_kinds: &'static [&'static str],
    /// Ancestor node kinds whose function-like children are methods
    /// for receiver-parameter purposes. This is narrower than
    /// `class_kinds` because some grammars expose modules or type
    /// specs as class-like declarations but they do not imply a
    /// receiver binding.
    pub method_context_kinds: &'static [&'static str],
    /// Anonymous type-expression boundaries that must not leak method
    /// ownership to an enclosing named type. Java anonymous classes are the
    /// canonical example: methods inside `new Interface() { ... }` belong to
    /// that anonymous object, not to the named class or interface surrounding
    /// the expression.
    pub method_owner_barrier_kinds: &'static [&'static str],
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
    /// Call-shaped grammar components whose enclosing call already owns the
    /// complete callee and argument list. The method-chain walker must not
    /// emit these components a second time. This inventory is adapter-owned;
    /// shared lowering does not recognize a language-specific node kind.
    pub nested_call_component_kinds: &'static [&'static str],
    /// Optional adapter callback for call semantics encoded by non-call CST
    /// nodes (operator forms, language constructs, markup sugar, and similar
    /// grammar-specific shapes).
    pub pseudo_call_extractor: Option<PseudoCallExtractor>,
    /// Optional exact lowering for an otherwise-unclassified syntax event.
    /// This is used when one grammar node kind represents several semantic
    /// transfers and the adapter must inspect its parsed token/child shape.
    pub syntax_event_extractor: Option<SyntaxEventExtractor>,
    /// Optional adapter callback returning the value receiver of a pseudo
    /// call. It must classify exactly the same nodes as
    /// `pseudo_call_extractor` when that pseudo call has a receiver.
    pub pseudo_call_receiver_extractor: Option<PseudoCallReceiverExtractor>,
    /// Optional exact classifier for argument passing syntax. Languages that
    /// do not expose caller-visible write-back leave this unset and receive
    /// ordinary value semantics.
    pub argument_passing_mode_extractor: Option<ArgumentPassingModeExtractor>,
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

    // === Grammar-specific lowering capabilities ===
    /// Non-standard syntax forms this adapter asks the shared compiler
    /// lowering pipeline to recognize. The core walker never selects these
    /// paths from a language id or rule/API name.
    pub special_forms: &'static [SyntaxSpecialForm],

    /// Builtin call spellings whose grammar/runtime semantics are exact
    /// runtime type predicates. These are language semantics, not security
    /// APIs, and therefore stay in the owning adapter.
    pub runtime_type_guard_calls: &'static [&'static str],
    /// Binary operator node kinds that semantically test a runtime type.
    pub runtime_type_guard_operators: &'static [&'static str],
    /// Unary operator node kinds that produce a runtime type label.
    pub runtime_typeof_operators: &'static [&'static str],
    /// Equality operator node kinds accepted around a runtime type label.
    pub runtime_type_equality_operators: &'static [&'static str],
    /// Tree-sitter node kinds whose operands describe a type or layout but do
    /// not read the operand's runtime value (`sizeof_expression`, for
    /// example). The owning adapter declares these exact grammar facts so
    /// shared lowering can omit their descendants without reparsing text.
    pub value_free_expression_kinds: &'static [&'static str],
    /// Language-keyword calls whose arguments are syntax metadata rather than
    /// runtime value reads (for example C# `nameof`). These are compiler
    /// semantics owned by the adapter, never security/API matching data.
    pub value_free_call_names: &'static [&'static str],
    /// Anonymous unary-operator token kinds whose result does not carry the
    /// operand's attacker-controlled value. This covers grammars that encode
    /// the operator and operand under a generic `unary_expression` node.
    pub value_free_unary_operators: &'static [&'static str],

    // === Reference-index syntax ===
    /// Complete call-node inventory used by the flat reference index. Unlike
    /// the flow walker's compatibility overlays, this is a closed adapter
    /// declaration.
    pub call_ref_kinds: &'static [&'static str],
    /// Grammar node kinds that represent member/field projections for flat
    /// read/write reference indexing.
    pub member_expression_kinds: &'static [&'static str],
    /// Grammar node kinds that represent subscript/index projections.
    pub subscript_expression_kinds: &'static [&'static str],
    /// Variable node kinds whose leading source punctuation is not part of
    /// the canonical binding identity.
    pub sigil_variable_kinds: &'static [&'static str],
    /// Dedicated global/special-variable node kinds.
    pub global_variable_kinds: &'static [&'static str],
    /// A bare subscript receiver also denotes an implicit call-like lookup in
    /// this grammar/DSL surface.
    pub subscript_base_call_refs: bool,
    /// Call-shaped grammar identifiers that are declarations/directives, not
    /// runtime calls.
    pub non_call_ref_names: &'static [&'static str],
    /// Dedicated grammar nodes that emit a canonical pseudo-call reference.
    pub synthetic_call_ref_names: &'static [(&'static str, &'static str)],
    /// Adapter-declared punctuation appended to a callee identifier by the
    /// surrounding call node (for example a macro marker).
    pub call_name_suffix_tokens: &'static [&'static str],
    /// Calls whose adapter-proven non-value syntax damage may overlap an
    /// otherwise valid flow event.
    pub syntax_error_tolerant_call_names: &'static [&'static str],
    /// Dedicated grammar nodes whose name/method child is a callable value
    /// (Java/Kotlin method references, for example).
    pub callable_reference_kinds: &'static [&'static str],
    /// Optional adapter callback for callable-value syntax that requires
    /// grammar-specific structural validation.
    pub callable_reference_extractor: Option<CallableReferenceExtractor>,

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

    /// Return-type annotations that denote "returns no value" (Scala `Unit`).
    /// A function declared with one of these types cannot return a tainted
    /// value, so the walker suppresses the synthetic tail-/expression-body
    /// Return for it — a tail *call* in such a body (`def f(x): Unit = {
    /// …; log(x) }`) consumes its argument, it does not return it, and
    /// tokenising that call's args into a Return over-taints the caller.
    /// Only consulted when the grammar exposes the type via a `return_type`
    /// field on the callable node; empty for languages without the field.
    pub void_return_type_names: &'static [&'static str],
}

/// Empty compiler-syntax contract used as a struct-update base by language
/// adapters. Every non-empty grammar inventory must be declared in the
/// owning `lang_*` crate; shared lowering never substitutes source syntax.
pub const EMPTY_HANDLER: GrammarHandler = GrammarHandler {
    fn_kinds: &[],
    class_kinds: &[],
    class_decl_kinds: &[],
    nested_type_ownership: true,
    method_kinds: &[],
    method_context_kinds: &[],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: &[],
    if_kinds: &[],
    for_kinds: &[],
    foreach_kinds: &[],
    while_kinds: &[],
    do_kinds: &[],
    loop_kinds: &[],
    call_kinds: &[],
    nested_call_component_kinds: &[],
    pseudo_call_extractor: None,
    syntax_event_extractor: None,
    pseudo_call_receiver_extractor: None,
    argument_passing_mode_extractor: None,
    assignment_kinds: &[],
    return_kinds: &[],
    throw_kinds: &[],
    lambda_kinds: &[],
    try_kinds: &[],
    catch_kinds: &[],
    finally_kinds: &[],
    break_kinds: &[],
    continue_kinds: &[],
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &[],
    special_forms: &[],
    runtime_type_guard_calls: &[],
    runtime_type_guard_operators: &[],
    runtime_typeof_operators: &[],
    runtime_type_equality_operators: &[],
    value_free_expression_kinds: &[],
    value_free_call_names: &[],
    value_free_unary_operators: &[],
    call_ref_kinds: &[],
    member_expression_kinds: &[],
    subscript_expression_kinds: &[],
    sigil_variable_kinds: &[],
    global_variable_kinds: &[],
    subscript_base_call_refs: false,
    non_call_ref_names: &[],
    synthetic_call_ref_names: &[],
    call_name_suffix_tokens: &[],
    syntax_error_tolerant_call_names: &[],
    callable_reference_kinds: &[],
    callable_reference_extractor: None,
    method_receiver_param_index: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
    void_return_type_names: &[],
};

/// Test-only cross-grammar fixture. Production adapters must declare every
/// non-empty syntax category themselves and use [`EMPTY_HANDLER`] only as an
/// empty struct-update base.
#[cfg(test)]
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
    class_decl_kinds: &[
        ("struct_item", crate::DeclKind::Struct),
        ("struct_declaration", crate::DeclKind::Struct),
        ("struct_specifier", crate::DeclKind::Struct),
        ("union_item", crate::DeclKind::Struct),
        ("union_specifier", crate::DeclKind::Struct),
        ("trait_item", crate::DeclKind::Trait),
        ("trait_definition", crate::DeclKind::Trait),
        ("interface_declaration", crate::DeclKind::Interface),
        ("enum_item", crate::DeclKind::Enum),
        ("enum_definition", crate::DeclKind::Enum),
        ("module", crate::DeclKind::Module),
    ],
    nested_type_ownership: true,
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
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &["constructor_declaration", "init_declaration"],
    // Constructor method spellings belong to the language adapter. The
    // generic tree-sitter lowering recognizes constructor node kinds only.
    constructor_names: &[],
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
    nested_call_component_kinds: &[],
    pseudo_call_extractor: None,
    syntax_event_extractor: None,
    pseudo_call_receiver_extractor: None,
    argument_passing_mode_extractor: None,
    assignment_kinds: &[
        "assignment",
        "assignment_expression",
        "assignment_statement",
        "augmented_assignment",
        "augmented_assignment_expression",
        "compound_assignment_expr",
        // PHP `$ref =& $src;` — reference aliasing is value-carrying:
        // taint on the RHS must reach the alias. The node kind is
        // PHP-specific, so listing it generically cannot collide.
        "reference_assignment_expression",
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
        // Go package/local constants. The generic walker may omit module
        // bindings from function flow, but file-level compiler facts still
        // need their exact target/value relationship for static provenance.
        "const_spec",
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
    special_forms: &[],
    runtime_type_guard_calls: &[],
    runtime_type_guard_operators: &[],
    runtime_typeof_operators: &[],
    runtime_type_equality_operators: &[],
    value_free_expression_kinds: &[],
    value_free_call_names: &[],
    value_free_unary_operators: &[],
    call_ref_kinds: &[],
    member_expression_kinds: &[],
    subscript_expression_kinds: &[],
    sigil_variable_kinds: &[],
    global_variable_kinds: &[],
    subscript_base_call_refs: false,
    non_call_ref_names: &[],
    synthetic_call_ref_names: &[],
    call_name_suffix_tokens: &[],
    syntax_error_tolerant_call_names: &[],
    callable_reference_kinds: &[],
    callable_reference_extractor: None,
    method_receiver_param_index: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: false,
    void_return_type_names: &[],
};

/// Test-only call inventory used by the cross-grammar kit fixtures.
#[cfg(test)]
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
];

impl GrammarHandler {
    fn is_fn(&self, k: &str) -> bool {
        self.fn_kinds.contains(&k)
    }
    fn is_class(&self, k: &str) -> bool {
        self.class_kinds.contains(&k)
    }
    fn is_if(&self, k: &str) -> bool {
        self.if_kinds.contains(&k)
    }
    fn is_for(&self, k: &str) -> bool {
        self.for_kinds.contains(&k)
    }
    fn is_foreach(&self, k: &str) -> bool {
        self.foreach_kinds.contains(&k)
    }
    fn is_while(&self, k: &str) -> bool {
        self.while_kinds.contains(&k)
    }
    fn is_do(&self, k: &str) -> bool {
        self.do_kinds.contains(&k)
    }
    fn is_loop(&self, k: &str) -> bool {
        self.loop_kinds.contains(&k)
    }
    fn is_call(&self, k: &str) -> bool {
        self.call_kinds.contains(&k)
    }
    fn is_assignment(&self, k: &str) -> bool {
        self.assignment_kinds.contains(&k)
    }
    fn is_return(&self, k: &str) -> bool {
        self.return_kinds.contains(&k)
    }
    fn is_throw(&self, k: &str) -> bool {
        self.throw_kinds.contains(&k)
    }
    fn is_lambda(&self, k: &str) -> bool {
        self.lambda_kinds.contains(&k)
    }
    fn is_constructor_method(&self, name: &str) -> bool {
        self.constructor_names.contains(&name)
    }
    fn is_try(&self, k: &str) -> bool {
        self.try_kinds.contains(&k)
    }
    fn is_catch(&self, k: &str) -> bool {
        self.catch_kinds.contains(&k)
    }
    fn is_finally(&self, k: &str) -> bool {
        self.finally_kinds.contains(&k)
    }
    fn is_break(&self, k: &str) -> bool {
        self.break_kinds.contains(&k)
    }
    fn is_continue(&self, k: &str) -> bool {
        self.continue_kinds.contains(&k)
    }
    fn is_yield(&self, k: &str) -> bool {
        self.yield_kinds.contains(&k)
    }
    fn is_await(&self, k: &str) -> bool {
        self.await_kinds.contains(&k)
    }
    fn is_defer(&self, k: &str) -> bool {
        self.defer_kinds.contains(&k)
    }
    fn is_using(&self, k: &str) -> bool {
        self.using_kinds.contains(&k)
    }
    fn has_special_form(&self, form: SyntaxSpecialForm) -> bool {
        self.special_forms.contains(&form)
    }
}

/// Select an assignment target from Tree-sitter fields and named-node
/// relationships. Downstream consumers must not split the surrounding source
/// statement to rediscover this node.
fn assignment_target_pattern_node<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    let kind = node.kind();
    node.child_by_field_name("left")
        .or_else(|| node.child_by_field_name("lhs"))
        .or_else(|| node.child_by_field_name("target"))
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.child_by_field_name("pattern"))
        .or_else(|| node.child_by_field_name("declarator"))
        .or_else(|| {
            (kind == "property_declaration")
                .then(|| {
                    first_named_child_of_kind(&node, "multi_variable_declaration")
                        .or_else(|| first_named_child_of_kind(&node, "variable_declaration"))
                })
                .flatten()
        })
        .or_else(|| first_non_keyword_named_child(&node, src))
}

fn assignment_target_node<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    let target = assignment_target_pattern_node(node, src)?;
    Some(match target.kind() {
        "variable_declarator"
        | "init_declarator"
        | "declarator"
        | "property_identifier"
        | "variable_declaration"
        | "function_declarator"
        | "pointer_declarator"
        | "parenthesized_declarator"
        | "block_pointer_declarator" => target
            .child_by_field_name("name")
            .or_else(|| {
                first_named_child_of_kind(&target, "variable_declarator")
                    .and_then(|decl| decl.child_by_field_name("name"))
            })
            .or_else(|| first_identifier_descendant(target))
            .or_else(|| first_non_keyword_named_child(&target, src))
            .unwrap_or(target),
        _ => target,
    })
}

/// Select an assignment RHS from Tree-sitter fields. The last-named-child
/// fallback covers grammars whose initializer is an unfielded sibling while
/// remaining a parsed-node relationship rather than a textual `=` scan.
fn assignment_value_node<'tree>(node: Node<'tree>, target_node: Option<Node<'tree>>) -> Option<Node<'tree>> {
    // Some grammars attach an RHS field id to punctuation. Perl list
    // assignment, for example, reports its opening `(` as `right` even
    // though the named `list_expression` is the actual value node. Compiler
    // facts must never treat an anonymous terminal as an expression; reject
    // those field results and use the named-child relationship below.
    node.child_by_field_name("right")
        .filter(Node::is_named)
        .or_else(|| node.child_by_field_name("rhs").filter(Node::is_named))
        .or_else(|| node.child_by_field_name("value").filter(Node::is_named))
        .or_else(|| node.child_by_field_name("result").filter(Node::is_named))
        .or_else(|| last_named_child_excluding(&node, target_node))
}

fn has_direct_token(node: &Node<'_>, src: &[u8], expected: &str) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() && node_text(&child, src).trim() == expected {
            return true;
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}

/// Return the compiler-resolved callable name for assignment RHS syntax that
/// denotes a callable value rather than invoking it. Detection is based on
/// Tree-sitter node kinds, fields, and operator terminals; it never scans the
/// surrounding assignment statement.
fn callable_reference_name(node: &Node<'_>, src: &[u8], handler: &GrammarHandler) -> Option<String> {
    named_callable_reference(node, src, handler.callable_reference_kinds).or_else(|| {
        handler
            .callable_reference_extractor
            .and_then(|extract| extract(*node, src))
    })
}

fn named_callable_reference(node: &Node<'_>, src: &[u8], kinds: &[&str]) -> Option<String> {
    if !kinds.contains(&node.kind()) {
        return None;
    }
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("method"))
        .or_else(|| node.child_by_field_name("function"))
        .or_else(|| last_non_comment_named_child(node))?;
    let name = node_text(&name, src).trim();
    (!name.is_empty()).then(|| name.to_string())
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
    // Iterative pre-order over the sequence's executable nodes. Children
    // are pushed in REVERSE so the LIFO stack pops them in source order —
    // otherwise a comma/sequence expression (`(a = gets(s), system(a))`)
    // emits its events backwards, so the sink appears "before" the
    // assignment that taints it (breaks ordered intra-analysis and the
    // last-write clean-overwrite accounting).
    let mut stack: Vec<Node<'_>> = Vec::new();
    {
        let mut cursor = root.walk();
        let children: Vec<Node<'_>> = root.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if is_large_literal_initializer_node(kind, &node) {
            continue;
        }
        if is_initializer_list_kind(kind)
            || kind == "comma_expression"
            || !(handler.is_assignment(kind) || handler.is_call(kind) || kind == "selector")
        {
            let mut cursor = node.walk();
            let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
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
            // Erlang `<< <<X>> || <<X>> <= Bin >>` (its list form shares
            // Python's `list_comprehension` kind name).
            | "binary_comprehension"
            // Erlang OTP 26+ map comprehension `#{K => V || ...}`.
            | "map_comprehension"
    )
}

/// Node kinds that bind a comprehension's loop variable from its
/// iterable. Python/JS: `for_in_clause` / `comp_for` (direct children of
/// the comprehension). Erlang: `generator` / `b_generator` / `m_generator`
/// (`X <- List`, `<<X>> <= Bin`), nested under wrapper nodes.
fn is_comprehension_binding_clause(kind: &str) -> bool {
    matches!(
        kind,
        "for_in_clause" | "comp_for" | "generator" | "b_generator" | "m_generator"
    )
}

/// Declared type surrounding an assignment-shaped initializer node.
/// Tree-sitter C/C++ place the `type` field on the parent `declaration` and
/// the initializer on its `init_declarator` child. Other grammars with the
/// same structural contract benefit without any language/name inventory.
fn assignment_declared_type(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let mut current = Some(*node);
    while let Some(candidate) = current {
        if let Some(type_node) = candidate.child_by_field_name("type") {
            let type_name = node_text(&type_node, src).trim();
            if !type_name.is_empty() {
                return Some(type_name.to_string());
            }
        }
        current = candidate.parent();
        if current.is_some_and(|parent| {
            matches!(
                parent.kind(),
                "function_definition" | "method_definition" | "lambda_expression"
            )
        }) {
            break;
        }
    }
    None
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
        let tail = bonsai_common::short_qualified_tail(&callee);
        if tail != callee {
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

/// True when the callable node declares a void/unit return type listed in
/// `handler.void_return_type_names`. Read syntactically from the grammar's
/// `return_type` field (Scala `def f(): Unit`), so it fires only for
/// languages that expose the annotation and opt into a void-type list.
fn callable_returns_void(node: &Node<'_>, src: &[u8], handler: &GrammarHandler) -> bool {
    if handler.void_return_type_names.is_empty() {
        return false;
    }
    let Some(return_type) = node.child_by_field_name("return_type") else {
        return false;
    };
    let text = node_text(&return_type, src).trim();
    handler.void_return_type_names.contains(&text)
}

fn append_tail_expression_return(
    events: &mut Vec<FlowEvent>,
    body: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) {
    // The tail expression is the last *value-bearing* child — skip
    // trailing comments, which tree-sitter exposes as named children.
    // Without this, a trailing `// done` / `# note` becomes the
    // synthesized Return's value and the real tail expression's
    // implicit-return taint is dropped.
    let Some(tail) = last_non_comment_named_child(body) else {
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
        value_flow: expression_flow::expression_flow_from_node_with_handler(tail, file, src, handler),
    });
}

fn append_expression_body_return(
    events: &mut Vec<FlowEvent>,
    body: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) {
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
        value_flow: expression_flow::expression_flow_from_node_with_handler(*body, file, src, handler),
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
    // A statement-shaped single child is control flow, not a tail
    // expression. Swift `func f() { if … }`, Kotlin `fun f() { when … }`,
    // and Solidity `function f() { if (…) {…} }` must NOT synthesize a
    // Return whose `value_text` unions the whole block — that fabricates
    // an over-tainted return (and a bogus return in a void function). The
    // `_statement` suffix rule fails closed for unseen statement kinds;
    // `statement` alone is Solidity's generic per-statement wrapper; the
    // `statements`-only expression list catches Kotlin control-flow
    // expressions in block-statement position while leaving
    // `fun f() = if (c) a else b` (which reaches the `if_expression`
    // directly, without a `statements` wrapper) with its legitimate Return.
    if first.kind() == "statement"
        || first.kind().ends_with("_statement")
        || (body.kind() == "statements"
            && matches!(
                first.kind(),
                "if_expression" | "when_expression" | "try_expression"
            ))
    {
        return None;
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

/// Last named child that is not a comment. Used by tail-expression
/// return synthesis: a trailing comment is not the returned value.
fn last_non_comment_named_child<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !child.kind().contains("comment"))
        .last()
}

fn binding_name_node<'a>(node: &Node<'a>, src: &[u8]) -> Option<Node<'a>> {
    let parent = node.parent()?;
    // Lua wraps the single RHS of `local f = function(...) ... end` in an
    // `expression_list` before the surrounding `assignment_statement`.
    // Treat a one-expression list as transparent so the callable can still
    // recover the local binding instead of disappearing from Pass 2.
    if matches!(parent.kind(), "expression_list" | "expressions") && parent.named_child_count() == 1 {
        return binding_name_node(&parent, src);
    }
    let value_is_node = parent
        .child_by_field_name("value")
        .or_else(|| parent.child_by_field_name("right"))
        .or_else(|| parent.child_by_field_name("rhs"))
        .is_some_and(|value| value.id() == node.id());
    // tree-sitter-lua does not field-label the two children of an
    // `assignment_statement`: the first is a `variable_list`, the second an
    // `expression_list`. When `node` is the latter, recover the sole LHS
    // identifier structurally.
    let structural_assignment_target = if parent.kind() == "assignment_statement" {
        let mut cursor = parent.walk();
        let children: Vec<Node<'a>> = parent.named_children(&mut cursor).collect();
        let rhs_position = children.iter().position(|child| child.id() == node.id());
        rhs_position
            .filter(|position| *position > 0)
            .and_then(|_| children.first().copied())
            .and_then(|lhs| first_identifier_descendant(lhs).or(Some(lhs)))
    } else {
        None
    };
    let is_last_named_child =
        last_non_comment_named_child(&parent).is_some_and(|value| value.id() == node.id());
    match parent.kind() {
        "variable_declarator" | "initialized_variable_definition" if value_is_node || is_last_named_child => {
            parent
                .child_by_field_name("name")
                .or_else(|| parent.child_by_field_name("pattern"))
        }
        "val_definition" | "var_definition" if value_is_node => parent
            .child_by_field_name("name")
            .or_else(|| parent.child_by_field_name("pattern")),
        "property_declaration" if value_is_node || is_last_named_child => parent
            .child_by_field_name("name")
            .or_else(|| parent.child_by_field_name("pattern"))
            .or_else(|| {
                first_named_child_of_kind(&parent, "variable_declaration")
                    .and_then(first_identifier_descendant)
            }),
        "assignment_expression" | "assignment" | "assignment_statement" | "binary_operator"
            if value_is_node || structural_assignment_target.is_some() =>
        {
            parent
                .child_by_field_name("left")
                .or_else(|| parent.child_by_field_name("lhs"))
                .or_else(|| parent.child_by_field_name("target"))
                .or(structural_assignment_target)
        }
        "pair" | "pair_pattern" if value_is_node => parent.child_by_field_name("key"),
        // C/C++ `auto f = [...]` — the closure sits in `init_declarator`'s
        // `value`; the binding name is the `declarator`. Without this arm
        // the stored closure's standalone decl is anonymous
        // (`<lambda@line:col>`) and `f(x)` can never resolve to it.
        "init_declarator" if value_is_node => parent.child_by_field_name("declarator"),
        // Rust `let f = |...| ...;` — binding name is the `pattern`.
        "let_declaration" if value_is_node => parent.child_by_field_name("pattern"),
        _ => None,
    }
}

fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

fn push_unique_name(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

#[derive(Debug)]
struct LocalClosureCapturePlan {
    lambda_index: usize,
    caller_index: usize,
    binding_name: String,
    rename_to_binding: bool,
    captures: Vec<String>,
}

/// Finalize lexical closure conversion after adapter-specific HIR lowering.
///
/// Some grammars need adapter passes to normalize their local-call syntax
/// (`binding.()` in Elixir, coderef calls in Perl). Running this compiler pass
/// after those adapters guarantees every canonical consumer sees the same
/// hidden capture parameters and arguments.
pub fn apply_local_closure_captures(index: &mut crate::DeclIndex) {
    lower_local_closure_captures(&mut index.defs);
}

/// Perform lexical closure conversion on locally-bound lambdas.
///
/// Tree-sitter supplies the nested callable span, its explicit parameters,
/// and every value-bearing read in its body. The enclosing declaration
/// supplies the bindings visible at the lambda's definition. Their
/// intersection is the capture set. Captures become trailing hidden
/// parameters on the lowered lambda and trailing hidden arguments on calls
/// to that local callable, exactly like a compiler closure-conversion pass.
fn lower_local_closure_captures(defs: &mut [crate::Decl]) {
    let mut plans = Vec::new();
    // Export aliases and other semantic aliases can deliberately share one
    // callable body span. Closure conversion owns the body once; renaming or
    // injecting captures into every alias would erase those public identities
    // and duplicate hidden parameters. Declaration order keeps the adapter's
    // canonical body declaration first, followed by its aliases.
    let mut planned_callable_spans = ahash::AHashSet::new();
    for lambda_index in 0..defs.len() {
        let lambda = &defs[lambda_index];
        let lambda_width = lambda.span.end.saturating_sub(lambda.span.start);
        let caller_index = defs
            .iter()
            .enumerate()
            .filter(|(index, candidate)| {
                let owner_span = candidate.body_span.unwrap_or(candidate.span);
                *index != lambda_index
                    && matches!(
                        candidate.kind,
                        crate::DeclKind::Function | crate::DeclKind::Method | crate::DeclKind::Constructor
                    )
                    && span_contains(owner_span, lambda.span)
                    && owner_span.end.saturating_sub(owner_span.start) > lambda_width
            })
            .min_by_key(|(_, candidate)| {
                let owner_span = candidate.body_span.unwrap_or(candidate.span);
                owner_span.end.saturating_sub(owner_span.start)
            })
            .map(|(index, _)| index);
        let Some(caller_index) = caller_index else {
            continue;
        };

        let caller = &defs[caller_index];
        // A nested declaration is a locally-bound closure only when the
        // enclosing callable has an AST-classified callable assignment whose
        // RHS span contains it. This excludes ordinary nested declarations
        // and obtains the invocation binding from syntax rather than from a
        // generated lambda name.
        let Some(binding_name) = local_callable_binding_for_span(&caller.flow_events, lambda.span) else {
            continue;
        };
        if !planned_callable_spans.insert(lambda.span) {
            continue;
        }
        let mut visible = caller.params.clone();
        for implicit in &caller.implicit_receiver_names {
            push_unique_name(&mut visible, implicit.clone());
        }
        collect_assignment_targets_before(&caller.flow_events, lambda.span.start, &mut visible);

        let mut reads = Vec::new();
        collect_flow_read_names(&lambda.flow_events, &mut reads);
        let mut captures: Vec<String> = Vec::new();
        for read in reads {
            if lambda
                .params
                .iter()
                .any(|param| same_identifier_name(param, &read))
            {
                continue;
            }
            let Some(visible_name) = visible
                .iter()
                .find(|candidate| same_identifier_name(candidate, &read))
            else {
                continue;
            };
            if !captures
                .iter()
                .any(|capture| same_identifier_name(capture, visible_name))
            {
                captures.push(visible_name.clone());
            }
        }
        plans.push(LocalClosureCapturePlan {
            lambda_index,
            caller_index,
            binding_name,
            // A direct name node inside the callable span is a compiler fact
            // for an explicitly named function expression. Its assignment
            // binding is an alias, not a replacement identity. Anonymous
            // closures instead carry a binding span outside (or equal to)
            // the callable span and are named by that binding.
            rename_to_binding: lambda.name_span == lambda.span
                || !span_contains(lambda.span, lambda.name_span),
            captures,
        });
    }

    for plan in plans {
        if plan.rename_to_binding {
            // Anonymous expression-bodied closures are invoked through their
            // local binding; make that AST-proven binding their declaration
            // identity as well. Explicitly named function expressions retain
            // their syntax-declared identity and resolve the outer binding
            // through the existing local-callable binding table.
            defs[plan.lambda_index].name.clone_from(&plan.binding_name);
        }
        if plan.captures.is_empty() {
            continue;
        }
        for capture in &plan.captures {
            if !defs[plan.lambda_index]
                .params
                .iter()
                .any(|param| same_identifier_name(param, capture))
            {
                defs[plan.lambda_index].params.push(capture.clone());
            }
        }
        inject_local_closure_capture_args(
            &mut defs[plan.caller_index].flow_events,
            &plan.binding_name,
            &plan.captures,
        );
    }
}

fn local_callable_binding_for_span(events: &[FlowEvent], callable_span: Span) -> Option<String> {
    fn visit(events: &[FlowEvent], callable_span: Span, best: &mut Option<(u64, String)>) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    span,
                    target,
                    value_kind: Some(crate::AssignValueKind::CallableReference),
                    ..
                } if span_contains(*span, callable_span) => {
                    let width = span.end.saturating_sub(span.start);
                    if best.as_ref().is_none_or(|(best_width, _)| width < *best_width) {
                        *best = Some((width, target.clone()));
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    visit(then_events, callable_span, best);
                    visit(else_events, callable_span, best);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => visit(body, callable_span, best),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    visit(body, callable_span, best);
                    visit(catch_events, callable_span, best);
                    visit(finally_events, callable_span, best);
                }
                _ => {}
            }
        }
    }

    let mut best = None;
    visit(events, callable_span, &mut best);
    best.map(|(_, binding)| binding)
}

fn collect_assignment_targets_before(events: &[FlowEvent], before: u64, out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Assign { span, target, .. } | FlowEvent::AggregateAssign { span, target, .. }
                if span.start <= before =>
            {
                push_unique_name(out, target.clone());
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assignment_targets_before(then_events, before, out);
                collect_assignment_targets_before(else_events, before, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assignment_targets_before(body, before, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assignment_targets_before(body, before, out);
                collect_assignment_targets_before(catch_events, before, out);
                collect_assignment_targets_before(finally_events, before, out);
            }
            _ => {}
        }
    }
}

fn collect_expression_flow_names(flow: &crate::ExpressionFlow, out: &mut Vec<String>) {
    if let Some(place) = &flow.place {
        push_unique_name(out, place.clone());
    }
    for source in &flow.source_names {
        push_unique_name(out, source.clone());
    }
    for field in &flow.aggregate_fields {
        collect_expression_flow_names(&field.value, out);
    }
    for item in &flow.tuple_items {
        collect_expression_flow_names(item, out);
    }
    for spread in &flow.spreads {
        collect_expression_flow_names(spread, out);
    }
}

fn collect_flow_read_names(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Call { receiver, args, .. } => {
                if let Some(receiver) = receiver {
                    push_unique_name(out, receiver.clone());
                }
                for arg in args {
                    if let Some(place) = &arg.place {
                        push_unique_name(out, place.clone());
                    }
                    for source in &arg.source_names {
                        push_unique_name(out, source.clone());
                    }
                }
            }
            FlowEvent::Assign {
                source_name,
                source_names,
                ..
            } => {
                if let Some(source) = source_name {
                    push_unique_name(out, source.clone());
                }
                for source in source_names {
                    push_unique_name(out, source.clone());
                }
            }
            FlowEvent::AggregateAssign { value_flow, .. }
            | FlowEvent::Return { value_flow, .. }
            | FlowEvent::Yield { value_flow, .. } => collect_expression_flow_names(value_flow, out),
            FlowEvent::Throw { value_name, .. } | FlowEvent::Await { value_name, .. } => {
                if let Some(value) = value_name {
                    push_unique_name(out, value.clone());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_flow_read_names(then_events, out);
                collect_flow_read_names(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_flow_read_names(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_flow_read_names(body, out);
                collect_flow_read_names(catch_events, out);
                collect_flow_read_names(finally_events, out);
            }
            FlowEvent::Break { .. } | FlowEvent::Continue { .. } | FlowEvent::Lifecycle { .. } => {}
        }
    }
}

fn inject_local_closure_capture_args(events: &mut [FlowEvent], binding: &str, captures: &[String]) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                call_kind,
                args,
                ..
            } if call_invokes_local_binding(name, receiver.as_deref(), binding) => {
                for capture in captures {
                    args.push(crate::CallArg {
                        span: *span,
                        passing_mode: crate::ArgumentPassingMode::Value,
                        name: None,
                        value_text: capture.clone(),
                        place: Some(capture.clone()),
                        source_names: vec![capture.clone()],
                    });
                }
                *call_kind = crate::CallKind::Indirect;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_local_closure_capture_args(then_events, binding, captures);
                inject_local_closure_capture_args(else_events, binding, captures);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_local_closure_capture_args(body, binding, captures);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_local_closure_capture_args(body, binding, captures);
                inject_local_closure_capture_args(catch_events, binding, captures);
                inject_local_closure_capture_args(finally_events, binding, captures);
            }
            _ => {}
        }
    }
}

fn call_invokes_local_binding(name: &str, receiver: Option<&str>, binding: &str) -> bool {
    if receiver.is_some_and(|receiver| same_identifier_name(receiver, binding)) {
        return true;
    }
    let call = name.trim().trim_end_matches(bonsai_common::is_name_punctuation);
    if same_identifier_name(call, binding) {
        return true;
    }
    bonsai_common::split_qualified_name_head_tail(call)
        .is_some_and(|(head, _)| same_identifier_name(head, binding))
}

fn tail_expression_value_name(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if looks_like_identifier(node.kind()) {
        let text = node_text(node, src).trim().to_string();
        if !text.is_empty() && !looks_like_literal_value(node.kind(), &text) {
            return Some(text);
        }
    }
    let text = node_text(node, src).trim();
    (looks_like_bare_identifier(text) && !looks_like_literal_value(node.kind(), text))
        .then(|| text.to_string())
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
    // Some grammars expose a call-shaped component below the enclosing call.
    // The adapter declares those exact component kinds because the outer
    // event already owns the complete callee and argument list.
    if handler.nested_call_component_kinds.contains(&node.kind()) {
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
        // Python member access (`a.b(x).c()` → the outer call's callee is
        // an `attribute` whose `object` is the inner call). Without this,
        // every inner call in a Python method chain — e.g. the
        // `cursor.execute(sql)` in `cursor.execute(sql).fetchall()` — is
        // dropped along with its args. `subscript` covers the computed
        // form `f()[i].m()`. Descent only emits on nodes that ARE calls,
        // so pure attribute/subscript chains add no spurious events.
        "attribute",
        "subscript",
        "subscript_expression",
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
        .or_else(|| node.child_by_field_name("target"))
        // Kotlin navigation_expression children are positional rather than
        // field-labelled; source order makes the first child its receiver.
        .or_else(|| first_named_child(&node));
    if let Some(inner) = next {
        walk_method_chain_receivers(inner, file, src, handler, class_names, out);
    }
}

struct ParsedCallTarget<'tree> {
    node: Node<'tree>,
    full_text: String,
}

/// Select the semantic callee node once from grammar fields. Both call-event
/// lowering and file-local receiver facts use this result, so their span join
/// cannot drift and receiver collection does not rebuild every argument list.
fn parsed_call_target<'tree>(node: &Node<'tree>, src: &[u8]) -> Option<ParsedCallTarget<'tree>> {
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
    let method_compound = method_receiver_name(node, src);
    let erlang_remote = erlang_remote_callee(node, src);
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
        .or_else(|| first_named_child(node))
        .or_else(|| first_identifier_like_child(node))
        .or_else(|| first_identifier_descendant(*node))?;
    let mut full_text = erlang_remote
        .as_ref()
        .map(|(_, name)| name.as_str())
        .or_else(|| method_compound.as_ref().map(|(_, name)| name.as_str()))
        .unwrap_or_else(|| node_text(&callee_node, src).trim())
        .to_string();
    if node.kind() == "macro_invocation" && !full_text.ends_with('!') {
        let node_src = node_text(node, src);
        let rest = node_src.trim_start().strip_prefix(&full_text).unwrap_or_default();
        if rest.trim_start().starts_with('!') {
            full_text.push('!');
        }
    }
    if full_text.is_empty() {
        return None;
    }
    Some(ParsedCallTarget {
        node: callee_node,
        full_text,
    })
}

fn build_call_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    class_names: &[String],
) -> Option<FlowEvent> {
    let target = parsed_call_target(&node, src)?;
    let callee_node = target.node;
    let full_text = target.full_text;
    let is_method = bonsai_common::qualified_name_owner(&full_text).is_some();
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
        || handler.is_constructor_method(short)
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
            let argument_node = arg;
            // Keyword arg (Python `k=v`, some C# / JS named args, Kotlin
            // `key = value` inside value_arguments, Dart `name: value`
            // as named_argument with a `label` child).
            let (name, value_node) = if arg.kind() == "argument"
                || arg.kind() == "keyword_argument"
                || arg.kind() == "named_argument"
                || arg.kind() == "value_argument"
                || arg.kind() == "named_expression"
                || arg.kind() == "labeled_expression"
                || arg.kind() == "tuple_expression_element"
            {
                let structural_named = named_value_argument_parts(arg);
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
                    })
                    .or_else(|| structural_named.map(|(name, _)| node_text(&name, src).trim().to_string()));
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
                    .or_else(|| structural_named.map(|(_, value)| value))
                    .unwrap_or_else(|| argument_value_node(arg));
                (nm, vn)
            } else {
                (None, argument_value_node(arg))
            };
            if let Some(argument) =
                call_arg_from_nodes_with_handler(argument_node, value_node, file, src, name, handler)
            {
                args.push(argument);
            }
        }
    }

    // Solidity: direct `call_argument` siblings on the call_expression.
    // Each call_argument contains an `expression` with the actual value.
    for arg in &solidity_args {
        let inner = first_named_child(arg).unwrap_or(*arg);
        if let Some(argument) = call_arg_from_nodes_with_handler(*arg, inner, file, src, None, handler) {
            args.push(argument);
        }
    }

    // Erlang: `args: expr_args` with `args: var` (or identifier-like)
    // children. expr_args can hold complex expressions; we take each
    // named child's trimmed text as the value.
    if let Some(eargs) = erlang_args_field {
        if eargs.kind() == "expr_args" {
            let mut cursor = eargs.walk();
            for arg in eargs.named_children(&mut cursor) {
                if let Some(argument) = call_arg_from_nodes_with_handler(arg, arg, file, src, None, handler) {
                    args.push(argument);
                }
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
                        if let Some(argument) =
                            call_arg_from_nodes_with_handler(child, child, file, src, None, handler)
                        {
                            args.push(argument);
                        }
                    }
                }
                if !cur.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    let receiver_types = inline_constructed_receiver_type(&node, src).into_iter().collect();
    Some(FlowEvent::Call {
        span: span_of(file, &callee_node),
        receiver: call_receiver_from_name(&name),
        receiver_types,
        name,
        call_kind,
        args,
    })
}

/// Kotlin-style named arguments expose two named children separated by an
/// unnamed `=` token but no field names. Preserve the label/value identity
/// from that CST shape so adapters and IDG transfer never parse `value_text`.
fn named_value_argument_parts(argument: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if argument.kind() != "value_argument" {
        return None;
    }
    let mut cursor = argument.walk();
    let mut saw_equals = false;
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if !child.is_named() && child.kind() == "=" {
                saw_equals = true;
                break;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    if !saw_equals {
        return None;
    }
    let mut cursor = argument.walk();
    let children = argument.named_children(&mut cursor).collect::<Vec<_>>();
    (children.len() == 2).then(|| (children[0], children[1]))
}

/// Type of an inline constructor used as a method receiver, derived from the
/// receiver subtree (`new T().m()`, `T().m()`). This is a tree-sitter fact;
/// downstream resolution never parses the rendered receiver text.
fn inline_constructed_receiver_type(node: &Node<'_>, src: &[u8]) -> Option<String> {
    fn constructor_descendant(node: Node<'_>) -> Option<Node<'_>> {
        if matches!(
            node.kind(),
            "new_expression"
                | "object_creation_expression"
                | "instance_expression"
                | "constructor_invocation"
                | "explicit_constructor_invocation"
        ) {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(found) = constructor_descendant(child) {
                return Some(found);
            }
        }
        None
    }

    let receiver = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("receiver"))
        .or_else(|| node.child_by_field_name("target"))
        .or_else(|| first_callee_expression_child(node))?;
    let constructor = constructor_descendant(receiver)?;
    let type_node = constructor
        .child_by_field_name("type")
        .or_else(|| constructor.child_by_field_name("constructor"))
        .or_else(|| constructor.child_by_field_name("name"))
        .or_else(|| first_identifier_like_child(&constructor))
        .or_else(|| first_identifier_descendant(constructor))?;
    let type_name = node_text(&type_node, src).trim();
    (!type_name.is_empty()).then(|| type_name.to_string())
}

/// Classify explicit caller-visible write-back syntax from tree-sitter
/// nodes. The result is a language-neutral compiler fact consumed by the
/// IDG; downstream engines never inspect `&`, `ref`, `out`, or `inout`
/// source text.
fn argument_passing_mode(
    argument: Node<'_>,
    value: Node<'_>,
    handler: &GrammarHandler,
) -> crate::ArgumentPassingMode {
    handler
        .argument_passing_mode_extractor
        .map_or(crate::ArgumentPassingMode::Value, |extract| {
            extract(argument, value)
        })
}

fn writeback_argument_place(argument: Node<'_>, value: Node<'_>, src: &[u8]) -> Option<String> {
    fn addressable_operand(node: Node<'_>) -> Option<Node<'_>> {
        node.child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("operand"))
            .or_else(|| node.child_by_field_name("value"))
            .or_else(|| node.child_by_field_name("expression"))
    }

    let operand = addressable_operand(value)
        .or_else(|| addressable_operand(argument))
        .unwrap_or(value);
    argument_place(&operand, src)
}

/// Build a language-neutral call argument directly from the tree-sitter
/// nodes that prove its syntax and value semantics.
///
/// `argument` is the outer argument node (for example a Python
/// `keyword_argument` or C# `argument`), while `value` is the expression
/// passed to the callee. Keeping both nodes lets the adapter preserve the
/// argument's exact span/name wrapper and classify write-back syntax without
/// asking any downstream engine to reinterpret [`crate::CallArg::value_text`].
/// Addressability and value operands are derived here from the parsed node
/// structure.
#[must_use]
#[cfg(test)]
pub fn call_arg_from_nodes(
    argument: Node<'_>,
    value: Node<'_>,
    file: FileId,
    src: &[u8],
    name: Option<String>,
) -> Option<CallArg> {
    call_arg_from_nodes_with_handler(argument, value, file, src, name, &GENERIC_HANDLER)
}

/// Build a [`CallArg`] using the active adapter's exact expression semantics.
/// The test compatibility helper `call_arg_from_nodes` delegates here; the compiler
/// walker always calls this variant so value-free language constructs are
/// lowered from CST facts rather than repaired in the taint engine.
#[must_use]
pub fn call_arg_from_nodes_with_handler(
    argument: Node<'_>,
    value: Node<'_>,
    file: FileId,
    src: &[u8],
    name: Option<String>,
    handler: &GrammarHandler,
) -> Option<CallArg> {
    if is_comment_node_kind(argument.kind()) || is_comment_node_kind(value.kind()) {
        return None;
    }
    let value_text = normalize_call_name_whitespace(node_text(&value, src));
    if value_text.is_empty() {
        return None;
    }
    let passing_mode = argument_passing_mode(argument, value, handler);
    let place = if matches!(passing_mode, crate::ArgumentPassingMode::WriteBack) {
        writeback_argument_place(argument, value, src)
    } else {
        argument_place(&value, src)
    };
    Some(CallArg {
        passing_mode,
        span: span_of(file, &argument),
        name,
        value_text,
        place,
        source_names: extract_rhs_expr_operands(&value, src, handler),
    })
}

/// Build a [`CallArg`] from an outer grammar argument node, unwrapping only
/// parser-declared argument wrappers. This is useful for adapter-specific
/// lowerings that still have the original tree-sitter node but do not use the
/// generic call walker.
#[must_use]
#[cfg(test)]
pub fn call_arg_from_node(
    argument: Node<'_>,
    file: FileId,
    src: &[u8],
    name: Option<String>,
) -> Option<CallArg> {
    let value = argument_value_node(argument);
    call_arg_from_nodes(argument, value, file, src, name)
}

/// Build a call argument using the active adapter's exact expression
/// semantics. Adapter-specific lowerings must use this variant instead of the
/// legacy generic helper.
#[must_use]
pub fn call_arg_from_node_with_handler(
    argument: Node<'_>,
    file: FileId,
    src: &[u8],
    name: Option<String>,
    handler: &GrammarHandler,
) -> Option<CallArg> {
    let value = argument_value_node(argument);
    call_arg_from_nodes_with_handler(argument, value, file, src, name, handler)
}

/// Lower all named children of an adapter-classified construct into call
/// arguments. Node selection and the synthetic callee identity remain in the
/// adapter; this helper only performs canonical argument lowering.
#[must_use]
pub fn named_child_call_args_with_handler(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<CallArg> {
    let mut args = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(argument) = call_arg_from_node_with_handler(child, file, src, None, handler) {
            args.push(argument);
        }
    }
    args
}

fn argument_value_node(argument: Node<'_>) -> Node<'_> {
    if !matches!(
        argument.kind(),
        "argument"
            | "call_argument"
            | "keyword_argument"
            | "named_argument"
            | "named_expression"
            | "labeled_expression"
            | "tuple_expression_element"
            | "value_argument"
    ) {
        return unwrap_transparent_expression(argument);
    }
    // Dart represents one projected argument (`c.capacity`) as sibling
    // nodes inside the `argument` wrapper: an identifier followed by one or
    // more selector nodes.  The wrapper, not its last selector, is therefore
    // the value expression proved by the CST.
    if argument.kind() == "argument" && has_split_selector_projection(&argument) {
        return argument;
    }
    if let Some(value) = argument
        .child_by_field_name("value")
        .or_else(|| argument.child_by_field_name("expression"))
        .or_else(|| argument.child_by_field_name("argument"))
        .or_else(|| argument.child_by_field_name("operand"))
    {
        return unwrap_transparent_expression(value);
    }
    let name_id = argument.child_by_field_name("name").map(|name| name.id());
    let label_id = argument.child_by_field_name("label").map(|label| label.id());
    let mut cursor = argument.walk();
    let mut value = None;
    for child in argument.named_children(&mut cursor) {
        if Some(child.id()) != name_id && Some(child.id()) != label_id {
            value = Some(child);
        }
    }
    unwrap_transparent_expression(value.unwrap_or(argument))
}

/// Peel parser-declared, single-child expression wrappers while preserving
/// the actual operator/member/call node that proves value semantics. The
/// Solidity grammar uses this shape for every call argument
/// (`call_argument -> expression -> member_expression`); classifying the
/// generic wrapper instead of its child loses an otherwise exact static
/// access path such as `env.command`.
fn unwrap_transparent_expression(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "expression" {
        let mut cursor = node.walk();
        let mut children = node.named_children(&mut cursor);
        let Some(only_child) = children.next() else {
            break;
        };
        if children.next().is_some() {
            break;
        }
        node = only_child;
    }
    node
}

/// Whether a parser wrapper contains one static dotted value as a base node
/// followed by selector siblings. Tree-sitter-Dart uses this shape for call
/// arguments such as `c.capacity`.
fn has_split_selector_projection(node: &Node<'_>) -> bool {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    children.len() > 1
        && matches!(children[0].kind(), "identifier" | "this" | "super")
        && children[1..].iter().all(|child| child.kind() == "selector")
}

fn split_selector_projection(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if !has_split_selector_projection(node) {
        return None;
    }
    let (projections, _) = split_selector_sequences(node, src)?;
    (projections.len() == 1)
        .then(|| projections.into_iter().next())
        .flatten()
}

/// Find static Dart-style selector chains among a node's named children.
/// Compound expressions keep unrelated operands as siblings, so return the
/// exact child ids consumed by each projection as well as its canonical path.
fn split_selector_sequences(node: &Node<'_>, src: &[u8]) -> Option<(Vec<String>, ahash::AHashSet<usize>)> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    let mut projections = Vec::new();
    let mut consumed = ahash::AHashSet::default();
    let mut index = 0usize;
    while index < children.len() {
        let base = children[index];
        if !matches!(base.kind(), "identifier" | "this" | "super") {
            index += 1;
            continue;
        }
        let mut parts = vec![node_text(&base, src).trim().to_string()];
        let mut selector_ids = Vec::new();
        let mut next = index + 1;
        while let Some(selector) = children.get(next) {
            if selector.kind() != "selector" || first_named_child_of_kind(selector, "argument_part").is_some()
            {
                break;
            }
            let Some(inner) = first_named_child(selector) else {
                break;
            };
            if !matches!(
                inner.kind(),
                "unconditional_assignable_selector" | "conditional_assignable_selector"
            ) {
                break;
            }
            let Some(field) =
                first_identifier_like_child(&inner).or_else(|| first_identifier_descendant(inner))
            else {
                break;
            };
            let field = node_text(&field, src).trim();
            if field.is_empty() {
                break;
            }
            parts.push(field.to_string());
            selector_ids.push(selector.id());
            next += 1;
        }
        if selector_ids.is_empty() || parts.iter().any(String::is_empty) {
            index += 1;
            continue;
        }
        consumed.insert(base.id());
        consumed.extend(selector_ids);
        projections.push(parts.join("."));
        index = next;
    }
    (!projections.is_empty()).then_some((projections, consumed))
}

/// A syntax-proven value projection represented as a call node without an
/// argument list. Elixir parses `c.capacity` as `call(target: dot(...))`;
/// this is a field read, not a method invocation.
fn argumentless_dot_projection(node: &Node<'_>, src: &[u8]) -> Option<String> {
    if node.kind() != "call" || node.child_by_field_name("arguments").is_some() {
        return None;
    }
    let target = node.child_by_field_name("target")?;
    fn collect(node: Node<'_>, src: &[u8], parts: &mut Vec<String>) -> bool {
        if node.kind() == "dot" {
            let mut cursor = node.walk();
            let children: Vec<_> = node.named_children(&mut cursor).collect();
            let Some(left) = node
                .child_by_field_name("left")
                .or_else(|| children.first().copied())
            else {
                return false;
            };
            let Some(right) = node
                .child_by_field_name("right")
                .or_else(|| children.last().copied())
            else {
                return false;
            };
            return left.id() != right.id() && collect(left, src, parts) && collect(right, src, parts);
        }
        if !matches!(node.kind(), "identifier" | "alias" | "atom") {
            return false;
        }
        let text = node_text(&node, src).trim();
        if text.is_empty() {
            return false;
        }
        parts.push(text.to_string());
        true
    }
    let mut parts = Vec::new();
    (collect(target, src, &mut parts) && parts.len() > 1).then(|| parts.join("."))
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
fn extract_rhs_expr_operands(node: &Node<'_>, src: &[u8], handler: &GrammarHandler) -> Vec<String> {
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
        "yul_identifier",
    ];
    if is_large_literal_initializer_node(node.kind(), node)
        || node_is_value_free_expression(*node, src, handler)
    {
        return Vec::new();
    }
    if let Some(projection) = split_selector_projection(node, src) {
        return vec![projection];
    }
    let mut out: Vec<String> = Vec::new();
    let mut stack: Vec<Node<'_>> = vec![*node];
    while let Some(n) = stack.pop() {
        if is_large_literal_initializer_node(n.kind(), &n) || node_is_value_free_expression(n, src, handler) {
            continue;
        }
        if n.kind() == "vararg_expression" {
            out.push(SYNTHETIC_VARARGS_PARAM.to_string());
            continue;
        }
        if let Some(projection) = argumentless_dot_projection(&n, src) {
            out.push(projection);
            continue;
        }
        let split_selector_children = split_selector_sequences(&n, src);
        if let Some((projections, _)) = &split_selector_children {
            out.extend(projections.iter().cloned());
        }
        out.extend(call_receiver_source_names(&n, src, handler));
        // Objective-C messages expose selector components and value
        // arguments as interleaved direct children. Walk only the actual
        // argument children selected by tree-sitter field metadata; method
        // selector identifiers are syntax, not value operands.
        if handler
            .special_forms
            .contains(&SyntaxSpecialForm::DirectCallArguments)
            && handler.call_ref_kinds.contains(&n.kind())
        {
            let mut cursor = n.walk();
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.is_named() && !matches!(cursor.field_name(), Some("receiver" | "method")) {
                        stack.push(child);
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            continue;
        }
        // Avoid treating nested-call callee names as value operands. Walk the
        // parsed argument containers instead, so constructor initializers and
        // compound call arguments retain their value carriers without any
        // rendered-expression parsing.
        if handler.call_ref_kinds.contains(&n.kind()) {
            // A chained call's receiver may itself be a call whose arguments
            // determine the outer result (`pattern.matcher(value).replace`).
            // The receiver-base collector intentionally returns only the
            // leftmost carrier, so recurse through the parsed receiver
            // expression to retain those nested argument dependencies while
            // still excluding method-name syntax.
            if let Some(receiver) = call_receiver_node(&n, handler) {
                out.extend(extract_rhs_expr_operands(&receiver, src, handler));
            }
            for args_node in call_argument_containers(n) {
                let mut arg_cursor = args_node.walk();
                for arg in args_node.named_children(&mut arg_cursor) {
                    out.extend(extract_rhs_expr_operands(&arg, src, handler));
                }
            }
            continue;
        }
        if handler.member_expression_kinds.contains(&n.kind()) {
            if let Some(name) = normalize_member_name(&n, src, handler) {
                let bare = name
                    .trim_start_matches(bonsai_common::is_name_punctuation)
                    .to_string();
                out.push(name);
                if !bare.is_empty() {
                    out.push(bare);
                }
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
                .or_else(|| {
                    let mut cursor = n.walk();
                    n.named_children(&mut cursor).skip(1).last()
                })
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
            if bonsai_common::qualified_name_owner(&place).is_some() {
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
                } else if let Some(sigil) = identifier_parent_sigil(n, src) {
                    out.push(format!("{sigil}{cleaned}"));
                }
            }
        }
        let mut child_cursor = n.walk();
        for child in n.named_children(&mut child_cursor) {
            if split_selector_children
                .as_ref()
                .is_some_and(|(_, consumed)| consumed.contains(&child.id()))
            {
                continue;
            }
            stack.push(child);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Return the exact value operands proved by one parsed expression.
///
/// This is an adapter-facing compiler primitive: the adapter decides that a
/// grammar construct carries its expression operands (for example, an
/// exception constructor's arguments), while this helper performs the
/// vocabulary-free CST walk. Shared analyses consume the resulting typed
/// event and never reinterpret rendered source text.
#[must_use]
pub fn expression_operand_names_with_handler(
    node: &Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<String> {
    extract_rhs_expr_operands(node, src, handler)
}

/// Whether the adapter's grammar proves that `node` computes metadata about
/// an operand rather than reading its runtime value. This is deliberately a
/// CST decision: the shared compiler never scans rendered source for operator
/// keywords, and every exact spelling/kind comes from the active adapter.
fn node_is_value_free_expression(node: Node<'_>, src: &[u8], handler: &GrammarHandler) -> bool {
    if handler.value_free_expression_kinds.contains(&node.kind()) {
        return true;
    }
    if !handler.value_free_unary_operators.is_empty() {
        let mut cursor = node.walk();
        if node
            .children(&mut cursor)
            .filter(|child| !child.is_named())
            .any(|child| handler.value_free_unary_operators.contains(&child.kind()))
        {
            return true;
        }
    }
    if handler.value_free_call_names.is_empty() || !handler.is_call(node.kind()) {
        return false;
    }
    parsed_call_target(&node, src).is_some_and(|target| {
        handler
            .value_free_call_names
            .contains(&short_name_of(&target.full_text))
    })
}

fn identifier_parent_sigil(node: Node<'_>, src: &[u8]) -> Option<&'static str> {
    let parent = node.parent()?;
    if !matches!(
        parent.kind(),
        "scalar" | "array" | "hash" | "variable_name" | "identifier_dollar_escaped"
    ) {
        return None;
    }
    ["$", "@", "%"]
        .into_iter()
        .find(|sigil| has_direct_token(&parent, src, sigil))
}

fn call_receiver_source_names(node: &Node<'_>, src: &[u8], handler: &GrammarHandler) -> Vec<String> {
    if !handler.call_ref_kinds.contains(&node.kind()) {
        return Vec::new();
    }
    let Some(receiver) = call_receiver_node(node, handler) else {
        return Vec::new();
    };
    receiver_value_bases(receiver, src, handler)
}

fn call_receiver_node<'tree>(node: &Node<'tree>, handler: &GrammarHandler) -> Option<Node<'tree>> {
    node.child_by_field_name("receiver")
        .or_else(|| node.child_by_field_name("object"))
        .or_else(|| node.child_by_field_name("invocant"))
        .or_else(|| {
            let callee = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("callee"))
                // Kotlin and Swift call expressions expose their callee as
                // the first named child rather than through a field.
                .or_else(|| first_named_child(node))?;
            member_receiver_node(callee, handler)
        })
}

/// Select the value side of a member expression from grammar structure.
/// Kotlin/Swift navigation expressions use positional children; the other
/// supported grammars expose one of the named receiver fields below.
fn member_receiver_node<'tree>(node: Node<'tree>, handler: &GrammarHandler) -> Option<Node<'tree>> {
    let member = if node.kind() == "expression" {
        first_named_child(&node).unwrap_or(node)
    } else {
        node
    };
    if !handler.member_expression_kinds.contains(&member.kind()) {
        return None;
    }
    member
        .child_by_field_name("object")
        .or_else(|| member.child_by_field_name("receiver"))
        .or_else(|| member.child_by_field_name("target"))
        .or_else(|| member.child_by_field_name("expression"))
        // tree-sitter-rust field expressions use `value` for the receiver.
        .or_else(|| member.child_by_field_name("value"))
        .or_else(|| first_named_child(&member))
}

fn receiver_value_bases(node: Node<'_>, src: &[u8], handler: &GrammarHandler) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(base) = leftmost_value_base(node, src, handler) {
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

fn leftmost_value_base(node: Node<'_>, src: &[u8], handler: &GrammarHandler) -> Option<String> {
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
    if handler.call_ref_kinds.contains(&kind) {
        if let Some(receiver) = call_receiver_node(&node, handler) {
            return leftmost_value_base(receiver, src, handler);
        }
    }
    if handler.member_expression_kinds.contains(&kind) || handler.subscript_expression_kinds.contains(&kind) {
        if let Some(object) = node
            .child_by_field_name("object")
            .or_else(|| node.child_by_field_name("receiver"))
            .or_else(|| node.child_by_field_name("value"))
        {
            return leftmost_value_base(object, src, handler);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(base) = leftmost_value_base(child, src, handler) {
            return Some(base);
        }
    }
    None
}

fn receiver_base_from_text(text: &str) -> Option<String> {
    let normalized = normalise_qualified_text(text);
    let trimmed = normalized
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    if trimmed.is_empty() {
        return None;
    }
    let candidate = bonsai_common::qualified_name_segments(trimmed)
        .first()
        .copied()
        .unwrap_or(trimmed)
        .trim()
        .trim_start_matches(bonsai_common::is_name_punctuation);
    looks_like_bare_identifier(candidate).then(|| candidate.to_string())
}

fn push_receiver_base_variants(out: &mut Vec<String>, base: &str) {
    let base = base.trim();
    if base.is_empty() {
        return;
    }
    let cleaned = base.trim_start_matches(bonsai_common::is_name_punctuation);
    if looks_like_bare_identifier(cleaned) {
        out.push(cleaned.to_string());
        if cleaned != base {
            out.push(base.to_string());
        }
    }
}

/// Identifier-continue byte: `_`, `$`, or ASCII alphanumeric.
pub(crate) fn is_ident_continue_byte(byte: u8) -> bool {
    byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric()
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
    let cleaned = last_tok
        .trim_matches(|c: char| {
            !(c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '@' | '%' | '!' | '?'))
        })
        .to_string();
    // Reject fragments that aren't a plausible bare lvalue. Structured
    // extractor/destructuring bindings are recovered from their CST pattern
    // nodes, so a wrapper fragment such as `Envelope(kind` is never a
    // semantic target.
    if cleaned.contains(['(', ')']) || cleaned.chars().any(|c: char| c.is_whitespace()) {
        return String::new();
    }
    cleaned
}

/// Compare two identifier names, ignoring leading sigils (`$`, `@`, `%`)
/// so Perl `$foo` and adapter-emitted `foo` map to the same binding.
fn same_identifier_name(left: &str, right: &str) -> bool {
    let left_bare = left.trim().trim_start_matches(['$', '@', '%']);
    let right_bare = right.trim().trim_start_matches(['$', '@', '%']);
    left_bare == right_bare
}

fn extra_lhs_binding_targets(node: &Node<'_>, src: &[u8], primary: &str) -> Vec<String> {
    let Some(lhs) = assignment_lhs_node(node) else {
        return Vec::new();
    };
    let Some(pattern) = destructured_assignment_pattern(lhs) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for target in binding_targets_from_pattern_node(&pattern, src) {
        if !target.is_empty() && target != primary && !out.iter().any(|t| t == &target) {
            out.push(target);
        }
    }
    out
}

/// Map grammar-proven keyed pattern bindings to exact projections of the RHS
/// container. Tree-sitter grammars either expose `key` / `value` fields on a
/// pair node or retain an anonymous `=>` token between two named children
/// (PHP array destructuring). Both shapes are parsed syntax relationships;
/// this helper never scans or splits the surrounding assignment rendering.
fn keyed_lhs_binding_sources(node: &Node<'_>, src: &[u8], rhs_base: &str) -> Vec<(String, String)> {
    let Some(lhs) = assignment_lhs_node(node) else {
        return Vec::new();
    };
    let Some(pattern) = destructured_assignment_pattern(lhs) else {
        return Vec::new();
    };
    let mut keyed = Vec::new();
    collect_keyed_pattern_bindings(pattern, src, &mut Vec::new(), &mut keyed);
    let base = rhs_base.trim().trim_end_matches('.');
    if base.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (binding, path) in keyed {
        if path.is_empty() {
            continue;
        }
        let source = format!("{base}.{}", path.join("."));
        if !out
            .iter()
            .any(|existing| existing == &(binding.clone(), source.clone()))
        {
            out.push((binding, source));
        }
    }
    out
}

fn collect_keyed_pattern_bindings(
    node: Node<'_>,
    src: &[u8],
    prefix: &mut Vec<String>,
    out: &mut Vec<(String, Vec<String>)>,
) {
    if let (Some(key), Some(value)) = (
        node.child_by_field_name("key")
            .or_else(|| node.child_by_field_name("name")),
        node.child_by_field_name("value")
            .or_else(|| node.child_by_field_name("pattern")),
    ) {
        if key.id() != value.id() {
            if let Some(key) = expression_flow::static_field_name(key, src) {
                prefix.push(key);
                collect_keyed_pattern_value(value, src, prefix, out);
                prefix.pop();
                return;
            }
        }
    }

    // PHP's list-literal pattern does not field its key/value children, but
    // the grammar retains the `=>` terminal between them. Walk the direct CST
    // children so nested expressions cannot be mistaken for pair syntax.
    let mut cursor = node.walk();
    let mut previous_named = None;
    let mut awaiting_value = false;
    let mut handled_value_ids = Vec::new();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.is_named() {
                if awaiting_value {
                    if let Some(key_node) = previous_named.take() {
                        if let Some(key) = expression_flow::static_field_name(key_node, src) {
                            prefix.push(key);
                            collect_keyed_pattern_value(child, src, prefix, out);
                            prefix.pop();
                            handled_value_ids.push(child.id());
                        }
                    }
                    awaiting_value = false;
                } else {
                    previous_named = Some(child);
                }
            } else if node_text(&child, src).trim() == "=>" {
                awaiting_value = true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    let mut named = node.walk();
    for child in node.named_children(&mut named) {
        if !handled_value_ids.contains(&child.id()) {
            collect_keyed_pattern_bindings(child, src, prefix, out);
        }
    }
}

fn collect_keyed_pattern_value(
    value: Node<'_>,
    src: &[u8],
    prefix: &mut Vec<String>,
    out: &mut Vec<(String, Vec<String>)>,
) {
    if destructured_assignment_pattern(value).is_some() {
        collect_keyed_pattern_bindings(value, src, prefix, out);
        return;
    }
    let targets = binding_targets_from_pattern_node(&value, src);
    if targets.len() == 1 && !prefix.is_empty() {
        out.push((targets[0].clone(), prefix.clone()));
    }
}

/// Return the parsed aggregate binding pattern for a multi-target assignment.
///
/// This is deliberately a syntax-kind whitelist. Walking every identifier
/// below an arbitrary LHS confuses place expressions with destructuring: in C,
/// `env.cmd[index] = value` contains the identifier `env`, but it writes one
/// indexed field rather than rebinding the whole `env` object. Tree-sitter
/// grammars represent real parallel/destructured bindings with one of these
/// aggregate pattern/list nodes, so only those nodes may fan out into extra
/// assignment targets.
fn destructured_assignment_pattern(node: Node<'_>) -> Option<Node<'_>> {
    const AGGREGATE_BINDING_KINDS: &[&str] = &[
        "array_pattern",
        "destructuring_pattern",
        "expression_list",
        "left_assignment_list",
        "list",
        "list_expression",
        "list_literal",
        "list_pattern",
        "multi_variable_declaration",
        "object_pattern",
        "pattern_list",
        "struct_pattern",
        "tuple",
        "tuple_pattern",
        "variable_list",
        "variables",
    ];
    if AGGREGATE_BINDING_KINDS.contains(&node.kind()) {
        return Some(node);
    }

    // Perl represents `my ($a, $b)` as one `variable_declaration` with a
    // repeated grammar field named `variables`; the singular `my $a` form
    // instead has one `variable` field. Repeated binding fields are the CST's
    // declaration that this is parallel binding, so the wrapper itself is the
    // aggregate pattern.
    if node.kind() == "variable_declaration" {
        let mut cursor = node.walk();
        let mut variable_fields = 0usize;
        if cursor.goto_first_child() {
            loop {
                if cursor.node().is_named() && cursor.field_name() == Some("variables") {
                    variable_fields += 1;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        if variable_fields > 1 {
            return Some(node);
        }
    }

    // Swift and a few pattern grammars use a generic `pattern` wrapper. It is
    // aggregate only when the CST itself exposes multiple pattern children;
    // a single identifier wrapper is not destructuring.
    if node.kind() == "pattern" {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        if children.len() > 1 {
            return Some(node);
        }
        return children.into_iter().find_map(destructured_assignment_pattern);
    }

    // Declaration wrappers may contain the actual parsed pattern as a field.
    // Follow only grammar-declared pattern/declarator relationships; never
    // descend through member, field, or subscript place expressions.
    for field in ["pattern", "declarator"] {
        if let Some(child) = node.child_by_field_name(field) {
            if let Some(pattern) = destructured_assignment_pattern(child) {
                return Some(pattern);
            }
        }
    }
    None
}

fn assignment_lhs_node<'tree>(node: &Node<'tree>) -> Option<Node<'tree>> {
    node.child_by_field_name("left")
        .or_else(|| node.child_by_field_name("lhs"))
        .or_else(|| node.child_by_field_name("target"))
        .or_else(|| node.child_by_field_name("pattern"))
        // Prefer an aggregate binding container over a repeated singular
        // `name` field. Lua's `variable_list` gives each child the `name`
        // field, so asking for `name` first silently collapses `ok, value`
        // to only `ok`.
        .or_else(|| first_named_child_of_kind(node, "variable_list"))
        .or_else(|| first_named_child_of_kind(node, "variables"))
        .or_else(|| first_named_child_of_kind(node, "multi_variable_declaration"))
        .or_else(|| first_named_child_of_kind(node, "pattern"))
        .or_else(|| first_named_child_of_kind(node, "tuple_pattern"))
        .or_else(|| first_named_child_of_kind(node, "array_pattern"))
        .or_else(|| first_named_child_of_kind(node, "list_pattern"))
        .or_else(|| first_named_child_of_kind(node, "left_assignment_list"))
        .or_else(|| first_named_child_of_kind(node, "tuple"))
        // A grammar-declared singular binding beats an unfielded expression
        // list. Go `var_spec`, for example, has `name: identifier` and
        // `value: expression_list`; selecting the latter as an LHS turns RHS
        // identifiers into phantom destructured bindings. Real multi-target
        // assignment grammars expose `left`/`lhs` or one of the aggregate
        // binding containers above.
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| first_named_child_of_kind(node, "expression_list"))
        .or_else(|| node.child_by_field_name("declarator"))
}

/// Return the parser-declared base and index expressions of a subscript
/// place. This deliberately consumes tree-sitter fields/children rather than
/// splitting the rendered LHS text; the synthetic item-write call therefore
/// carries the same exact argument facts as an ordinary parsed call.
fn subscript_place_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if !matches!(
        node.kind(),
        "subscript_expression"
            | "subscript"
            | "element_reference"
            | "array_access"
            | "element_access_expression"
            | "bracket_index_expression"
            | "index_expression"
            | "indexing_expression"
    ) {
        return None;
    }
    let base = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| node.child_by_field_name("argument"))
        .or_else(|| node.child_by_field_name("base"))
        .or_else(|| node.child_by_field_name("receiver"));
    let key = node
        .child_by_field_name("index")
        .or_else(|| node.child_by_field_name("subscript"))
        .or_else(|| node.child_by_field_name("key"));
    if let (Some(base), Some(key)) = (base, key) {
        return Some((base, key));
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    match children.as_slice() {
        [base, key, ..] => Some((*base, *key)),
        _ => None,
    }
}

fn ruby_append_mutation_assignment(
    node: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
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
    let mut source_names = extract_rhs_expr_operands(&right, src, handler);
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

/// Fold every run of ASCII whitespace (spaces, tabs, newlines) in
/// `raw` into a single space, trim the result, and remove padding
/// around dotted qualified-name separators. Used to normalise callee
/// text across multi-line method chains — a Rust / Swift / Kotlin /
/// Java expression spanning multiple source lines would otherwise
/// keep its embedded newlines + indentation in the callee's displayed
/// `name` field, cluttering the `calls` column and breaking
/// downstream substring filters and sanitizer/sink matcher regexes.
#[must_use]
pub fn normalize_call_name_whitespace(raw: &str) -> String {
    let mut folded = String::with_capacity(raw.len());
    let mut in_ws = false;
    for c in raw.chars() {
        if c.is_whitespace() {
            if !in_ws {
                if !folded.is_empty() {
                    folded.push(' ');
                }
                in_ws = true;
            }
        } else {
            folded.push(c);
            in_ws = false;
        }
    }
    // `in_ws` at end means we pushed a trailing space; strip it.
    if folded.ends_with(' ') {
        folded.pop();
    }
    let mut out = String::with_capacity(folded.len());
    let mut chars = folded.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '.' {
            while out.ends_with(' ') {
                out.pop();
            }
            out.push('.');
            while matches!(chars.peek(), Some(' ')) {
                chars.next();
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Return the final identifier segment of an adapter-classified name.
/// Shared lowering recognizes structural punctuation boundaries, not a union
/// of source-language qualifier spellings.
pub fn short_name_of(raw: &str) -> &str {
    let trimmed = raw.trim().trim_matches(bonsai_common::is_name_punctuation);
    bonsai_common::short_qualified_tail(trimmed)
}

/// Test-fixture helper for varying only function kinds in cross-grammar kit
/// tests. Production adapters use explicit local handlers.
#[must_use]
#[cfg(test)]
pub const fn with_fn_kinds(fn_kinds: &'static [&'static str]) -> GrammarHandler {
    with_fn_kinds_and_implicit_receivers(
        fn_kinds,
        GENERIC_HANDLER.implicit_receiver_names,
        GENERIC_HANDLER.implicit_receiver_prefixes,
    )
}

/// Test-fixture variant with explicit receiver spellings.
#[cfg(test)]
pub const fn with_fn_kinds_and_implicit_receivers(
    fn_kinds: &'static [&'static str],
    implicit_receiver_names: &'static [&'static str],
    implicit_receiver_prefixes: &'static [&'static str],
) -> GrammarHandler {
    GrammarHandler {
        fn_kinds,
        class_kinds: GENERIC_HANDLER.class_kinds,
        class_decl_kinds: GENERIC_HANDLER.class_decl_kinds,
        nested_type_ownership: GENERIC_HANDLER.nested_type_ownership,
        method_kinds: GENERIC_HANDLER.method_kinds,
        method_context_kinds: GENERIC_HANDLER.method_context_kinds,
        method_owner_barrier_kinds: GENERIC_HANDLER.method_owner_barrier_kinds,
        constructor_method_kinds: GENERIC_HANDLER.constructor_method_kinds,
        constructor_names: GENERIC_HANDLER.constructor_names,
        if_kinds: GENERIC_HANDLER.if_kinds,
        for_kinds: GENERIC_HANDLER.for_kinds,
        foreach_kinds: GENERIC_HANDLER.foreach_kinds,
        while_kinds: GENERIC_HANDLER.while_kinds,
        do_kinds: GENERIC_HANDLER.do_kinds,
        loop_kinds: GENERIC_HANDLER.loop_kinds,
        call_kinds: GENERIC_HANDLER.call_kinds,
        nested_call_component_kinds: GENERIC_HANDLER.nested_call_component_kinds,
        pseudo_call_extractor: GENERIC_HANDLER.pseudo_call_extractor,
        syntax_event_extractor: GENERIC_HANDLER.syntax_event_extractor,
        pseudo_call_receiver_extractor: GENERIC_HANDLER.pseudo_call_receiver_extractor,
        argument_passing_mode_extractor: GENERIC_HANDLER.argument_passing_mode_extractor,
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
        special_forms: GENERIC_HANDLER.special_forms,
        runtime_type_guard_calls: GENERIC_HANDLER.runtime_type_guard_calls,
        runtime_type_guard_operators: GENERIC_HANDLER.runtime_type_guard_operators,
        runtime_typeof_operators: GENERIC_HANDLER.runtime_typeof_operators,
        runtime_type_equality_operators: GENERIC_HANDLER.runtime_type_equality_operators,
        value_free_expression_kinds: GENERIC_HANDLER.value_free_expression_kinds,
        value_free_call_names: GENERIC_HANDLER.value_free_call_names,
        value_free_unary_operators: GENERIC_HANDLER.value_free_unary_operators,
        call_ref_kinds: GENERIC_HANDLER.call_ref_kinds,
        member_expression_kinds: GENERIC_HANDLER.member_expression_kinds,
        subscript_expression_kinds: GENERIC_HANDLER.subscript_expression_kinds,
        sigil_variable_kinds: GENERIC_HANDLER.sigil_variable_kinds,
        global_variable_kinds: GENERIC_HANDLER.global_variable_kinds,
        subscript_base_call_refs: GENERIC_HANDLER.subscript_base_call_refs,
        non_call_ref_names: GENERIC_HANDLER.non_call_ref_names,
        synthetic_call_ref_names: GENERIC_HANDLER.synthetic_call_ref_names,
        call_name_suffix_tokens: GENERIC_HANDLER.call_name_suffix_tokens,
        syntax_error_tolerant_call_names: GENERIC_HANDLER.syntax_error_tolerant_call_names,
        callable_reference_kinds: GENERIC_HANDLER.callable_reference_kinds,
        callable_reference_extractor: GENERIC_HANDLER.callable_reference_extractor,
        method_receiver_param_index: GENERIC_HANDLER.method_receiver_param_index,
        implicit_receiver_names,
        implicit_receiver_prefixes,
        tail_expression_returns: GENERIC_HANDLER.tail_expression_returns,
        void_return_type_names: GENERIC_HANDLER.void_return_type_names,
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

/// Build exact assignment-to-RHS node links from the parsed syntax tree. The
/// traversal is iterative and uncapped. These are syntax facts rather than a
/// projection of flow events: adapters may attach an assignment event to a
/// callable after the generic walk (for example, a Java class constant used by
/// a method), and its original Tree-sitter relationship must still be present.
#[must_use]
pub fn extract_assignment_value_facts(
    tree: &Tree,
    file: FileId,
    handler: &GrammarHandler,
    src: &[u8],
) -> Vec<crate::AssignmentValueFact> {
    let mut facts = Vec::new();
    let mut node_stack = vec![tree.root_node()];
    while let Some(node) = node_stack.pop() {
        let span = span_of(file, &node);
        let is_assignment = handler.is_assignment(node.kind())
            && (node.kind() != "binary_operator" || binary_operator_is_assignment(&node, src));
        if is_assignment {
            let target = assignment_target_pattern_node(node, src);
            if let Some(value) = assignment_value_node(node, target) {
                let target_span = target.map(|target| span_of(file, &target));
                let value_span = span_of(file, &value);
                if value_span.start >= span.start
                    && value_span.end <= span.end
                    && value_span.start < value_span.end
                {
                    let direct_call_name = if callable_reference_name(&value, src, handler).is_some() {
                        None
                    } else {
                        extract_direct_call_info(&value, src, handler)
                            .and_then(|(name, _)| name)
                            .or_else(|| {
                                handler
                                    .is_call(value.kind())
                                    .then(|| parsed_call_target(&value, src))
                                    .flatten()
                                    .map(|target| normalize_call_name_whitespace(&target.full_text))
                            })
                    };
                    let direct_call_receiver = direct_call_name.as_deref().and_then(call_receiver_from_name);
                    let call_sites = if callable_reference_name(&value, src, handler).is_some() {
                        Vec::new()
                    } else {
                        expression_flow::expression_call_spans(value, file, handler)
                    };
                    facts.push(crate::AssignmentValueFact {
                        assignment_span: span,
                        target: assignment_target_node(node, src)
                            .and_then(|target| argument_place(&target, src)),
                        target_is_immutable: false,
                        target_owner: None,
                        target_span,
                        value_span,
                        call_sites,
                        value_flow: expression_flow::expression_flow_from_node_with_handler(
                            value, file, src, handler,
                        ),
                        exact_callable_return: None,
                        exact_static_call_args: None,
                        direct_call_name,
                        direct_call_receiver,
                    });
                }
            }
        }
        let mut cursor = node.walk();
        node_stack.extend(node.named_children(&mut cursor));
    }
    facts.sort_by_key(|fact| {
        (
            fact.assignment_span.start,
            fact.assignment_span.end,
            fact.target_span.map_or(0, |span| span.start),
            fact.target_span.map_or(0, |span| span.end),
            fact.value_span.start,
            fact.value_span.end,
        )
    });
    facts.dedup();
    facts
}

/// Collect receiver-expression dependencies directly from call CST nodes.
/// The call event's own span is the stable join key used by IDG transfer;
/// receiver rendering remains available for diagnostics but is never parsed
/// for value carriers.
pub fn extract_call_receiver_facts(
    tree: &Tree,
    file: FileId,
    handler: &GrammarHandler,
    src: &[u8],
) -> Vec<crate::CallReceiverFact> {
    let mut facts = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let receiver_and_span = if handler.is_call(node.kind()) {
            call_receiver_node(&node, handler)
                .zip(parsed_call_target(&node, src))
                .map(|(receiver, target)| (receiver, span_of(file, &target.node)))
        } else {
            handler
                .pseudo_call_receiver_extractor
                .and_then(|extract| extract(node, src))
                .map(|receiver| (receiver, span_of(file, &node)))
        };
        if let Some((receiver, call_span)) = receiver_and_span {
            let value_flow =
                expression_flow::expression_flow_from_node_with_handler(receiver, file, src, handler);
            facts.push(crate::CallReceiverFact {
                call_span,
                receiver_span: span_of(file, &receiver),
                value_flow,
                role: crate::CallReceiverRole::Value,
                static_value: None,
            });
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    facts.sort_by_key(|fact| (fact.call_span.start, fact.call_span.end));
    facts.dedup();
    facts
}

/// Collect nested call-argument value shapes from the same Tree-sitter nodes
/// that produced the adapter-normalized [`FlowEvent::Call`] records.
///
/// Flow events supply canonical callee spans and argument order. The syntax
/// tree supplies exact argument expression nodes. Joining them here keeps
/// downstream engines independent of language delimiters and rendered
/// argument text.
#[must_use]
pub fn extract_call_argument_value_facts(
    tree: &Tree,
    file: FileId,
    defs: &[crate::Decl],
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<crate::CallArgumentValueFact> {
    fn direct_call_callee_span(
        node: Node<'_>,
        file: FileId,
        src: &[u8],
        handler: &GrammarHandler,
    ) -> Option<Span> {
        if handler.call_ref_kinds.contains(&node.kind()) {
            return parsed_call_target(&node, src).map(|target| span_of(file, &target.node));
        }
        let child = transparent_direct_call_child(&node, handler)?;
        direct_call_callee_span(child, file, src, handler)
    }

    fn collect_requests(events: &[FlowEvent], out: &mut Vec<(Span, usize, Span)>) {
        for event in events {
            match event {
                FlowEvent::Call { span, args, .. } => {
                    out.extend(
                        args.iter()
                            .enumerate()
                            .map(|(index, argument)| (*span, index, argument.span)),
                    );
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect_requests(then_events, out);
                    collect_requests(else_events, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect_requests(body, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    collect_requests(body, out);
                    collect_requests(catch_events, out);
                    collect_requests(finally_events, out);
                }
                _ => {}
            }
        }
    }

    let mut requests = Vec::new();
    for decl in defs {
        collect_requests(&decl.flow_events, &mut requests);
    }
    requests
        .sort_by_key(|(call, index, argument)| (call.start, call.end, *index, argument.start, argument.end));
    requests.dedup();

    let mut nodes_by_span: std::collections::HashMap<(u64, u64), Vec<Node<'_>>> =
        std::collections::HashMap::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_named() {
            let span = span_of(file, &node);
            nodes_by_span
                .entry((span.start, span.end))
                .or_default()
                .push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    let mut facts = Vec::new();
    for (call_span, argument_index, argument_span) in requests {
        let selected = nodes_by_span
            .get(&(argument_span.start, argument_span.end))
            .and_then(|nodes| {
                nodes
                    .iter()
                    .map(|node| {
                        let value = argument_value_node(*node);
                        (
                            expression_flow::expression_flow_from_node_with_handler(
                                value, file, src, handler,
                            ),
                            direct_call_callee_span(value, file, src, handler),
                        )
                    })
                    .max_by_key(|(flow, _)| {
                        (
                            flow.aggregate_fields.len() + flow.tuple_items.len() + flow.spreads.len(),
                            usize::from(!flow.is_empty()),
                        )
                    })
            });
        if let Some((value_flow, direct_call_span)) = selected.filter(|(flow, _)| !flow.is_empty()) {
            facts.push(crate::CallArgumentValueFact {
                call_span,
                argument_index,
                argument_span,
                direct_call_span,
                value_flow,
                static_value: None,
                exact_static_aggregate_fields: Vec::new(),
                exact_static_sequence_values: None,
            });
        }
    }
    facts.sort_by_key(|fact| {
        (
            fact.call_span.file.raw(),
            fact.call_span.start,
            fact.call_span.end,
            fact.argument_index,
        )
    });
    facts.dedup();
    facts
}

/// Attach adapter-decoded scalar literals to compiler call-argument facts.
///
/// The shared walker owns only the syntax relationship between a normalized
/// call argument and its exact Tree-sitter value node. Each language adapter
/// supplies the literal decoder, so boolean/null/string syntax never leaks
/// into downstream analysis engines.
pub fn populate_call_argument_static_values(
    index: &mut crate::DeclIndex,
    tree: &Tree,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
    decode: fn(Node<'_>, &[u8]) -> Option<crate::StaticScalarValue>,
) {
    fn collect_requests(events: &[FlowEvent], out: &mut Vec<(Span, usize, Span)>) {
        for event in events {
            match event {
                FlowEvent::Call { span, args, .. } => out.extend(
                    args.iter()
                        .enumerate()
                        .map(|(index, argument)| (*span, index, argument.span)),
                ),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect_requests(then_events, out);
                    collect_requests(else_events, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect_requests(body, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    collect_requests(body, out);
                    collect_requests(catch_events, out);
                    collect_requests(finally_events, out);
                }
                _ => {}
            }
        }
    }

    let mut requests = Vec::new();
    for decl in &index.defs {
        collect_requests(&decl.flow_events, &mut requests);
    }
    requests.sort_by_key(|(call, argument_index, argument)| {
        (
            call.file.raw(),
            call.start,
            call.end,
            *argument_index,
            argument.start,
            argument.end,
        )
    });
    requests.dedup();

    let mut argument_nodes = std::collections::HashMap::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_named() {
            let span = span_of(file, &node);
            argument_nodes.insert((span.start, span.end), node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    for (call_span, argument_index, argument_span) in requests {
        let Some(argument_node) = argument_nodes.get(&(argument_span.start, argument_span.end)) else {
            continue;
        };
        let value_node = argument_value_node(*argument_node);
        let static_value = decode(value_node, src);
        let exact_static_aggregate_fields =
            expression_flow::exact_static_aggregate_fields(value_node, src, decode).unwrap_or_default();
        let exact_static_sequence_values =
            expression_flow::exact_static_sequence_values(value_node, src, decode);
        if static_value.is_none()
            && exact_static_aggregate_fields.is_empty()
            && exact_static_sequence_values.is_none()
        {
            continue;
        }
        if let Some(fact) = index
            .call_argument_values
            .iter_mut()
            .find(|fact| fact.call_span == call_span && fact.argument_index == argument_index)
        {
            fact.static_value = static_value;
            fact.exact_static_aggregate_fields = exact_static_aggregate_fields;
            fact.exact_static_sequence_values = exact_static_sequence_values;
        } else {
            index.call_argument_values.push(crate::CallArgumentValueFact {
                call_span,
                argument_index,
                argument_span,
                direct_call_span: if handler.call_ref_kinds.contains(&value_node.kind()) {
                    parsed_call_target(&value_node, src).map(|target| span_of(file, &target.node))
                } else {
                    None
                },
                value_flow: Default::default(),
                static_value,
                exact_static_aggregate_fields,
                exact_static_sequence_values,
            });
        }
    }
    index.call_argument_values.sort_by_key(|fact| {
        (
            fact.call_span.file.raw(),
            fact.call_span.start,
            fact.call_span.end,
            fact.argument_index,
        )
    });
    index.call_argument_values.dedup();
}

/// Read-only inputs shared by the declaration-lowering passes.
///
/// Keeping these inputs together makes the pass boundary explicit: lowering
/// reads the Tree-sitter CST plus grammar capabilities and appends semantic
/// declarations. It does not rediscover language syntax from rendered text.
struct CallableLowering<'a> {
    tree: &'a Tree,
    file: FileId,
    src: &'a [u8],
    handler: &'a GrammarHandler,
    class_names: &'a [String],
    error_spans: &'a [Span],
    file_has_syntax_errors: bool,
}

/// Lower anonymous callable nodes into the same declaration IR used by named
/// callables. Call-argument lambdas are intentionally omitted because the
/// enclosing flow walker already lowers those bodies in place.
fn lower_lambda_declarations(lowering: &CallableLowering<'_>, defs: &mut Vec<crate::Decl>, next: &mut u32) {
    let lambda_nodes = collect_kinds(lowering.tree, lowering.handler.lambda_kinds);
    for lambda in lambda_nodes {
        // Some adapters promote expression-bodied callables to normal
        // declarations because their grammar exposes enough structure
        // to name and walk them directly. Do not index the same syntax
        // again as a lambda; duplicate FuncIds split call resolution
        // from matcher attribution for a single semantic function.
        if lowering.handler.fn_kinds.contains(&lambda.kind()) {
            continue;
        }
        // Skip lambdas that are passed directly as call arguments.
        // `walk_into` inlines those bodies into the enclosing call's
        // owner via `walk_lambda_body`; emitting a second synthetic
        // decl for the same source events creates duplicate source
        // starts and duplicate findings with different chain roots.
        // Keep non-call-argument lambdas, including local or top-level
        // assignments, because their bodies are not otherwise inlined.
        if lambda_is_inlined_call_argument(&lambda, lowering.handler) {
            continue;
        }
        let span = span_of(lowering.file, &lambda);
        let binding_name = binding_name_node(&lambda, lowering.src);
        let name = binding_name.map_or_else(
            || {
                format!(
                    "<lambda@{}:{}>",
                    lambda.start_position().row + 1,
                    lambda.start_position().column + 1
                )
            },
            |name_node| callable_binding_name_from_node(&name_node, lowering.src),
        );
        if name.is_empty() {
            continue;
        }
        let params = extract_param_names(&lambda, lowering.src);
        let body_node = lambda
            .child_by_field_name("body")
            .or_else(|| lambda.child_by_field_name("block"))
            .or_else(|| first_named_child_of_kind(&lambda, "block"))
            .or_else(|| first_named_child_of_kind(&lambda, "compound_statement"))
            .or_else(|| first_named_child_of_kind(&lambda, "statement_block"))
            // Kotlin `lambda_literal` and Swift closure bodies nest their
            // statements under a `statements` node (after the params).
            .or_else(|| first_named_child_of_kind(&lambda, "statements"))
            // Erlang `F = fun() -> Body end` (H17): the fun body nests under
            // `clause_body` (directly, or via a `fun_clause` wrapper), the
            // same field the main function-decl path handles.
            .or_else(|| first_named_child_of_kind(&lambda, "clause_body"))
            .or_else(|| {
                first_named_child_of_kind(&lambda, "fun_clause")
                    .and_then(|fc| first_named_child_of_kind(&fc, "clause_body"))
            })
            // Elixir `fn x -> BODY end`: `anonymous_function` → `stab_clause`
            // → `body`/`right` field.
            .or_else(|| {
                first_named_child_of_kind(&lambda, "stab_clause").and_then(|sc| {
                    sc.child_by_field_name("body")
                        .or_else(|| sc.child_by_field_name("right"))
                })
            })
            // Expression-bodied lambdas with no wrapper node (Scala
            // `(x) => sink(x)`, Rust `|x| expr`): the body is the last
            // named child that isn't a parameter / type annotation.
            .or_else(|| lambda_expression_body_child(&lambda));
        let syntax_broken =
            lowering.file_has_syntax_errors && callable_has_syntax_error(&lambda, body_node.as_ref());
        let implicit_return_node =
            body_node.and_then(|body| implicit_return_expression_node(&body, lowering.handler));
        let body_implicit_returns = implicit_return_node.is_some();
        let mut flow_events = if let Some(body) = body_node {
            let mut events = walk_flow_events(
                body,
                lowering.file,
                lowering.src,
                lowering.handler,
                lowering.class_names,
            );
            if let Some(return_node) = implicit_return_node {
                append_expression_body_return(
                    &mut events,
                    &return_node,
                    lowering.file,
                    lowering.src,
                    lowering.handler,
                );
            } else if lowering.handler.tail_expression_returns {
                append_tail_expression_return(
                    &mut events,
                    &body,
                    lowering.file,
                    lowering.src,
                    lowering.handler,
                );
            }
            events
        } else {
            Vec::new()
        };
        if syntax_broken {
            retain_flow_events_outside_errors(
                &mut flow_events,
                lowering.error_spans,
                lowering.handler.syntax_error_tolerant_call_names,
            );
        }
        annotate_tuple_call_result_bindings(&mut flow_events, lowering.tree, lowering.src);
        if params.is_empty() && flow_events.is_empty() {
            continue;
        }
        let symbol = bonsai_common::SymbolId::new(*next);
        *next += 1;
        defs.push(crate::Decl {
            symbol,
            kind: crate::DeclKind::Function,
            name,
            qualified_name: None,
            module_path: crate::ModulePath::default(),
            span,
            name_span: binding_name.map_or(span, |name_node| span_of(lowering.file, &name_node)),
            visibility: crate::Visibility::Public,
            parent: None,
            body_span: body_node.map(|body| span_of(lowering.file, &body)),
            flow_events,
            has_implicit_returns: lowering.handler.tail_expression_returns || body_implicit_returns,
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
}

/// Connect nested callable declarations to their nearest lexical callable.
///
/// Tree-sitter spans are the ownership source of truth. Anonymous lambdas and
/// named local functions are lowered in separate passes, so assigning parents
/// after both passes avoids order dependence and keeps every language adapter
/// on the same compiler contract.
fn assign_lexical_callable_parents(defs: &mut [crate::Decl]) {
    let is_callable = |kind: crate::DeclKind| {
        matches!(
            kind,
            crate::DeclKind::Function | crate::DeclKind::Method | crate::DeclKind::Constructor
        )
    };
    let mut callables = defs
        .iter()
        .enumerate()
        .filter(|(_, decl)| is_callable(decl.kind))
        .map(|(index, decl)| (index, decl.body_span.unwrap_or(decl.span)))
        .collect::<Vec<_>>();
    // AST declaration/body intervals are laminar. Put enclosing intervals
    // first when two declarations begin at the same byte, then maintain the
    // active lexical owner chain as a stack. This is O(n log n), unlike a
    // per-child scan across every declaration in a generated source file.
    callables.sort_unstable_by_key(|(index, region)| {
        (
            region.file.raw(),
            region.start,
            std::cmp::Reverse(region.end),
            *index,
        )
    });
    let mut active: Vec<(usize, Span)> = Vec::new();
    let mut parents = Vec::new();
    for (index, region) in callables {
        while active.last().is_some_and(|(_, candidate)| {
            candidate.file != region.file
                || candidate.start > region.start
                || region.end > candidate.end
                || (candidate.start == region.start && candidate.end == region.end)
        }) {
            active.pop();
        }
        if defs[index].parent.is_none() {
            if let Some((parent_index, _)) = active.last() {
                parents.push((index, defs[*parent_index].symbol));
            }
        }
        active.push((index, region));
    }
    for (index, parent) in parents {
        defs[index].parent = Some(parent);
    }
}

/// Lower class nodes and connect methods to their nearest syntactic owner.
fn lower_class_declarations(
    lowering: &CallableLowering<'_>,
    class_nodes: &[Node<'_>],
    function_parent_spans: &[(bonsai_common::SymbolId, Span)],
    defs: &mut Vec<crate::Decl>,
    next: &mut u32,
) {
    let mut class_infos = Vec::new();
    for class_node in class_nodes {
        // For C / C++ `typedef struct { ... } UserInfo;` the
        // struct_specifier itself is anonymous — the name lives on a
        // sibling type_identifier in the enclosing type_definition.
        let name_node = class_node
            .child_by_field_name("name")
            .or_else(|| first_identifier_like_child(class_node))
            .or_else(|| anonymous_struct_typedef_name(class_node));
        let Some(name_node) = name_node else {
            continue;
        };
        let name = node_text(&name_node, lowering.src);
        if name.is_empty() {
            continue;
        }
        let symbol = bonsai_common::SymbolId::new(*next);
        *next += 1;
        let class_span = span_of(lowering.file, class_node);
        let lexical_owner_span = lowering
            .handler
            .nested_type_ownership
            .then(|| nearest_class_owner_span(class_node, lowering.handler))
            .flatten()
            .map(|owner| span_of(lowering.file, &owner));
        class_infos.push((symbol, class_span, lexical_owner_span));
        defs.push(crate::Decl {
            symbol,
            kind: lowering
                .handler
                .class_decl_kinds
                .iter()
                .find_map(|(node_kind, decl_kind)| (*node_kind == class_node.kind()).then_some(*decl_kind))
                .unwrap_or(crate::DeclKind::Class),
            name: name.to_string(),
            qualified_name: None,
            module_path: crate::ModulePath::default(),
            span: class_span,
            name_span: span_of(lowering.file, &name_node),
            visibility: crate::Visibility::Public,
            parent: None,
            body_span: Some(class_span),
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

    // Class-like declarations can themselves be lexically nested. Preserve
    // that AST ownership just as we do for methods: a nested interface,
    // class, record, trait, or struct is owned by the nearest strictly
    // enclosing named class-like declaration. This is source syntax, not a
    // naming heuristic; the resulting parent chain is what later produces
    // identities such as `Outer.Dispatcher.dispatchRequest`.
    let class_parents = class_infos
        .iter()
        .map(|(symbol, _, lexical_owner_span)| {
            let parent = lexical_owner_span.and_then(|owner_span| {
                class_infos
                    .iter()
                    .find(|(_, candidate_span, _)| *candidate_span == owner_span)
                    .map(|(candidate, _, _)| *candidate)
            });
            (*symbol, parent)
        })
        .collect::<Vec<_>>();
    for (symbol, parent) in class_parents {
        if let Some(decl) = defs.iter_mut().find(|decl| decl.symbol == symbol) {
            decl.parent = parent;
        }
    }

    for (function_symbol, parent_span) in function_parent_spans {
        let Some(class_symbol) = class_infos
            .iter()
            .find(|(_, class_span, _)| *class_span == *parent_span)
            .map(|(symbol, _, _)| *symbol)
        else {
            continue;
        };
        if let Some(decl) = defs.iter_mut().find(|decl| decl.symbol == *function_symbol) {
            decl.parent = Some(class_symbol);
        }
    }
}

/// Lower executable file-scope syntax into a synthetic declaration so scripts
/// and module initializers participate in the same flow IR as callables.
fn lower_module_declaration(lowering: &CallableLowering<'_>, defs: &mut Vec<crate::Decl>, next: &mut u32) {
    let module_syntax_broken = lowering.error_spans.iter().any(|error| {
        !defs
            .iter()
            .any(|decl| decl.span.start <= error.start && error.end <= decl.span.end)
    });
    let mut root_events = walk_flow_events(
        lowering.tree.root_node(),
        lowering.file,
        lowering.src,
        lowering.handler,
        lowering.class_names,
    );
    if module_syntax_broken {
        retain_flow_events_outside_errors(
            &mut root_events,
            lowering.error_spans,
            lowering.handler.syntax_error_tolerant_call_names,
        );
    }
    let has_actionable_event = root_events.iter().any(|event| {
        matches!(
            event,
            crate::FlowEvent::Call { .. }
                | crate::FlowEvent::Assign { .. }
                | crate::FlowEvent::Yield { .. }
                | crate::FlowEvent::Await { .. }
        )
    });
    if !has_actionable_event {
        return;
    }

    let symbol = bonsai_common::SymbolId::new(*next);
    *next += 1;
    let module_span = span_of(lowering.file, &lowering.tree.root_node());
    defs.push(crate::Decl {
        symbol,
        kind: crate::DeclKind::Function,
        name: MODULE_DECL_NAME.to_string(),
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
            .or_else(|| binding_name_node(&node, src))
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
        // A function declared to return a void/unit type carries no return
        // value, so synthesizing an implicit Return for its tail expression
        // would tokenize that expression (often a side-effecting call whose
        // args are consumed, not returned) into a bogus tainted return.
        let returns_void = callable_returns_void(&node, src, handler);
        let mut flow_events = if let Some(b) = body_node {
            let mut events = walk_flow_events(b, file, src, handler, &class_names);
            if returns_void {
                // no synthetic return for a void/unit function
            } else if let Some(return_node) = implicit_return_node {
                append_expression_body_return(&mut events, &return_node, file, src, handler);
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
            retain_flow_events_outside_errors(
                &mut flow_events,
                &error_spans,
                handler.syntax_error_tolerant_call_names,
            );
        }
        annotate_tuple_call_result_bindings(&mut flow_events, &tree, src);

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
        let param_annotations = extract_param_annotations(&param_source, src, handler);
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
            has_implicit_returns: !returns_void && (handler.tail_expression_returns || body_implicit_returns),
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
    // This is a distinct compiler pass because lambda ownership differs from
    // named callable ownership in higher-order calls.
    let lowering = CallableLowering {
        tree: &tree,
        file,
        src,
        handler,
        class_names: &class_names,
        error_spans: &error_spans,
        file_has_syntax_errors,
    };
    lower_lambda_declarations(&lowering, &mut defs, &mut next);
    // Pass 3: class declarations and syntactic method ownership.
    lower_class_declarations(
        &lowering,
        &class_nodes,
        &function_parent_spans,
        &mut defs,
        &mut next,
    );
    assign_lexical_callable_parents(&mut defs);

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
    lower_module_declaration(&lowering, &mut defs, &mut next);

    let mut refs = extract_call_refs(&tree, file, src, handler);
    refs.extend(extract_decorators(&tree, file, src));
    refs.extend(extract_read_write_refs(&tree, file, src, handler));
    let strings = extract_string_literals(&tree, file, src);
    let comments = extract_comments(&tree, file, src);
    let assignment_values = extract_assignment_value_facts(&tree, file, handler, src);
    let call_receivers = extract_call_receiver_facts(&tree, file, handler, src);
    let call_argument_values = extract_call_argument_value_facts(&tree, file, &defs, src, handler);
    let runtime_type_narrowings = extract_runtime_type_narrowing_facts(&tree, file, handler, src);
    let branch_conditions = extract_branch_condition_facts(&tree, file, handler, src);
    crate::DeclIndex {
        file,
        defs,
        refs,
        assignment_values,
        call_receivers,
        call_argument_values,
        static_string_maps: Vec::new(),
        string_compositions: Vec::new(),
        finite_literal_selections: Vec::new(),
        character_substitutions: Vec::new(),
        character_constraints: Vec::new(),
        guarded_value_filters: Vec::new(),
        same_origin_path_constraints: Vec::new(),
        compiler_guards: Vec::new(),
        dynamic_key_filters: Vec::new(),
        runtime_type_narrowings,
        branch_conditions,
        aggregate_layouts: Vec::new(),
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

fn callable_binding_name_from_node(node: &Node<'_>, src: &[u8]) -> String {
    // C-family callable declarators can contain type identifiers after the
    // actual binding (`void (^f)(NSString *)`). Text-token fallback walks
    // from the end and would name that block `NSString`; the CST declarator
    // chain puts the binding identifier first and proves `f` exactly.
    if node.kind().contains("declarator") {
        if let Some(identifier) = first_identifier_descendant(*node) {
            let name = node_text(&identifier, src).trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    callable_binding_name_from_text(node_text(node, src))
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

fn call_receiver_from_name(name: &str) -> Option<String> {
    if let Some(receiver) = rust_value_receiver_from_scoped_name(name) {
        return Some(receiver);
    }
    let normalised = normalise_qualified_text(name);
    let (receiver, _) = normalised.rsplit_once('.')?;
    let receiver = receiver.trim();
    (!receiver.is_empty()).then(|| receiver.to_string())
}

fn rust_value_receiver_from_scoped_name(name: &str) -> Option<String> {
    let segments = bonsai_common::qualified_name_segments(name);
    let [head, tail] = segments.as_slice() else {
        return None;
    };
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
            // Bare row keys target method-style calls — the binding is the
            // receiver. Qualified row keys target namespaced
            // free functions — the binding is the indexed arg.
            // The qualified-name fallback only fires for adapters
            // that fold receiver and method into the call name
            // and emit no args.
            let row_is_qualified = bonsai_common::qualified_name_owner(row.call_match).is_some();
            let raw = if !row_is_qualified {
                if let Some(rx) = receiver.as_deref() {
                    rx.trim().to_string()
                } else if let Some(arg) = args.get(row.arg_index) {
                    let Some(place) = arg.place.as_deref() else {
                        continue;
                    };
                    place.trim().to_string()
                } else if let Some(head) = bonsai_common::qualified_name_owner(name) {
                    head.trim().to_string()
                } else {
                    continue;
                }
            } else if let Some(arg) = args.get(row.arg_index) {
                let Some(place) = arg.place.as_deref() else {
                    continue;
                };
                place.trim().to_string()
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

/// Bare row keys match the call's trailing segment; qualified keys require an
/// exact match. Separator syntax remains adapter-owned.
fn lifecycle_call_matches(call_name: &str, row_match: &str) -> bool {
    let call = call_name.trim();
    if call == row_match {
        return true;
    }
    if bonsai_common::qualified_name_owner(row_match).is_some() {
        return false;
    }
    bonsai_common::short_qualified_tail(call) == row_match
}

/// Bare-identifier binding name for the lifecycle lattice.
/// Source punctuation is stripped structurally from an adapter-classified
/// place, and a qualified place is folded to its trailing identifier.
fn lifecycle_binding_name(raw: &str) -> String {
    let trimmed = bonsai_common::trim_leading_name_punctuation(raw.trim()).trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let tail = bonsai_common::short_qualified_tail(trimmed).trim();
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
            if !text.is_empty() {
                out.push(crate::StringLiteral {
                    span: span_of(file, &node),
                    category: crate::StringCategory::classify(&text),
                    text,
                    static_value: None,
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

/// Scan the tree for call-site nodes and return them as flat [`crate::Ref`]
/// entries. Kept for legacy consumers; prefer `flow_events` for rich flow.
///
pub fn extract_call_refs(
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<crate::Ref> {
    let mut out = Vec::new();
    let mut call_ref_kinds = handler.call_ref_kinds.to_vec();
    for (kind, _) in handler.synthetic_call_ref_names {
        if !call_ref_kinds.contains(kind) {
            call_ref_kinds.push(kind);
        }
    }
    let remote_call_syntax = handler
        .special_forms
        .contains(&SyntaxSpecialForm::RemoteCallExpression);
    for node in collect_kinds(tree, &call_ref_kinds) {
        if remote_call_syntax && erlang_remote_is_call_expr(&node) {
            continue;
        }
        let erlang_call = remote_call_syntax
            .then(|| erlang_call_callee(&node, src))
            .flatten();
        let erlang_remote = remote_call_syntax
            .then(|| erlang_remote_callee(&node, src))
            .flatten();
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
            .or_else(|| erlang_call.as_ref().map(|(n, _)| *n))
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
            .or(erlang_call.as_ref())
            .map(|(_, name)| normalize_call_name_whitespace(name))
            .unwrap_or_else(|| normalize_call_name_whitespace(node_text(&callee, src)));
        for suffix in handler.call_name_suffix_tokens {
            if inner_name.ends_with(suffix) {
                continue;
            }
            let node_src = node_text(&node, src);
            let rest = node_src
                .trim_start()
                .strip_prefix(&inner_name)
                .unwrap_or_default();
            if rest.trim_start().starts_with(suffix) {
                inner_name.push_str(suffix);
                break;
            }
        }
        if inner_name.is_empty() {
            continue;
        }
        if handler.non_call_ref_names.contains(&inner_name.as_str()) {
            continue;
        }
        if let Some((_, synthetic_name)) = handler
            .synthetic_call_ref_names
            .iter()
            .find(|(kind, _)| *kind == node.kind())
        {
            out.push(crate::Ref {
                span: span_of(file, &node),
                name: (*synthetic_name).to_string(),
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
    if handler
        .special_forms
        .contains(&SyntaxSpecialForm::SplitSelectorCall)
    {
        for node in collect_kinds(tree, &["selector"]) {
            let has_argument_part = first_named_child_of_kind(&node, "argument_part").is_some();
            if !has_argument_part {
                continue;
            }
            if let Some(FlowEvent::Call { name, span, .. }) =
                build_dart_selector_call_event(node, file, src, handler)
            {
                out.push(crate::Ref {
                    span,
                    name: normalize_call_name_whitespace(&name),
                    kind: crate::RefKind::Call,
                    scope: None,
                    resolved: None,
                });
            }
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
/// Uses a dependency worklist to reach a fixed point for arbitrarily long
/// reassignment chains. Walks the full flow tree — branches, loops,
/// try, await/yield, defer, etc. — so aliases introduced inside any
/// control-flow region are visible to call sites elsewhere in the
/// function. Language-agnostic: every adapter's assignment emission
/// lands here.
pub fn extend_alias_map_with_flow_events<S: std::hash::BuildHasher>(
    map: &mut std::collections::HashMap<String, AliasTarget, S>,
    events: &[crate::FlowEvent],
) {
    // Collect assignment dependencies from the flow tree. Constructor and
    // factory result types are compiler type facts on `Decl.type_aliases`;
    // this generic alias pass must not infer types from call-name casing.
    type AssignmentAlias = (String, Option<String>);

    fn collect(out: &mut Vec<AssignmentAlias>, events: &[crate::FlowEvent]) {
        for ev in events {
            match ev {
                crate::FlowEvent::Assign {
                    target, source_name, ..
                } if !target.is_empty() => {
                    out.push((target.clone(), source_name.clone()));
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
    // Reverse assignment dependencies make propagation linear in the alias
    // graph rather than repeatedly rescanning every statement. Each target
    // is inserted at most once, so cycles terminate without a round limit.
    let mut dependents: ahash::AHashMap<&str, Vec<&str>> = ahash::AHashMap::new();
    for (target, source) in &triples {
        let Some(source) = source.as_deref().filter(|source| !source.is_empty()) else {
            continue;
        };
        dependents.entry(source).or_default().push(target);
    }
    let mut pending = std::collections::VecDeque::new();
    let mut enqueued = ahash::AHashSet::new();
    // Seed in source-event order so competing reassignments remain
    // deterministic and match the adapter's lexical fact order.
    for (_, source) in &triples {
        let Some(source) = source.as_deref().filter(|source| map.contains_key(*source)) else {
            continue;
        };
        if enqueued.insert(source) {
            pending.push_back(source);
        }
    }
    while let Some(source) = pending.pop_front() {
        let Some(resolved) = map.get(source).cloned() else {
            continue;
        };
        for target in dependents.get(source).into_iter().flatten() {
            if map.contains_key(*target) {
                continue;
            }
            map.insert((*target).to_string(), resolved.clone());
            if enqueued.insert(*target) {
                pending.push_back(target);
            }
        }
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

/// Classify imported namespace/type qualifiers as non-value call receivers.
///
/// Language adapters own both inputs: [`crate::ImportSpec`] records the local
/// binding established by import syntax, and [`crate::CallReceiverFact`]
/// records the exact receiver expression from Tree-sitter. This linker step
/// joins those typed facts so IDG transfer does not invent a runtime receiver
/// edge for calls such as `pickle.loads(data)` or `fmt.Println(value)`.
///
/// A local parameter or a non-import assignment with the same name is exact
/// shadowing evidence and keeps the receiver value-bearing. Assignment events
/// that contain the import anchor itself (for example CommonJS
/// `const fs = require("fs")`) are part of the namespace binding, not a
/// shadowing write.
pub fn mark_namespace_call_receivers(index: &mut crate::DeclIndex, imports: &crate::ImportIndex) {
    let mut namespace_spans = std::collections::HashMap::<String, Vec<Span>>::new();
    for import in &imports.imports {
        // `original_name` identifies a concrete imported member. Only a
        // whole-module/type binding is a non-value qualifier.
        if import.original_name.is_some() {
            continue;
        }
        let Some(local) = import.alias.as_deref().filter(|local| !local.is_empty()) else {
            continue;
        };
        namespace_spans
            .entry(local.to_string())
            .or_default()
            .push(import.span);
    }
    if namespace_spans.is_empty() {
        return;
    }

    for receiver in &mut index.call_receivers {
        let base = receiver
            .value_flow
            .projection
            .as_ref()
            .map(|projection| projection.base.as_str())
            .or(receiver.value_flow.place.as_deref());
        let Some(base) = base else {
            continue;
        };
        let Some(import_spans) = namespace_spans.get(base) else {
            continue;
        };
        let owner = index
            .defs
            .iter()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Module | DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && span_contains(decl.body_span.unwrap_or(decl.span), receiver.receiver_span)
            })
            .min_by_key(|decl| {
                let span = decl.body_span.unwrap_or(decl.span);
                span.end.saturating_sub(span.start)
            });
        if owner.is_some_and(|decl| {
            decl.params.iter().any(|param| param == base)
                || flow_events_assign_name_outside_imports(&decl.flow_events, base, import_spans)
        }) {
            continue;
        }
        receiver.role = crate::CallReceiverRole::Namespace;
    }
}

fn flow_events_assign_name_outside_imports(events: &[FlowEvent], name: &str, imports: &[Span]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Assign { span, target, .. } | FlowEvent::AggregateAssign { span, target, .. }
            if target == name =>
        {
            !imports.iter().any(|import| spans_overlap(*span, *import))
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            flow_events_assign_name_outside_imports(then_events, name, imports)
                || flow_events_assign_name_outside_imports(else_events, name, imports)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            flow_events_assign_name_outside_imports(body, name, imports)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            flow_events_assign_name_outside_imports(body, name, imports)
                || flow_events_assign_name_outside_imports(catch_events, name, imports)
                || flow_events_assign_name_outside_imports(finally_events, name, imports)
        }
        _ => false,
    })
}

fn spans_overlap(left: Span, right: Span) -> bool {
    left.file == right.file && left.start <= right.end && right.start <= left.end
}

/// Derive a local module binding only when the normalized import target
/// exposes an identifier directly. File-extension stripping is intentionally
/// absent: adapters know whether a string is a file URI and must emit its
/// local binding in `ImportSpec::alias`.
pub fn module_local_binding(module: &str) -> Option<String> {
    let trimmed = module
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'))
        .trim_end_matches(['/', '\\'])
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    // A path-like target can be a side-effect import, include, or require.
    // Only its grammar adapter knows whether it creates a binding, so the
    // shared layer must not infer one from a basename.
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.starts_with('.') {
        return None;
    }
    let mut candidate = bonsai_common::short_qualified_tail(trimmed);
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

// --- attribute-chain / subscript ref emission -------------------------------
//
// The following const tables + helpers back `extract_read_write_refs`. They
// are intentionally kept private — every grammar-specific kind listed here
// is an implementation detail of how this file surfaces `RefKind::Read` /
// `RefKind::Write` facts for attribute chains, subscript access, and
// sigil'd variable reads. Adapter crates should not depend on them.

// All grammar node-kind sets used by the reference index come from the active
// adapter's `GrammarHandler`; this shared lowering code owns no language
// union.

/// True when `node` is the callee of an enclosing call expression. The
/// callee slot is a `Call` ref already (emitted by `extract_call_refs`),
/// so we skip it here to avoid emitting a duplicate `Read` at the same
/// span that would wrongly satisfy a `kind: read` rule against a
/// callee's dotted name.
fn is_call_callee(node: &Node<'_>, handler: &GrammarHandler) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !handler.call_ref_kinds.contains(&parent.kind()) {
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
fn is_write_target(node: &Node<'_>, handler: &GrammarHandler) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !handler.assignment_kinds.contains(&parent.kind()) {
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
fn normalize_member_name(node: &Node<'_>, src: &[u8], handler: &GrammarHandler) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = Some(*node);
    while let Some(n) = cur {
        if !handler.member_expression_kinds.contains(&n.kind()) {
            // Base of the chain — include its text and stop.
            let text = node_text(&n, src).trim().to_string();
            if !text.is_empty() {
                // Preserve language sigils in the canonical storage place.
                // The operand inventory separately emits bare aliases for
                // tolerant name matching; dropping the sigil here loses the
                // exact qualified identity (`$c.capacity`) needed to suppress
                // its whole-object carrier (`$c`).
                parts.push(text);
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
            })
            .or_else(|| {
                let mut cursor = n.walk();
                n.named_children(&mut cursor)
                    .skip(1)
                    .last()
                    .and_then(first_identifier_descendant)
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
            .or_else(|| n.child_by_field_name("receiver"))
            .or_else(|| first_named_child(&n));
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
    let cleaned = bonsai_common::trim_leading_name_punctuation(&text).to_string();
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
pub fn extract_read_write_refs(
    tree: &tree_sitter::Tree,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<crate::Ref> {
    let mut out = Vec::new();

    // Attribute chains — `req.query`, `request.args`, `Runtime.getRuntime`…
    for node in collect_kinds(tree, handler.member_expression_kinds) {
        if is_call_callee(&node, handler) {
            continue;
        }
        let Some(name) = normalize_member_name(&node, src, handler) else {
            continue;
        };
        let kind = if is_write_target(&node, handler) {
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
    for node in collect_kinds(tree, handler.subscript_expression_kinds) {
        if is_call_callee(&node, handler) {
            continue;
        }
        let Some(name) = normalize_subscript_name(&node, src) else {
            continue;
        };
        let kind = if is_write_target(&node, handler) {
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
        if handler.subscript_base_call_refs
            && bonsai_common::qualified_name_owner(&name).is_none()
            && is_bare_identifier_base(&node)
        {
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
    for node in collect_kinds(tree, handler.sigil_variable_kinds) {
        if is_call_callee(&node, handler) {
            continue;
        }
        let raw = node_text(&node, src).trim().to_string();
        let name = bonsai_common::trim_leading_name_punctuation(&raw).to_string();
        if name.is_empty() {
            continue;
        }
        let kind = if is_write_target(&node, handler) {
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
    for node in collect_kinds(tree, handler.global_variable_kinds) {
        let raw = node_text(&node, src).trim().to_string();
        let name = bonsai_common::trim_leading_name_punctuation(&raw).to_string();
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
    for node in collect_kinds(tree, handler.assignment_kinds) {
        let lhs = node
            .child_by_field_name("left")
            .or_else(|| node.child_by_field_name("target"))
            .or_else(|| first_named_child(&node));
        let Some(lhs) = lhs else { continue };
        let lhs_text = node_text(&lhs, src).trim().to_string();
        // Only fire on dotted member writes; bare-identifier writes
        // (`x = y`) are already covered by the Assign FlowEvent's
        // target field and don't need a separate Write ref.
        let canonical_lhs = normalise_qualified_text(&lhs_text);
        if bonsai_common::qualified_name_owner(&canonical_lhs).is_none() {
            continue;
        }
        let last = bonsai_common::short_qualified_tail(&canonical_lhs)
            .trim_matches(bonsai_common::is_name_punctuation)
            .to_string();
        if last.is_empty() {
            continue;
        }
        // The adapter's subscript walker already covers direct indexed LHS
        // nodes; do not duplicate them as field writes.
        if handler.subscript_expression_kinds.contains(&lhs.kind()) {
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
fn build_dart_selector_call_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
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
    let mut args: Vec<CallArg> = Vec::new();
    if let Some(arg_part) = first_named_child_of_kind(&node, "argument_part") {
        if let Some(arg_list) = first_named_child_of_kind(&arg_part, "arguments") {
            args = dart_call_args_from_arguments(&arg_list, file, src, handler);
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

/// Build [`CallArg`]s from a Dart `arguments` node. Dart splits named
/// args (`runInShell: true`) into a `named_argument` node with a `label`
/// child; those surface with `name` populated so `keyword_arg_equals`
/// constraints fire.
fn dart_call_args_from_arguments(
    arg_list: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<CallArg> {
    let mut args: Vec<CallArg> = Vec::new();
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
                passing_mode: Default::default(),
                span: span_of(file, &arg),
                name,
                place: argument_place(&value_node, src),
                source_names: extract_rhs_expr_operands(&value_node, src, handler),
                value_text,
            });
            continue;
        }
        if let Some(argument) = call_arg_from_node_with_handler(arg, file, src, None, handler) {
            args.push(argument);
        }
    }
    args
}

/// The receiver a Dart `cascade_section` applies to: the variable the
/// whole cascade expression is bound to (`var b = Builder()..name = x`
/// → `b`), or — for statement-position cascades (`w..m(x);`) — the base
/// identifier that opens the sibling chain.
fn dart_cascade_receiver(node: &Node<'_>, src: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    if matches!(
        parent.kind(),
        "initialized_variable_definition" | "initialized_identifier"
    ) {
        if let Some(name) = parent.child_by_field_name("name") {
            let text = node_text(&name, src).trim().to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    // Statement-position cascade (`w..a()..b()`): the receiver is the
    // base identifier that opens the chain — the last identifier-like
    // node BEFORE the first `cascade_section`. Resolve it by a single
    // FORWARD scan of the parent's children (which stops at the first
    // cascade_section), NOT a per-section backward `prev_named_sibling`
    // walk: tree-sitter's prev_sibling is O(child-index), so walking
    // back once per section over an n-section chain is O(n^2)+ and hangs
    // on long generated cascades.
    let mut cursor = parent.walk();
    let mut base: Option<String> = None;
    for child in parent.named_children(&mut cursor) {
        match child.kind() {
            "identifier" | "this" | "super" => {
                base = Some(node_text(&child, src).trim().to_string());
            }
            "selector" | "argument_part" => {}
            "cascade_section" => break,
            _ => {}
        }
    }
    if let Some(base) = base.filter(|b| !b.is_empty()) {
        return Some(base);
    }
    None
}

/// Events for one Dart `cascade_section`:
/// - `..method(args)` (has an `argument_part`) → a Method `Call` on the
///   cascade receiver.
/// - `..field = value` (selector + trailing value expression) → an
///   `Assign` to `receiver.field` carrying the value's operands.
fn build_dart_cascade_events(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<Vec<FlowEvent>> {
    let selector = first_named_child_of_kind(&node, "cascade_selector")?;
    let member = first_identifier_like_child(&selector)
        .map(|id| node_text(&id, src).trim().to_string())
        .filter(|name| !name.is_empty())?;
    let receiver = dart_cascade_receiver(&node, src);
    if let Some(arg_part) = first_named_child_of_kind(&node, "argument_part") {
        let args = first_named_child_of_kind(&arg_part, "arguments")
            .map(|list| dart_call_args_from_arguments(&list, file, src, handler))
            .unwrap_or_default();
        let name = match receiver.as_deref() {
            Some(recv) => format!("{recv}.{member}"),
            None => member,
        };
        return Some(vec![FlowEvent::Call {
            span: span_of(file, &node),
            receiver: call_receiver_from_name(&name).or(receiver),
            receiver_types: Vec::new(),
            name,
            call_kind: CallKind::Method,
            args,
        }]);
    }
    // Field-write form: the value expression is the named child after
    // the cascade_selector.
    let mut cursor = node.walk();
    let value = node
        .named_children(&mut cursor)
        .find(|child| child.kind() != "cascade_selector" && child.start_byte() > selector.end_byte())?;
    let target = match receiver.as_deref() {
        Some(recv) => format!("{recv}.{member}"),
        None => member,
    };
    let value_text = node_text(&value, src).trim();
    Some(vec![FlowEvent::Assign {
        span: span_of(file, &node),
        target,
        source_name: looks_like_bare_identifier(value_text).then(|| value_text.to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: extract_rhs_expr_operands(&value, src, handler),
        declares_new_binding: false,
        value_kind: None,
    }])
}

/// Call event for Dart `new T(args)` / `const T(args)` object
/// expressions — the explicit forms of construction (the implicit
/// `T(args)` form already goes through the selector-call path).
///
/// `new_expression` is a node kind SHARED with C++ (`new Box(args)`),
/// whose args live in an `argument_list` child and which the generic
/// walker already handles correctly. Require the Dart-specific
/// `arguments`-kind child so C++ new-expressions fall through untouched.
fn build_dart_object_expression_call(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    let arguments = first_named_child_of_kind(&node, "arguments")?;
    let type_node =
        first_named_child_of_kind(&node, "type_identifier").or_else(|| first_identifier_like_child(&node))?;
    let name = node_text(&type_node, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    let args = dart_call_args_from_arguments(&arguments, file, src, handler);
    Some(FlowEvent::Call {
        span: span_of(file, &node),
        receiver: None,
        receiver_types: Vec::new(),
        name,
        call_kind: CallKind::Constructor,
        args,
    })
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
    !swift_trailing_lambdas(*node).is_empty()
}

/// Find trailing closures through the grammar's `call_suffix` wrappers.
/// The iterative walk is bounded by the finite CST, not an arbitrary depth.
fn swift_trailing_lambdas(node: Node<'_>) -> Vec<Node<'_>> {
    let mut lambdas = Vec::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        let mut cursor = current.walk();
        let children = current.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if child.kind() == "lambda_literal" {
                lambdas.push(child);
            } else if child.kind() == "call_suffix" {
                pending.push(child);
            }
        }
    }
    lambdas.sort_by_key(tree_sitter::Node::start_byte);
    lambdas
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

/// True when a `binary_operator` node is an Elixir/F#-style pipe (`|>`).
/// The operator is an unnamed child between `left` and `right`.
fn binary_operator_is_pipe(node: &Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() && node_text(&child, src).trim() == "|>" {
            return true;
        }
        if !cursor.goto_next_sibling() {
            return false;
        }
    }
}

/// Prepend the piped value (`left`) as argument 0 of the RHS call event
/// emitted by an Elixir pipe. Finds the Call event in `out[before..]`
/// whose span matches the `right` call node and inserts the LHS CallArg
/// at the front of its argument list, so `lhs |> f(a)` reads as `f(lhs,
/// a)`. If the RHS produced no Call (e.g. `x |> Enum.map(&f/1)` bare
/// capture, or a non-call RHS) the pipe is left as-is.
fn prepend_pipe_arg_to_call(
    out: &mut [FlowEvent],
    before: usize,
    right: &Node<'_>,
    left: &Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) {
    let right_span = span_of(file, right);
    let Some(piped_arg) = call_arg_from_node_with_handler(*left, file, src, None, handler) else {
        return;
    };
    // Prefer the outermost call at the RHS span (the pipe targets the
    // top-level RHS call, not a nested one inside its args).
    for event in out[before..].iter_mut() {
        if let FlowEvent::Call { span, args, .. } = event {
            if *span == right_span {
                args.insert(0, piped_arg);
                return;
            }
        }
    }
    // Fallback: the first call whose span is contained in the RHS span.
    for event in out[before..].iter_mut() {
        if let FlowEvent::Call { span, args, .. } = event {
            if span.start >= right_span.start && span.end <= right_span.end {
                args.insert(0, piped_arg);
                return;
            }
        }
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
            // `call_argument` — Solidity exposes each argument as a
            // direct `call_argument` child (no `arguments` wrapper);
            // without it, a nested call arg like `sink(source())` never
            // surfaces its inner `source()` Call.
            "arguments" | "argument_list" | "value_arguments" | "call_suffix" | "expr_args"
            | "call_argument" | "token_tree" => {
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
        // Single nested call exposed directly as the `arguments` field
        // (Perl `sink(source())`): walk it whole so its Call surfaces.
        if handler.is_call(container.kind()) {
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

fn non_closure_arg_source_names(
    node: &Node<'_>,
    src: &[u8],
    arg_container_kinds: &[&str],
    handler: &GrammarHandler,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if arg_container_kinds.contains(&child.kind()) {
            out.extend(non_closure_arg_source_names_from_container(child, src, handler));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn non_closure_arg_source_names_from_container(
    container: Node<'_>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Vec<String> {
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
        out.extend(extract_rhs_expr_operands(&arg, src, handler));
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

fn emit_inline_closure_param_bindings_from_yield_call(
    lambda: Node<'_>,
    _file: FileId,
    src: &[u8],
    call_event: Option<&FlowEvent>,
    out: &mut Vec<FlowEvent>,
) {
    let Some(FlowEvent::Call {
        span: call_span,
        name,
        args,
        ..
    }) = call_event
    else {
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
            // This binding is the yielded output of the enclosing call, so
            // its semantic identity is that AST call site. The block span is
            // only the lexical scope of the parameter and cannot resolve a
            // callee in the callgraph.
            span: *call_span,
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
        if handler.method_owner_barrier_kinds.contains(&kind) {
            return None;
        }
        if handler.fn_kinds.contains(&kind) || handler.lambda_kinds.contains(&kind) {
            return None;
        }
        parent = candidate.parent();
    }
    None
}

/// The body of an expression-bodied lambda that has no wrapping
/// statement/block node — Scala `(x) => sink(x)`, Rust `|x| expr`. The
/// body is the last named child that is not a parameter list, single
/// parameter, or type annotation. Returns `None` when every named child
/// looks like a parameter/type (a param-only or bodyless lambda).
fn lambda_expression_body_child<'a>(lambda: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = lambda.walk();
    let children: Vec<Node<'a>> = lambda.named_children(&mut cursor).collect();
    children.into_iter().rev().find(|child| {
        let kind = child.kind();
        !kind.contains("param") && !kind.contains("type") && !kind.ends_with("parameters")
    })
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

fn erlang_call_callee<'tree>(node: &Node<'tree>, src: &[u8]) -> Option<(Node<'tree>, String)> {
    if node.kind() != "call" {
        return None;
    }
    let expr = node.child_by_field_name("expr")?;
    if let Some((callee_node, name)) = erlang_remote_callee(&expr, src) {
        return Some((callee_node, name));
    }
    let callee_node = expr
        .child_by_field_name("expr")
        .or_else(|| expr.child_by_field_name("name"))
        .or_else(|| first_identifier_like_child(&expr))
        .or_else(|| first_identifier_descendant(expr))
        .unwrap_or(expr);
    let name = node_text(&callee_node, src).trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some((callee_node, name))
}

fn erlang_remote_is_call_expr(node: &Node<'_>) -> bool {
    if node.kind() != "remote" {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "call" {
        return false;
    }
    parent
        .child_by_field_name("expr")
        .is_some_and(|expr| expr.id() == node.id())
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
    let prefix = module_segments.join(".");
    for decl in &mut idx.defs {
        if decl.qualified_name.is_none() {
            decl.qualified_name = Some(format!("{prefix}.{}", decl.name));
        }
        if decl.module_path.is_empty() {
            decl.module_path = module_path.clone();
        }
    }
    apply_lexical_member_qualified_names(idx, ".");
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
    apply_lexical_member_qualified_names(idx, ".");
}

/// Qualify callable/type members through their AST-declared lexical owner.
///
/// Module identity alone is insufficient for compiler navigation:
/// `pkg.A.run` and `pkg.B.run` are different declarations even when their
/// bare names and source module match. Ownership comes exclusively from
/// `Decl.parent`; span containment and source-text naming conventions are not
/// consulted.
pub fn apply_lexical_member_qualified_names(idx: &mut crate::DeclIndex, separator: &str) {
    let declarations = idx
        .defs
        .iter()
        .map(|decl| {
            (
                decl.symbol,
                (
                    decl.parent,
                    decl.name.clone(),
                    decl.qualified_name.clone().unwrap_or_else(|| decl.name.clone()),
                ),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut resolved = std::collections::HashMap::new();
    let mut visiting = std::collections::HashSet::new();
    fn resolve_name(
        symbol: bonsai_common::SymbolId,
        separator: &str,
        declarations: &std::collections::HashMap<
            bonsai_common::SymbolId,
            (Option<bonsai_common::SymbolId>, String, String),
        >,
        resolved: &mut std::collections::HashMap<bonsai_common::SymbolId, String>,
        visiting: &mut std::collections::HashSet<bonsai_common::SymbolId>,
    ) -> Option<String> {
        if let Some(name) = resolved.get(&symbol) {
            return Some(name.clone());
        }
        let (parent, name, module_qualified) = declarations.get(&symbol)?;
        if !visiting.insert(symbol) {
            return Some(module_qualified.clone());
        }
        let qualified = parent
            .and_then(|parent| resolve_name(parent, separator, declarations, resolved, visiting))
            .map_or_else(
                || module_qualified.clone(),
                |owner| format!("{owner}{separator}{name}"),
            );
        visiting.remove(&symbol);
        resolved.insert(symbol, qualified.clone());
        Some(qualified)
    }
    for decl in &idx.defs {
        let _ = resolve_name(
            decl.symbol,
            separator,
            &declarations,
            &mut resolved,
            &mut visiting,
        );
    }
    for decl in &mut idx.defs {
        if decl.parent.is_some() {
            decl.qualified_name = resolved.get(&decl.symbol).cloned();
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
    let call_bearing_assignments: ahash::AHashSet<Span> = idx
        .assignment_values
        .iter()
        .filter(|fact| !fact.call_sites.is_empty())
        .map(|fact| fact.assignment_span)
        .collect();
    for decl in &mut idx.defs {
        classify_assign_value_kinds(&mut decl.flow_events, &call_bearing_assignments);
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
pub const MODULE_DECL_NAME: &str = "__module__";

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
    let is_fn_kind = |k: &str| handler.fn_kinds.contains(&k);
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

/// Canonical type name carried by a call that has already been proven to be a
/// constructor by adapter `CallKind` or declaration resolution. Spelling and
/// casing are normalization only; they never prove constructor semantics.
fn proven_constructor_type_name(callee: &str) -> Option<String> {
    let bare = bonsai_common::short_qualified_tail(callee.trim()).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Result type carried by a compiler-classified constructor call. Adapters
/// attach the declared owner as the first receiver type for factory-shaped
/// constructors. Before receiver typing runs, a qualified constructor syntax
/// such as `Type.new(...)` or `Type->new(...)` still carries its AST-proven
/// receiver; that owner is the constructed type, not the selector tail.
fn proven_constructor_result_type_name(
    callee: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
) -> Option<String> {
    receiver_types
        .first()
        .filter(|type_name| !type_name.trim().is_empty())
        .cloned()
        .or_else(|| receiver.and_then(proven_constructor_type_name))
        .or_else(|| proven_constructor_type_name(callee))
}

fn resolved_declared_constructor_type(
    callee: &str,
    declared_types: &ahash::AHashSet<String>,
) -> Option<String> {
    let candidates = callee
        .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
        .filter(|candidate| !candidate.is_empty())
        .collect::<ahash::AHashSet<_>>();
    let mut matches = declared_types.iter().filter(|name| {
        candidates.contains(name.as_str()) || candidates.contains(bonsai_common::short_qualified_tail(name))
    });
    let resolved = matches.next()?.clone();
    matches.next().is_none().then_some(resolved)
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
    collect_constructor_result_type_aliases_with_declared_types(events, out, &ahash::AHashSet::new());
}

fn collect_constructor_result_type_aliases_with_declared_types(
    events: &[crate::FlowEvent],
    out: &mut Vec<crate::TypeAliasBinding>,
    declared_types: &ahash::AHashSet<String>,
) {
    let mut constructor_calls = events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call {
                name,
                span,
                receiver,
                receiver_types,
                call_kind: CallKind::Constructor,
                ..
            } => proven_constructor_result_type_name(name, receiver.as_deref(), receiver_types)
                .map(|type_name| (*span, type_name)),
            _ => None,
        })
        .collect::<Vec<_>>();
    constructor_calls.sort_by_key(|(span, _)| (span.file.raw(), span.start, span.end));

    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_call: Some(callee),
                span,
                ..
            } => {
                if target.is_empty() {
                    continue;
                }
                let type_name = contained_constructor_call_type(&constructor_calls, *span)
                    .or_else(|| resolved_declared_constructor_type(callee, declared_types));
                if let Some(type_name) = type_name {
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
                if let Some(type_name) = contained_constructor_call_type(&constructor_calls, *span) {
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
                collect_constructor_result_type_aliases_with_declared_types(then_events, out, declared_types);
                collect_constructor_result_type_aliases_with_declared_types(else_events, out, declared_types);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_constructor_result_type_aliases_with_declared_types(body, out, declared_types);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_constructor_result_type_aliases_with_declared_types(body, out, declared_types);
                collect_constructor_result_type_aliases_with_declared_types(
                    catch_events,
                    out,
                    declared_types,
                );
                collect_constructor_result_type_aliases_with_declared_types(
                    finally_events,
                    out,
                    declared_types,
                );
            }
            _ => {}
        }
    }
}

/// Find the constructor type for a `new`-expression RHS that the
/// grammar surfaced as a sibling `Call` event rather than the
/// assignment's `source_call` (the JS/TS shape). Searches a span-sorted
/// constructor index for a `Call` whose span lies inside or exactly covers the
/// assignment expression, preferring the leftmost (outermost) one so
/// `x = new Foo(new Bar())` resolves to `Foo`. Returns `None` when no
/// contained constructor call exists, so unrelated adjacent statements
/// (`x = compute(); Helper();`) never mistype `x`.
fn contained_constructor_call_type(
    constructor_calls: &[(Span, String)],
    assign_span: Span,
) -> Option<String> {
    let first = constructor_calls.partition_point(|(span, _)| {
        span.file.raw() < assign_span.file.raw()
            || (span.file == assign_span.file && span.start < assign_span.start)
    });
    constructor_calls[first..]
        .iter()
        .take_while(|(span, _)| span.file == assign_span.file && span.start < assign_span.end)
        .find(|(span, _)| span.end <= assign_span.end)
        .map(|(_, type_name)| type_name.clone())
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
    let declared_types = idx
        .defs
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                crate::DeclKind::Class | crate::DeclKind::Struct | crate::DeclKind::Enum
            )
        })
        .flat_map(|decl| std::iter::once(decl.name.clone()).chain(decl.qualified_name.clone()))
        .filter(|name| !name.is_empty())
        .collect::<ahash::AHashSet<_>>();
    for decl in &mut idx.defs {
        let mut ctor_aliases = Vec::new();
        collect_constructor_result_type_aliases_with_declared_types(
            &decl.flow_events,
            &mut ctor_aliases,
            &declared_types,
        );
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

fn classify_assign_value_kinds(events: &mut [FlowEvent], call_bearing_assignments: &ahash::AHashSet<Span>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                source_name,
                source_call,
                source_call_args,
                source_names,
                value_kind,
                span,
                ..
            } => {
                if value_kind.is_some() {
                    continue;
                }
                let kind = if source_call.is_some() {
                    crate::AssignValueKind::CallResult
                } else if source_name.is_none()
                    && source_names.is_empty()
                    && source_call_args.is_empty()
                    && !call_bearing_assignments.contains(span)
                {
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
                classify_assign_value_kinds(then_events, call_bearing_assignments);
                classify_assign_value_kinds(else_events, call_bearing_assignments);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                classify_assign_value_kinds(body, call_bearing_assignments);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                classify_assign_value_kinds(body, call_bearing_assignments);
                classify_assign_value_kinds(catch_events, call_bearing_assignments);
                classify_assign_value_kinds(finally_events, call_bearing_assignments);
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
    apply_call_receiver_types_with_language_syntax(idx, &[], &[], &[], crate::ReceiverTypeSyntax::none());
}

pub fn apply_call_receiver_types_with_super_tokens(
    idx: &mut crate::DeclIndex,
    super_receiver_tokens: &[&str],
) {
    apply_call_receiver_types_with_language_syntax(
        idx,
        super_receiver_tokens,
        &[],
        &[],
        crate::ReceiverTypeSyntax::none(),
    );
}

/// Adapter-aware receiver typing. Constructor method spellings are syntax
/// facts: only a language that declares a bare constructor form such as Ruby
/// `new` may bind that receiver-less call to the enclosing class.
pub fn apply_call_receiver_types_with_language_syntax(
    idx: &mut crate::DeclIndex,
    super_receiver_tokens: &[&str],
    implicit_receiver_tokens: &[&str],
    constructor_method_names: &[&str],
    receiver_type_syntax: crate::ReceiverTypeSyntax,
) {
    let syntax = ReceiverTypingSyntax {
        super_receiver_tokens,
        implicit_receiver_tokens,
        constructor_method_names,
        receiver_type_syntax,
        explicit_receiver_name: None,
    };
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
        let syntax = ReceiverTypingSyntax {
            explicit_receiver_name: decl
                .receiver_param_index
                .and_then(|index| decl.params.get(index))
                .map(String::as_str),
            ..syntax
        };
        apply_call_receiver_types_to_events(
            &mut decl.flow_events,
            &decl.type_aliases,
            implicit_receiver_types.as_deref(),
            &class_facts,
            syntax,
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

#[derive(Copy, Clone)]
struct ReceiverTypingSyntax<'a> {
    super_receiver_tokens: &'a [&'a str],
    implicit_receiver_tokens: &'a [&'a str],
    constructor_method_names: &'a [&'a str],
    receiver_type_syntax: crate::ReceiverTypeSyntax,
    /// Exact adapter-lowered receiver parameter for this declaration. This
    /// carries grammar evidence such as Python's first method parameter or
    /// Rust's `self` without teaching the shared pass either spelling.
    explicit_receiver_name: Option<&'a str>,
}

fn apply_call_receiver_types_to_events(
    events: &mut [FlowEvent],
    aliases: &[crate::TypeAliasBinding],
    implicit_receiver_types: Option<&[String]>,
    class_facts: &ClassFactsIndex<'_>,
    syntax: ReceiverTypingSyntax<'_>,
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
                if let Some(receiver) = receiver.as_deref() {
                    for ty in receiver_types_for_expr(
                        receiver,
                        aliases,
                        implicit_receiver_types,
                        class_facts,
                        syntax,
                    ) {
                        push_unique_receiver_type(receiver_types, ty);
                    }
                } else if matches!(call_kind, crate::CallKind::Constructor) {
                    if syntax.constructor_method_names.contains(&short_name_of(name)) {
                        // A bare constructor call inside a class-like
                        // declaration (`new(...)`, `Self(...)`) constructs
                        // the AST-declared enclosing type only when the
                        // adapter declares that exact syntax. Preserve the
                        // parent-symbol fact on the call so return/assignment
                        // typing never has to reinterpret the spelling.
                        if let Some(types) = implicit_receiver_types {
                            for ty in types {
                                push_unique_receiver_type(receiver_types, ty.clone());
                            }
                        }
                    }
                } else {
                    let Some(types) = implicit_receiver_types else {
                        continue;
                    };
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
            FlowEvent::AggregateAssign { .. } => {}
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
                    syntax,
                );
                apply_call_receiver_types_to_events(
                    else_events,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    syntax,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                apply_call_receiver_types_to_events(
                    body,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    syntax,
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
                    syntax,
                );
                apply_call_receiver_types_to_events(
                    catch_events,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    syntax,
                );
                apply_call_receiver_types_to_events(
                    finally_events,
                    aliases,
                    implicit_receiver_types,
                    class_facts,
                    syntax,
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
    syntax: ReceiverTypingSyntax<'_>,
) -> Vec<String> {
    let mut out = Vec::new();
    // Wrapper delimiters are semantic syntax owned by the adapter. Inspect
    // them before generic name normalization trims leading/trailing
    // punctuation; otherwise `type(self)` becomes `type(self` and the exact
    // wrapper fact is lost.
    if let Some(inner) = receiver_class_object_inner_expr(receiver.trim(), syntax.receiver_type_syntax) {
        for ty in receiver_types_for_expr(inner, aliases, implicit_receiver_types, class_facts, syntax) {
            push_unique_receiver_type(&mut out, ty);
        }
        if !out.is_empty() {
            return out;
        }
    }
    let normalized = normalize_receiver_type_expr(receiver);
    let tail = short_name_of(&normalized);
    if let Some(projected_type) = receiver_projected_type_name(&normalized, class_facts) {
        push_receiver_type_and_bases(&mut out, projected_type, class_facts);
        return out;
    }
    if let Some(declared_type) = receiver_declared_class_type(&normalized, class_facts) {
        push_receiver_type_and_bases(&mut out, declared_type, class_facts);
        return out;
    }
    let has_member_projection = bonsai_common::qualified_name_segments(&normalized).len() > 1;
    let projection_base = receiver_projection_base(&normalized);
    let base_is_implicit = receiver_matches_syntax_token(projection_base, syntax.implicit_receiver_tokens)
        || syntax
            .explicit_receiver_name
            .is_some_and(|name| normalize_receiver_type_expr(name) == projection_base)
        || receiver_matches_syntax_token(projection_base, syntax.super_receiver_tokens);
    // H7: an unguarded `alias.name == tail` types `pool.conn` (tail `conn`)
    // as whatever an unrelated local/param named `conn` is, a name-only FP.
    // Only fall back to the bare tail when there is no member projection, OR
    // the projection base is an implicit receiver (`this.field`/`self.field`)
    // where the tail genuinely names a field the alias map can resolve.
    let allow_bare_tail = !has_member_projection || base_is_implicit;
    for alias in aliases {
        let normalized_alias = normalize_receiver_type_expr(&alias.name);
        if normalized_alias == normalized || (allow_bare_tail && normalized_alias == tail) {
            push_receiver_type_and_bases(&mut out, alias.type_name.clone(), class_facts);
        }
    }
    for alias in aliases {
        let normalized_alias = normalize_receiver_type_expr(&alias.name);
        if receiver_projected_alias_matches(&normalized, &normalized_alias) {
            push_receiver_type_and_bases(&mut out, alias.type_name.clone(), class_facts);
        }
    }
    if receiver_matches_syntax_token(tail, syntax.implicit_receiver_tokens)
        || syntax
            .explicit_receiver_name
            .is_some_and(|name| normalize_receiver_type_expr(name) == tail)
    {
        if let Some(types) = implicit_receiver_types {
            for ty in types {
                push_receiver_type_and_bases(&mut out, ty.clone(), class_facts);
            }
        }
    } else if receiver_matches_syntax_token(tail, syntax.super_receiver_tokens) {
        if let Some(types) = implicit_receiver_types {
            for ty in types.iter().skip(1) {
                push_receiver_type_and_bases(&mut out, ty.clone(), class_facts);
            }
        }
    }
    out
}

fn receiver_matches_syntax_token(receiver: &str, syntax_tokens: &[&str]) -> bool {
    syntax_tokens
        .iter()
        .any(|token| token.trim().trim_matches(bonsai_common::is_name_punctuation) == receiver)
}

fn receiver_class_object_inner_expr(receiver: &str, syntax: crate::ReceiverTypeSyntax) -> Option<&str> {
    let expr = receiver.trim();
    for wrapper in syntax.wrapper_calls {
        if let Some(inner) = expr
            .strip_prefix(wrapper)
            .and_then(|rest| rest.strip_prefix('('))
            .and_then(|rest| rest.strip_suffix(')'))
        {
            let inner = inner.trim();
            if !inner.is_empty() {
                return Some(inner);
            }
        }
    }
    for suffix in syntax.class_object_suffixes {
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
    bonsai_common::qualified_name_segments(receiver)
        .into_iter()
        .next()
        .unwrap_or(receiver)
        .trim()
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
    let has_member_projection = bonsai_common::qualified_name_segments(receiver).len() > 1;
    if !has_member_projection {
        return None;
    }
    let tail = short_name_of(receiver)
        .trim_matches(bonsai_common::is_name_punctuation)
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

/// Resolve class references in a receiver expression against declarations
/// already emitted by the adapter. This covers immediate construction and
/// class-side factory syntax without interpreting constructor method names:
/// punctuation and call delimiters provide candidate identifiers, while the
/// class index decides whether any candidate is a type.
fn receiver_declared_class_type(receiver: &str, class_facts: &ClassFactsIndex<'_>) -> Option<String> {
    receiver
        .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
        .filter(|candidate| !candidate.is_empty())
        .rev()
        .find_map(|candidate| {
            let canonical = canonical_simple_type_name(candidate);
            class_facts
                .by_canonical_name
                .get(&canonical)
                .map(|(name, _)| name.clone())
        })
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
    let qualified = raw.trim().trim_matches(bonsai_common::is_name_punctuation).trim();
    if qualified.is_empty() || qualified == canonical {
        return None;
    }
    let has_qualifier = bonsai_common::qualified_name_segments(qualified).len() > 1;
    has_qualifier.then(|| qualified.to_string())
}

fn normalize_receiver_type_expr(receiver: &str) -> String {
    normalise_qualified_text(receiver)
        .trim()
        .trim_matches(bonsai_common::is_name_punctuation)
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
