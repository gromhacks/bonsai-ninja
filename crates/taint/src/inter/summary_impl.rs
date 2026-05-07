//! Implementation of `compute_function_summary` and its helpers.
//!
//! The public types (`FunctionSummary`, `ReturnAccessPath`,
//! `ParamSideEffect`) and the public accessor (`function_summary`)
//! live in `inter/summary.rs`; the implementation here is everything
//! needed to compute one summary from a `Decl`.
//!
//! ## How summaries are computed
//!
//! A function summary records which **parameter indices**, when
//! tainted on entry, still contribute to the function's return value
//! at every exit point. For `def transform(x): return x.upper()` the
//! summary is `returns_taint_of = {0}` (param 0 transits to the
//! return). For `def constant(): return 42` it's `{}` (nothing
//! transits to the return).
//!
//! The pipeline:
//!
//! 1. Walk the callee's events with an assign-chain seed of `{ param_i }`.
//! 2. Collect every name that gets assigned to any candidate "return
//!    token". `Return.value_name` is the ground-truth signal when the
//!    adapter surfaces it; otherwise we fall back to explicit return
//!    text and terminal tail-expression evidence.
//! 3. If `param_i` contributes to the tainted set at function exit,
//!    record `i` in the summary.
//!
//! Three transit kinds tracked separately:
//!
//! - **Direct value transit** (`returns_taint_of`) — `return x` when
//!   `x` was the seed.
//! - **Descendant transit** (`returns_descendant_taint_of`) — `return
//!   x.cmd` when `x.*` was the seed (lifecycle/carrier patterns).
//! - **Container transit** (`returns_container_taint_of`) — `return
//!   {"value": x}` where `x` was the seed (the result becomes a
//!   tainted descendant container in the caller).
//!
//! Plus two structural facts:
//!
//! - **Access paths** (`returns_access_paths`) — exact `(param, "cmd")`
//!   tuples for `return param.cmd` so callers can propagate
//!   `arg.cmd` without promoting sibling `arg.user`.
//! - **Param side effects** (`taints_params_from`) — `(source_param,
//!   target_param)` for in-place writes like `join(dst, ..., src)`
//!   where `src` taints `dst`.
//!
//! Recursion is not a concern here because each summary is computed
//! independently from the decl's events; cross-function recursion is
//! handled at the inter-pass level.

use ahash::AHashMap;
use bonsai_lang_api::{Decl, DeclKind, FlowEvent};

use crate::{
    assign_chain_taints,
    assignment::identifier_tokens_outside_strings,
    text::{is_quoted_literal, qualified_accesses, text_looks_qualified},
    TokenSet,
};

use super::{
    apply_event_transfer, apply_unresolved_call_side_effects, arg_text_is_tainted, bind_param_taint,
    call_receiver_from_name, identifier_value_occurs, insert_descendant_target_taint, insert_target_taint,
    insert_value_target_taint, normalise_qualified_text, normalise_target_text, push_unique_string,
    qualified_wildcard_seed_matches, value_marker, FunctionSummary, InterTaintConfig, ParamSideEffect,
    ReturnAccessPath,
};

/// Compute the return-taint summary for one function by running the
/// assign-chain pass with each parameter individually seeded and
/// checking whether the resulting taint set intersects with anything
/// that could plausibly flow to a return.
///
/// Return summaries are intentionally return-specific. If an adapter
/// exposes `Return.value_name`, use that precise site; otherwise fall
/// back only to explicit return text or terminal tail-expression
/// evidence. A function that merely consumes tainted input (`audit(x)`)
/// and returns a clean value must not be summarized as returning `x`.
#[must_use]
pub(crate) fn compute_function_summary(decl: &Decl) -> FunctionSummary {
    let mut returns_taint_of = Vec::new();
    let mut returns_descendant_taint_of = Vec::new();
    let mut returns_container_taint_of = Vec::new();
    // Functions with no params have no transit to record — short-circuit.
    if decl.params.is_empty() {
        return FunctionSummary {
            returns_taint_of,
            returns_descendant_taint_of,
            returns_container_taint_of,
            returns_access_paths: Vec::new(),
            taints_params_from: Vec::new(),
        };
    }
    // Prefer ground-truth Return.value_name when the adapter surfaced
    // it. Some grammars expose a call-expression return as the callee
    // or receiver (`return store.persist(valid)` -> value_name
    // `store`), so also accept explicit Return.value_text evidence.
    // Falls back to terminal tail evidence only when no Return
    // carries a value_name (adapter hasn't wired the field yet for
    // this grammar).
    let return_names = collect_return_value_names(&decl.flow_events);
    let has_precise_returns = !return_names.is_empty();
    let allow_terminal_tail_return = decl.has_implicit_returns;
    // Methods that return `self`-style state need an extra check:
    // any growth of the taint set past the seed implies the receiver state changed.
    let returns_implicit_receiver = decl.parent.is_some()
        && return_names
            .iter()
            .any(|name| !receiver_state_candidates(name).is_empty());
    for (param_idx, param) in decl.params.iter().enumerate() {
        if param.is_empty() {
            continue;
        }
        // Direct value transit — seed only the bare param name and run the chain.
        let mut value_seed = TokenSet::default();
        insert_value_target_taint(&mut value_seed, param);
        let value_tainted_at_end = assign_chain_taints(&value_seed, &decl.flow_events);
        let value_contributes = if has_precise_returns {
            return_names.iter().any(|name| value_tainted_at_end.contains(name))
                || contains_tainted_return(&decl.flow_events, &value_tainted_at_end)
                // Receiver-state methods: any growth past the seed counts as transit.
                || (returns_implicit_receiver && value_tainted_at_end.len() > value_seed.len())
        } else {
            // No precise return names — fall back to explicit / terminal-tail evidence.
            contains_tainted_return(&decl.flow_events, &value_tainted_at_end)
                || (allow_terminal_tail_return
                    && terminal_event_returns_taint(&decl.flow_events, &value_tainted_at_end))
        };
        if value_contributes {
            returns_taint_of.push(param_idx);
        }
        // Descendant transit — seed `param.*` so `return param.cmd` is flagged
        // even when the bare `param` itself doesn't contribute.
        let mut descendant_seed = TokenSet::default();
        insert_descendant_target_taint(&mut descendant_seed, param);
        let descendant_tainted_at_end = assign_chain_taints(&descendant_seed, &decl.flow_events);
        let descendant_contributes = if has_precise_returns {
            return_names.iter().any(|name| {
                descendant_tainted_at_end.contains(name)
                    || arg_text_is_tainted(name, &descendant_tainted_at_end)
                    || return_name_has_descendant_taint(name, &descendant_tainted_at_end)
            }) || contains_tainted_return(&decl.flow_events, &descendant_tainted_at_end)
                || (returns_implicit_receiver && descendant_tainted_at_end.len() > descendant_seed.len())
        } else {
            contains_tainted_return(&decl.flow_events, &descendant_tainted_at_end)
                || (allow_terminal_tail_return
                    && terminal_event_returns_taint(&decl.flow_events, &descendant_tainted_at_end))
        };
        if descendant_contributes {
            returns_descendant_taint_of.push(param_idx);
        }
        // Container transit: `return {"k": param}` builds a fresh
        // container, so the caller should see descendant taint.
        if contains_tainted_container_return(&decl.flow_events, &value_tainted_at_end) {
            returns_container_taint_of.push(param_idx);
        }
    }
    FunctionSummary {
        returns_taint_of,
        returns_descendant_taint_of,
        returns_container_taint_of,
        returns_access_paths: compute_return_access_paths(decl),
        taints_params_from: compute_param_side_effects(decl),
    }
}

/// True when `name` itself is not tainted as a whole value, but the
/// assignment pass recorded it as a scalar alias derived from a tainted
/// descendant (`carrier.*` -> `tmp.*` -> `return tmp`). Return summaries
/// need this distinction so callers receive descendant-derived scalar
/// taint without forcing every carrier sibling to become tainted.
fn return_name_has_descendant_taint(name: &str, tainted: &TokenSet) -> bool {
    let normalised = normalise_qualified_text(name.trim());
    !normalised.is_empty() && qualified_wildcard_seed_matches(&normalised, tainted)
}

/// Walk the decl once per parameter, tracking every aliased access
/// path that ends up flowing to a `Return` / `Yield` site. This
/// captures `(param_idx, "field.path")` pairs so callers know the
/// caller's `lhs.field.path` is exactly what becomes tainted.
fn compute_return_access_paths(decl: &Decl) -> Vec<ReturnAccessPath> {
    let mut access_paths = Vec::new();
    for (param_idx, param) in decl.params.iter().enumerate() {
        if param.is_empty() {
            continue;
        }
        // Per-parameter alias map; assignments may bind aliases that later
        // get returned, so the map evolves as we walk events.
        let mut aliases: AHashMap<String, Vec<String>> = AHashMap::new();
        walk_return_access_path_events(
            &decl.flow_events,
            param_idx,
            param,
            &mut aliases,
            &mut access_paths,
        );
    }
    access_paths
}

/// Recursively walk `events` to discover access paths flowing from
/// `param` into any return / yield site. Branches / try blocks get
/// their alias maps cloned and re-merged so cross-branch state
/// doesn't bleed.
fn walk_return_access_path_events(
    events: &[FlowEvent],
    param_idx: usize,
    param: &str,
    aliases: &mut AHashMap<String, Vec<String>>,
    access_paths: &mut Vec<ReturnAccessPath>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                let mut paths_for_target = Vec::new();
                // Cover every source surface — single name, multi-source, and call args.
                for source in source_name
                    .iter()
                    .map(String::as_str)
                    .chain(source_names.iter().map(String::as_str))
                    .chain(source_call_args.iter().map(String::as_str))
                {
                    collect_source_access_paths(source, param, aliases, &mut paths_for_target);
                }
                // Aliasing the target makes downstream returns of `target` produce these paths.
                for path in paths_for_target {
                    insert_access_alias(aliases, target, &path);
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                // Returns may carry both a textual form and a name — check both.
                for return_value in [value_text.as_deref(), value_name.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    let mut direct_paths = Vec::new();
                    collect_source_access_paths(return_value, param, aliases, &mut direct_paths);
                    // Returning an aliased target yields all access paths bound to that alias.
                    for (alias, alias_paths) in aliases.iter() {
                        if identifier_value_occurs(return_value, alias) {
                            for path in alias_paths {
                                push_return_access_path(access_paths, param_idx, path);
                            }
                        }
                    }
                    for path in direct_paths {
                        push_return_access_path(access_paths, param_idx, &path);
                    }
                }
            }
            FlowEvent::Yield { value_text, .. } => {
                // Yields are "returns over time" for our purposes — same handling.
                if let Some(yield_value) = value_text.as_deref() {
                    let mut direct_paths = Vec::new();
                    collect_source_access_paths(yield_value, param, aliases, &mut direct_paths);
                    for (alias, alias_paths) in aliases.iter() {
                        if identifier_value_occurs(yield_value, alias) {
                            for path in alias_paths {
                                push_return_access_path(access_paths, param_idx, path);
                            }
                        }
                    }
                    for path in direct_paths {
                        push_return_access_path(access_paths, param_idx, &path);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                // Each arm gets its own alias map snapshot so they don't pollute each other.
                let mut then_aliases = aliases.clone();
                walk_return_access_path_events(
                    then_events,
                    param_idx,
                    param,
                    &mut then_aliases,
                    access_paths,
                );
                let mut else_aliases = aliases.clone();
                walk_return_access_path_events(
                    else_events,
                    param_idx,
                    param,
                    &mut else_aliases,
                    access_paths,
                );
                // Join: post-branch aliases include anything seen on either arm.
                merge_access_aliases(aliases, then_aliases);
                merge_access_aliases(aliases, else_aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_return_access_path_events(body, param_idx, param, aliases, access_paths);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                // Try body and catch each get a fresh snapshot — exceptions split control flow.
                let mut body_aliases = aliases.clone();
                walk_return_access_path_events(body, param_idx, param, &mut body_aliases, access_paths);
                let mut catch_aliases = aliases.clone();
                walk_return_access_path_events(
                    catch_events,
                    param_idx,
                    param,
                    &mut catch_aliases,
                    access_paths,
                );
                merge_access_aliases(&mut body_aliases, catch_aliases);
                // Finally runs after either path — fold it on top of the merged body+catch state.
                walk_return_access_path_events(
                    finally_events,
                    param_idx,
                    param,
                    &mut body_aliases,
                    access_paths,
                );
                merge_access_aliases(aliases, body_aliases);
            }
            _ => {}
        }
    }
}

/// Append every access path implied by `source` (either directly
/// rooted in `param`, or via an existing alias binding) to `out`.
fn collect_source_access_paths(
    source: &str,
    param: &str,
    aliases: &AHashMap<String, Vec<String>>,
    out: &mut Vec<String>,
) {
    // Direct hit: `source` is `param.foo.bar` — extract `foo.bar`.
    if let Some(path) = access_path_from_param(source, param) {
        push_unique_string(out, path);
    }
    // Indirect hit: `source` matches a previously-aliased target — inherit its paths.
    for key in access_alias_keys(source) {
        if let Some(paths) = aliases.get(&key) {
            for path in paths {
                push_unique_string(out, path.clone());
            }
        }
    }
}

/// Strip the `param.` prefix off `source`; return the remaining
/// access path or None when `source` doesn't start with `param`.
fn access_path_from_param(source: &str, param: &str) -> Option<String> {
    let source = normalise_target_text(source);
    if source.is_empty() {
        return None;
    }
    // Try every alias spelling of `param` (with / without sigils) as a prefix.
    for base in access_alias_keys(param) {
        if let Some(rest) = source.strip_prefix(&base) {
            // Require the next char to be `.` — guard against `paramX` matching `param`.
            if let Some(path) = rest.strip_prefix('.') {
                let path = path.trim().trim_matches('.').to_string();
                if !path.is_empty() {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Bind `path` to every alias-spelling of `target` so a later return
/// of `target` (or its sigil variants) can look the path back up.
fn insert_access_alias(aliases: &mut AHashMap<String, Vec<String>>, target: &str, path: &str) {
    for key in access_alias_keys(target) {
        push_unique_string(aliases.entry(key).or_default(), path.to_string());
    }
}

/// Lookup keys for `text`: the normalised form plus a sigil-stripped
/// fallback so `$user` and `user` resolve to the same alias.
pub(super) fn access_alias_keys(text: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let normalised = normalise_target_text(text);
    if !normalised.is_empty() {
        push_unique_string(&mut keys, normalised.clone());
        // Sigil-stripped variant (`$x` -> `x`) so PHP / Perl style names alias correctly.
        let bare = normalised.trim_start_matches(&['$', '@', '%'][..]);
        if bare != normalised && !bare.is_empty() {
            push_unique_string(&mut keys, bare.to_string());
        }
    }
    keys
}

/// Fold `source` into `target`, deduplicating by exact path string.
fn merge_access_aliases(target: &mut AHashMap<String, Vec<String>>, source: AHashMap<String, Vec<String>>) {
    for (alias, paths) in source {
        let target_paths = target.entry(alias).or_default();
        for path in paths {
            push_unique_string(target_paths, path);
        }
    }
}

/// Append `(param, path)` to the access-path output if it isn't
/// already present — keeps the result list deduplicated.
fn push_return_access_path(out: &mut Vec<ReturnAccessPath>, param: usize, path: &str) {
    let path = path.trim().trim_matches('.');
    if path.is_empty() {
        return;
    }
    if !out
        .iter()
        .any(|existing| existing.param == param && existing.path == path)
    {
        out.push(ReturnAccessPath {
            param,
            path: path.to_string(),
        });
    }
}

/// Discover parameter-to-parameter side effects: for each source
/// param, simulate "what if it was tainted on entry?" and check
/// whether any other param ends up tainted at function exit.
fn compute_param_side_effects(decl: &Decl) -> Vec<ParamSideEffect> {
    let mut effects = Vec::new();
    for (source_idx, source_param) in decl.params.iter().enumerate() {
        if source_param.is_empty() {
            continue;
        }
        // Seed only the source param and run a side-effect-aware walk.
        let mut state = TokenSet::default();
        insert_value_target_taint(&mut state, source_param);
        walk_events_for_local_side_effects(&decl.flow_events, &mut state);
        for (target_idx, target_param) in decl.params.iter().enumerate() {
            // Skip self-edges and unnamed params.
            if source_idx == target_idx || target_param.is_empty() {
                continue;
            }
            // Record the (source, target) edge once per distinct pair.
            if target_param_is_mutated_by_state(target_param, &state)
                && !effects.iter().any(|effect: &ParamSideEffect| {
                    effect.source_param == source_idx && effect.target_param == target_idx
                })
            {
                effects.push(ParamSideEffect {
                    source_param: source_idx,
                    target_param: target_idx,
                });
            }
        }
    }
    effects
}

/// True when the post-walk taint state contains evidence that
/// `param` (or any descendant of it) was mutated.
fn target_param_is_mutated_by_state(param: &str, state: &TokenSet) -> bool {
    let param = normalise_target_text(param);
    !param.is_empty()
        && (state.contains(&param)
            || state.contains(&value_marker(&param))
            // Wildcard descendant marker: `param.*` covers `param.field` etc.
            || state.contains(&format!("{param}.*"))
            // Concrete descendant: a seed whose normalised form is `param.something`.
            || state.iter().any(|seed| {
                let seed = normalise_qualified_text(seed);
                seed.strip_prefix(param.as_str())
                    .is_some_and(|rest| rest.starts_with('.'))
            }))
}

/// Walk events, mutating `state` to reflect every observable side
/// effect on local / parameter names. Used only to detect param-to-
/// param taint flow within one function — call resolution is left to
/// the inter pass.
fn walk_events_for_local_side_effects(events: &[FlowEvent], state: &mut TokenSet) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                // Find arg positions whose text is currently tainted.
                let tainted_at_call: Vec<(usize, String)> = args
                    .iter()
                    .enumerate()
                    .filter(|(_, arg)| arg_text_is_tainted(&arg.value_text, state))
                    .map(|(arg_idx, arg)| (arg_idx, arg.value_text.clone()))
                    .collect();
                // Conservative: an unresolved callee may write taint into other args.
                apply_unresolved_call_side_effects(args, &tainted_at_call, state);
            }
            FlowEvent::Assign { .. } => {
                // Reuse the shared event-transfer logic with a minimal config —
                // no sanitizers, zero budget, since we're only counting locals.
                let transfer_config = InterTaintConfig {
                    sanitizers: TokenSet::default(),
                    budget: 0,
                    intra_worklist_cap: None,
                    ..Default::default()
                };
                apply_event_transfer(event, state, &transfer_config, None, None);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                // Each arm gets a clone; the join is a union.
                let mut then_state = state.clone();
                walk_events_for_local_side_effects(then_events, &mut then_state);
                let mut else_state = state.clone();
                walk_events_for_local_side_effects(else_events, &mut else_state);
                let mut merged = then_state;
                merged.extend(else_state);
                *state = merged;
            }
            FlowEvent::Loop { body, .. } => loop {
                // Fixed-point iteration — re-walk the body until the state stops growing.
                let len_before = state.len();
                walk_events_for_local_side_effects(body, state);
                if state.len() == len_before {
                    break;
                }
            },
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                // Conservative: assume each block runs and contributes its effects.
                walk_events_for_local_side_effects(body, state);
                walk_events_for_local_side_effects(catch_events, state);
                walk_events_for_local_side_effects(finally_events, state);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_events_for_local_side_effects(body, state);
            }
            _ => {}
        }
    }
}

/// Collect every `Return { value_name: Some(n) }` target name in the
/// function body (including nested branches / loops / try / defer /
/// using scopes). Empty when the adapter hasn't populated value_name
/// for this grammar — callers fall back to the reachability heuristic.
fn collect_return_value_names(events: &[FlowEvent]) -> Vec<String> {
    let mut return_names = Vec::new();
    walk_return_names(events, &mut return_names);
    return_names
}

/// True when the callee returns its receiver / receiver state —
/// e.g. a builder method `set_x` that returns `self` after mutating.
fn callee_returns_implicit_receiver_state(decl: &Decl) -> bool {
    let receiver_state_names = receiver_state_names_for_decl(decl);
    if receiver_state_names.is_empty() {
        return false;
    }
    // Seed all receiver-state names with both bare and descendant taint
    // so any path that returns the receiver (or a sub-field) registers.
    let mut receiver_state = TokenSet::default();
    for name in receiver_state_names {
        insert_target_taint(&mut receiver_state, &name);
        insert_descendant_target_taint(&mut receiver_state, &name);
    }
    contains_tainted_return(&decl.flow_events, &receiver_state)
}

/// True when calling `decl` on `receiver` would yield a tainted
/// return given the caller's current `caller_state`. Two paths:
/// first, the projected `receiver.method` form is itself tainted;
/// second, binding the caller's receiver state into the callee
/// produces a tainted return.
pub(super) fn implicit_receiver_return_is_tainted(
    decl: &Decl,
    receiver: &str,
    caller_state: &TokenSet,
) -> bool {
    let receiver = normalise_target_text(receiver);
    if !receiver.is_empty() {
        // Form 1: caller has tainted `receiver.method` directly.
        let projected_method = format!("{receiver}.{}", decl.name);
        if caller_state.contains(&projected_method)
            || caller_state.contains(&value_marker(&projected_method))
            || qualified_wildcard_seed_matches(&projected_method, caller_state)
        {
            return true;
        }
    }
    let receiver_state_names = receiver_state_names_for_decl(decl);
    if receiver_state_names.is_empty() {
        return false;
    }
    // Form 2: project caller-side receiver taint into callee parameter space
    // and check whether the callee's return path is tainted under that binding.
    let mut callee_state = TokenSet::default();
    for receiver_seed in receiver_state_names {
        bind_param_taint(&mut callee_state, &receiver_seed, &receiver, caller_state);
    }
    if !callee_state.is_empty() && contains_tainted_return(&decl.flow_events, &callee_state) {
        return true;
    }
    // Fallback: caller knows the receiver itself is tainted, and the callee
    // returns receiver-state — so the call's value is tainted by transitivity.
    (caller_state.contains(&receiver) || caller_state.contains(&value_marker(&receiver)))
        && callee_returns_implicit_receiver_state(decl)
}

/// All names in `decl` that act as the receiver / receiver state.
/// Drawn first from adapter-supplied lists, then fallbacks: inferred
/// from event shape, then the first param for plain `Method` decls,
/// then any implicit-member bases the body references.
pub(super) fn receiver_state_names_for_decl(decl: &Decl) -> Vec<String> {
    let mut names = Vec::new();
    // Adapter-declared receiver names take priority — they're the most precise signal.
    for name in decl
        .implicit_receiver_names
        .iter()
        .chain(decl.receiver_state_sources.iter())
    {
        push_receiver_state_name(&mut names, name);
    }
    // Adapter said nothing — try to spot `self`/`this` markers in events.
    if names.is_empty() {
        infer_receiver_state_names(&decl.flow_events, &mut names);
    }
    // Plain Method without explicit hints: the first param is the conventional receiver.
    if names.is_empty() && matches!(decl.kind, DeclKind::Method) {
        if let Some(first_param) = decl.params.first() {
            push_receiver_state_name(&mut names, first_param);
            if !first_param.trim().is_empty() && !names.iter().any(|existing| existing == first_param) {
                names.push(first_param.clone());
            }
        }
    }
    // Implicit member access (`return self.foo`) — bare bases count too.
    infer_implicit_member_state_names(&decl.flow_events, &mut names, decl.params.is_empty());
    names
}

/// Recursively walk events looking for `self` / `this` style markers
/// so paramless or inferred-receiver decls still pick up state.
fn infer_receiver_state_names(events: &[FlowEvent], names: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Call { receiver, name, .. } => {
                // Explicit receiver field is the cheapest signal.
                if let Some(receiver) = receiver.as_deref() {
                    push_receiver_state_name(names, receiver);
                }
                // Some adapters fold the receiver into `name` (e.g. `self.do_it`) — split it back out.
                if let Some(receiver) = call_receiver_from_name(name) {
                    push_receiver_state_name(names, &receiver);
                }
            }
            FlowEvent::Assign {
                source_call,
                source_names,
                ..
            } => {
                if let Some(receiver) = source_call.as_deref().and_then(call_receiver_from_name) {
                    push_receiver_state_name(names, &receiver);
                }
                for source in source_names {
                    push_receiver_state_name(names, source);
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                // Returning `self` directly — both forms can carry it.
                if let Some(value) = value_text.as_deref() {
                    push_receiver_state_name(names, value);
                }
                if let Some(value) = value_name.as_deref() {
                    push_receiver_state_name(names, value);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                infer_receiver_state_names(then_events, names);
                infer_receiver_state_names(else_events, names);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                infer_receiver_state_names(body, names);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                infer_receiver_state_names(body, names);
                infer_receiver_state_names(catch_events, names);
                infer_receiver_state_names(finally_events, names);
            }
            _ => {}
        }
    }
}

/// Push every receiver-state spelling extracted from `text`,
/// skipping any duplicates already in `names`.
fn push_receiver_state_name(names: &mut Vec<String>, text: &str) {
    for candidate in receiver_state_candidates(text) {
        if !names.iter().any(|existing| existing == &candidate) {
            names.push(candidate);
        }
    }
}

/// Walk events looking for implicit member bases like `self.foo` /
/// `state.bar`, capturing the bases (`self`, `state`) as receiver
/// state. When `include_bare_members` is set, plain identifiers in
/// assigns / call args also count — needed for paramless funcs.
fn infer_implicit_member_state_names(
    events: &[FlowEvent],
    names: &mut Vec<String>,
    include_bare_members: bool,
) {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                // Returning a member access exposes its base as state.
                if let Some(value) = value_text.as_deref() {
                    push_implicit_member_bases(names, value);
                }
                if let Some(value) = value_name.as_deref() {
                    push_implicit_member_bases(names, value);
                }
            }
            FlowEvent::Assign { source_names, .. } => {
                for source in source_names {
                    push_implicit_member_bases(names, source);
                    // Bare-member mode: capture plain identifiers for paramless callees.
                    if include_bare_members {
                        push_implicit_bare_member_name(names, source);
                    }
                }
            }
            FlowEvent::Call { args, .. } => {
                if include_bare_members {
                    for arg in args {
                        push_implicit_bare_member_name(names, &arg.value_text);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                infer_implicit_member_state_names(then_events, names, include_bare_members);
                infer_implicit_member_state_names(else_events, names, include_bare_members);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                infer_implicit_member_state_names(body, names, include_bare_members);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                infer_implicit_member_state_names(body, names, include_bare_members);
                infer_implicit_member_state_names(catch_events, names, include_bare_members);
                infer_implicit_member_state_names(finally_events, names, include_bare_members);
            }
            _ => {}
        }
    }
}

/// Add `text` as a bare-identifier receiver-state candidate when it
/// looks like a plain identifier (no dots, no quotes, no leading
/// digit). Filters keep call args like `42`, `"x"`, or `obj.field`
/// from polluting the receiver-state list.
fn push_implicit_bare_member_name(names: &mut Vec<String>, text: &str) {
    let candidate = text.trim();
    // Reject anything that isn't a clean bare identifier.
    if candidate.is_empty()
        || text_looks_qualified(candidate)
        || is_quoted_literal(candidate)
        || !candidate
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !candidate
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return;
    }
    if !names.iter().any(|existing| existing == candidate) {
        names.push(candidate.to_string());
    }
}

/// Append the leading base of every qualified access in `text`,
/// excluding bases that look type-like (start with uppercase).
fn push_implicit_member_bases(names: &mut Vec<String>, text: &str) {
    for access in qualified_accesses(text) {
        let Some(base) = access.split('.').next() else {
            continue;
        };
        let base = base.trim();
        // `Foo.bar` is most likely a static / namespaced access, not receiver state.
        if base.is_empty() || looks_like_type_or_namespace(base) {
            continue;
        }
        if !names.iter().any(|existing| existing == base) {
            names.push(base.to_string());
        }
    }
}

/// Heuristic: identifiers starting with an uppercase letter are
/// treated as types or namespaces (`Foo.bar`), not receivers.
fn looks_like_type_or_namespace(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_uppercase())
}

/// Extract every receiver-style marker (`self`, `this`, `super`,
/// `parent`, with or without sigils) referenced by `text`. Used to
/// canonicalise adapter-supplied receiver names across grammars.
fn receiver_state_candidates(text: &str) -> Vec<String> {
    let normalised = normalise_qualified_text(text);
    let mut candidates = Vec::new();
    // Try the raw and normalised forms so both `$self` and `self` register.
    push_receiver_marker_candidate(&mut candidates, text);
    push_receiver_marker_candidate(&mut candidates, &normalised);
    // Tokens inside the normalised text — handles `self.foo + bar` etc.
    for token in identifier_tokens_outside_strings(&normalised) {
        push_receiver_marker_candidate(&mut candidates, &token);
    }
    // Qualified-access bases — `self.field` contributes `self`.
    for access in qualified_accesses(&normalised) {
        if let Some(base) = access.split('.').next() {
            push_receiver_marker_candidate(&mut candidates, base);
        }
    }
    candidates
}

/// Recognise the canonical receiver names (`self`, `this`, `super`,
/// `parent`) and push both sigil-bearing and bare spellings.
fn push_receiver_marker_candidate(out: &mut Vec<String>, token: &str) {
    let token = token.trim();
    if token.is_empty() {
        return;
    }
    // Strip sigils so we can match on the bare name regardless of grammar.
    let bare = token.trim_start_matches(&['$', '@', '%'][..]);
    if !matches!(bare, "self" | "this" | "super" | "parent") {
        return;
    }
    // Push both forms — adapters may key on either.
    for candidate in [token, bare] {
        if !candidate.is_empty() && !out.iter().any(|existing| existing == candidate) {
            out.push(candidate.to_string());
        }
    }
}

/// Recursively collect `value_name` from every Return / Yield event,
/// including those nested in branches / loops / try blocks.
fn walk_return_names(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Return {
                value_name: Some(name),
                ..
            }
            | FlowEvent::Yield {
                value_text: Some(name),
                ..
            } => out.push(name.clone()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_return_names(then_events, out);
                walk_return_names(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_return_names(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_return_names(body, out);
                walk_return_names(catch_events, out);
                walk_return_names(finally_events, out);
            }
            _ => {}
        }
    }
}

/// True when any `Return` or `Yield` in `events` (recursively
/// through nested control structures) carries a tainted value.
/// Adapters that expose a richer `Return { value_name }` can replace
/// this with a direct check later; for now, being conservative and
/// returning true only for explicit return-bearing events keeps
/// clean consume-only helpers from becoming caller-tainting.
fn contains_tainted_return(events: &[FlowEvent], tainted: &TokenSet) -> bool {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text: Some(text),
                ..
            }
            | FlowEvent::Yield {
                value_text: Some(text),
                ..
            } if return_value_text_is_tainted(text, tainted) => return true,
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if contains_tainted_return(then_events, tainted)
                || contains_tainted_return(else_events, tainted) =>
            {
                return true;
            }
            FlowEvent::Loop { body, .. } if contains_tainted_return(body, tainted) => return true,
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } if contains_tainted_return(body, tainted)
                || contains_tainted_return(catch_events, tainted)
                || contains_tainted_return(finally_events, tainted) =>
            {
                return true;
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. }
                if contains_tainted_return(body, tainted) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn return_value_text_is_tainted(text: &str, tainted: &TokenSet) -> bool {
    arg_text_is_tainted(terminal_return_expression_text(text), tainted)
}

fn terminal_return_expression_text(text: &str) -> &str {
    let trimmed = text.trim();
    let without_do = trimmed
        .strip_prefix("do ")
        .and_then(|inner| inner.strip_suffix(" end"))
        .unwrap_or(trimmed)
        .trim();
    let without_arrow = without_do.strip_prefix("->").unwrap_or(without_do).trim();
    split_terminal_return_segment(without_arrow).trim()
}

fn split_terminal_return_segment(text: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut last_split = 0usize;
    let mut chars = text.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ';' | ',' if depth == 0 => last_split = idx + ch.len_utf8(),
            _ => {}
        }
    }
    &text[last_split..]
}

/// True when any `Return`/`Yield` in `events` builds a fresh
/// container (object literal / array / tuple) whose contents include
/// a tainted value. Used to classify "container transit" — taint
/// flows into the caller via the returned aggregate, not by direct
/// transit of a single name.
fn contains_tainted_container_return(events: &[FlowEvent], tainted: &TokenSet) -> bool {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text: Some(text),
                ..
            }
            | FlowEvent::Yield {
                value_text: Some(text),
                ..
            } if return_text_constructs_container(text) && arg_text_is_tainted(text, tainted) => {
                return true;
            }
            FlowEvent::Branch {
                condition,
                then_events,
                else_events,
                ..
            } if condition
                .as_deref()
                .is_some_and(|condition| arg_text_is_tainted(condition, tainted))
                && (events_have_dynamic_container_return(then_events)
                    || events_have_dynamic_container_return(else_events)) =>
            {
                // Tainted condition guarding a dynamic container return — caller sees taint
                // even though no single source name persists into the returned container.
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if contains_tainted_container_return(then_events, tainted)
                || contains_tainted_container_return(else_events, tainted) =>
            {
                return true;
            }
            FlowEvent::Loop { body, .. } if contains_tainted_container_return(body, tainted) => {
                return true;
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } if contains_tainted_container_return(body, tainted)
                || contains_tainted_container_return(catch_events, tainted)
                || contains_tainted_container_return(finally_events, tainted) =>
            {
                return true;
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. }
                if contains_tainted_container_return(body, tainted) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Cheap syntactic gate: the return text begins with a container
/// constructor (`{...}`, `[...]`, or `(...)` carrying nested braces).
fn return_text_constructs_container(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with('{')
        || trimmed.starts_with('[')
        // Tuples may wrap a dict / list literal — `({"x": y})`.
        || trimmed.starts_with('(') && (trimmed.contains('{') || trimmed.contains('['))
}

/// True when any return / yield in `events` builds a container
/// whose body references at least one runtime identifier (i.e. it's
/// not a fully-static literal like `{"k": "v"}` or `[1, 2, 3]`).
fn events_have_dynamic_container_return(events: &[FlowEvent]) -> bool {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text: Some(text),
                ..
            }
            | FlowEvent::Yield {
                value_text: Some(text),
                ..
            } if return_text_constructs_container(text) && return_text_has_dynamic_identifier(text) => {
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if events_have_dynamic_container_return(then_events)
                    || events_have_dynamic_container_return(else_events)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if events_have_dynamic_container_return(body) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if events_have_dynamic_container_return(body)
                    || events_have_dynamic_container_return(catch_events)
                    || events_have_dynamic_container_return(finally_events)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// True when `text` mentions a runtime identifier — anything that
/// isn't a hardcoded boolean / null literal.
fn return_text_has_dynamic_identifier(text: &str) -> bool {
    identifier_tokens_outside_strings(text).iter().any(|token| {
        !matches!(
            token.as_str(),
            "true" | "false" | "True" | "False" | "null" | "None" | "nil"
        )
    })
}

/// Tail-position evidence: when no explicit `Return` carries a
/// value, the function's terminal event may still implicitly
/// produce the return value (Rust / Ruby tail-expression style).
fn terminal_event_returns_taint(events: &[FlowEvent], tainted: &TokenSet) -> bool {
    let Some(last_event) = events.last() else {
        return false;
    };
    match last_event {
        // Calls in tail position produce a return value, but we
        // can't see through the callee here — leave to the inter pass.
        FlowEvent::Call { .. } => false,
        FlowEvent::Yield {
            value_text: Some(text),
            ..
        } => arg_text_is_tainted(text, tainted),
        FlowEvent::Assign {
            target,
            source_name,
            source_names,
            source_call_args,
            ..
        } => {
            // Tail assign: any tainted source on the RHS, or a tainted target name, transits.
            tainted.contains(target)
                || source_name
                    .as_deref()
                    .is_some_and(|source| arg_text_is_tainted(source, tainted))
                || source_names
                    .iter()
                    .any(|source| arg_text_is_tainted(source, tainted))
                || source_call_args
                    .iter()
                    .any(|source| arg_text_is_tainted(source, tainted))
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            // Either arm can be the tail in a branch-as-expression form.
            terminal_event_returns_taint(then_events, tainted)
                || terminal_event_returns_taint(else_events, tainted)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            terminal_event_returns_taint(body, tainted)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            // Finally runs last, so it's the actual tail; fall back to catch / body.
            terminal_event_returns_taint(finally_events, tainted)
                || terminal_event_returns_taint(catch_events, tainted)
                || terminal_event_returns_taint(body, tainted)
        }
        FlowEvent::Return { .. } => contains_tainted_return(std::slice::from_ref(last_event), tainted),
        _ => false,
    }
}
