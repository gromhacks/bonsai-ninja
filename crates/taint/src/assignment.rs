//! Assign-chain propagation pass.
//!
//! The reachability pass answers "is the source's name visible
//! anywhere on the chain?" — a blunt but honest proxy. Assign-chain
//! sharpens that by following
//! `FlowEvent::Assign { target, source_name  }` edges transitively:
//! if `y = source()` and later `z = y`, then `z` is tainted because
//! `y` was tainted. The `source_name` field on every assignment is
//! the bridge — adapters already populate it wherever the RHS is a
//! simple identifier.
//!
//! ## Semantics
//!
//! Assign-chain is **monotonic**: a name becomes tainted when an
//! assignment pulls from a tainted source, and stays tainted for the
//! rest of the walk. Reassignment-from-clean (`x = 5` after
//! `x = recv()`) does NOT remove taint — that's the intraprocedural
//! pass's CFG-aware job, which needs block ordering to distinguish
//! live data from overwritten data. Monotonic assign-chain is deliberately conservative:
//! for security work false positives beat false negatives, and the
//! intraprocedural pass is the layer that reclaims precision.
//!
//! The walker is an **in-order pass over the flow-event tree**. It
//! recurses into `Branch` / `Loop` / `Try` / `Defer` / `Using`
//! bodies and unions the taint sets coming out of each. Loop bodies
//! iterate to a fixed point so loop-carried assignment taint is visible
//! to later checks.
//!
//! ## API
//!
//! `assign_chain_taints(seed, events)` returns the full set of
//! identifiers that become tainted starting from `seed` after
//! walking `events`. Callers check `.contains(target)` themselves to
//! answer "does this specific name end up tainted?".
//!
//! The function is intraprocedural within a single flow-event tree;
//! the interprocedural pass handles cross-call propagation via the
//! resolved call graph.

use crate::{
    text::{normalise_qualified_text, qualified_access_bases, text_looks_qualified},
    tokens::{canonical_bare_name, qualified_wildcard_seed_matches, rhs_has_descendant_shape},
    TokenSet,
};
use bonsai_lang_api::FlowEvent;

/// Compute the set of identifiers tainted after walking `events`
/// in source order, starting from `seed`. Monotonic — the returned
/// set is always a superset of `seed`.
///
/// For each `FlowEvent::Assign { target, source_name: Some(src)  }`,
/// if `src` is already in the taint set, `target` is added. Nested
/// constructs (`Branch`, `Loop`, `Try`, `Defer`, `Using`) recurse and
/// union their results back into the caller's taint set.
///
/// Tokens that come out of the RHS as compound expressions
/// (`x + 1`, `f(x)`, etc.) produce `source_name = None` in most
/// adapters today — assign-chain skips those conservatively rather
/// than trying to regex-parse them. The intraprocedural pass will
/// enrich this via expression-level flow.
#[must_use]
pub fn assign_chain_taints(seed: &TokenSet, events: &[FlowEvent]) -> TokenSet {
    let mut tainted = seed.clone();
    walk_events(events, &mut tainted);
    tainted
}

/// Convenience predicate: does `target` end up tainted given the
/// starting `seed`? Shorthand for `assign_chain_taints(...).contains(target)`.
#[must_use]
pub fn target_is_tainted(seed: &TokenSet, target: &str, events: &[FlowEvent]) -> bool {
    assign_chain_taints(seed, events).contains(target)
}

/// True when the try-body contains a `Throw { value_name: Some(n) }`
/// whose `n` is in the current tainted set. Signals to the caller
/// that the catch region should be entered with its binding seeded
/// as tainted (G8 — exception-flow taint). Recurses through nested
/// control flow so throws buried inside branches/loops/inner tries
/// are still detected.
fn throw_taints_catch(events: &[FlowEvent], tainted: &TokenSet) -> bool {
    for event in events {
        match event {
            // Direct throw of a tainted value — the trigger we're looking for.
            FlowEvent::Throw {
                value_name: Some(thrown_name),
                ..
            } if !thrown_name.is_empty() && tainted.contains(thrown_name) => return true,
            // Recurse into branch arms; either arm carrying a tainted throw is enough.
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if throw_taints_catch(then_events, tainted) || throw_taints_catch(else_events, tainted) => {
                return true;
            }
            FlowEvent::Loop { body, .. } if throw_taints_catch(body, tainted) => return true,
            // Nested try/catch/finally regions can also harbour the throw.
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } if throw_taints_catch(body, tainted)
                || throw_taints_catch(catch_events, tainted)
                || throw_taints_catch(finally_events, tainted) =>
            {
                return true;
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. }
                if throw_taints_catch(body, tainted) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Walk flow events in order, mutating `tainted` in place. Assignment
/// RHS checks short-circuit after the first successful target insert;
/// the pass is set-based, so the remaining checks cannot change the
/// answer for that assignment.
///
/// Separate helper (not a closure) so recursion into nested constructs is
/// straightforward.
fn walk_events(events: &[FlowEvent], tainted: &mut TokenSet) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => {
                if target.is_empty() {
                    continue;
                }
                if let Some(source) = source_name.as_deref() {
                    if text_is_tainted(source, tainted) {
                        insert_target_taint(tainted, target);
                        if rhs_has_descendant_shape(source_names) {
                            insert_descendant_target_taint(tainted, target);
                        }
                        continue;
                    }
                }
                // Pass through compiler-proven descendant operands without
                // promoting the whole target. Display text in
                // `source_call_args` is never reparsed here; adapters already
                // lowered value-bearing places into `source_names`.
                if source_names
                    .iter()
                    .any(|source| !source.is_empty() && actual_has_descendant_taint(source, tainted))
                {
                    insert_descendant_target_taint(tainted, target);
                    continue;
                }
                if source_call
                    .as_deref()
                    .is_some_and(|callee| text_is_tainted(callee, tainted))
                {
                    insert_target_taint(tainted, target);
                    if rhs_has_descendant_shape(source_names) {
                        insert_descendant_target_taint(tainted, target);
                    }
                    continue;
                }
                // G2 — compound RHS operand taint. `y = prefix +
                // tainted` / `y = obj.field` / `y = f"{x} {y}"` /
                // `y = cond ? a : b`. Adapter surfaces every bare
                // identifier in the RHS as `source_names`.
                let qualified_bases = qualified_source_bases(source_names);
                if source_names.iter().any(|name| {
                    // Skip the qualified-access base (e.g. `obj` in `obj.field`):
                    // its presence in the operand list is structural, not a taint signal.
                    !name.is_empty()
                        && !qualified_bases.contains(&canonical_bare_name(name))
                        && text_is_tainted(name, tainted)
                }) {
                    insert_target_taint(tainted, target);
                    if rhs_has_descendant_shape(source_names) {
                        insert_descendant_target_taint(tainted, target);
                    }
                    continue;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                // Monotonic taint makes branch join trivial: walk
                // both arms against the *same* starting set, then
                // union the results. Either arm that taints a name
                // propagates it out.
                let mut then_taints = tainted.clone();
                walk_events(then_events, &mut then_taints);
                let mut else_taints = tainted.clone();
                walk_events(else_events, &mut else_taints);
                tainted.extend(then_taints);
                tainted.extend(else_taints);
            }
            FlowEvent::Loop { body, .. } => {
                // Iterate loop bodies to a fixed point. The transfer
                // function is monotonic over a finite set of source
                // names emitted by adapters, so convergence is quick
                // and avoids assuming a fixed number of back-edge
                // passes is enough for every loop shape.
                loop {
                    let before = tainted.len();
                    walk_events(body, tainted);
                    if tainted.len() == before {
                        break;
                    }
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                walk_events(body, tainted);
                // G8: if any `throw tainted` appeared in the body AND
                // the catch region has a declared binding, seed that
                // binding as tainted for the catch walk. This is how
                // `throw user_input; catch (e) { sink(e) }` propagates
                // through the exception handler. `throw_taints_body`
                // checks the body we just walked for any Throw whose
                // `value_name` is currently tainted.
                if let Some(param) = catch_param.as_deref() {
                    if throw_taints_catch(body, tainted) && !param.is_empty() {
                        tainted.insert(param.to_string());
                    }
                }
                walk_events(catch_events, tainted);
                walk_events(finally_events, tainted);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_events(body, tainted);
            }
            // Calls don't taint the caller's scope directly in
            // assign-chain. A tainted argument → tainted callee
            // parameter is the interprocedural pass's job.
            // A tainted return value written back to a variable shows
            // up as a later Assign event (assuming the adapter
            // populated source_name with the callee name — not
            // always the case).
            _ => {}
        }
    }
}

/// True when `text` references any tainted identifier — by direct
/// match, by qualified-access wildcard match (e.g. `obj.*`), by
/// receiver-method projection (`tainted.method(...)`), or by a canonical
/// adapter-lowered place.
fn text_is_tainted(text: &str, tainted: &TokenSet) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if tainted.contains(trimmed) {
        return true;
    }
    let normalised = normalise_qualified_text(trimmed);
    if crate::tokens::receiver_method_projection_is_tainted(trimmed, tainted, false) {
        return true;
    }
    // Wildcard seeds like `obj.*` only match qualified accesses,
    // never bare identifiers — guard the cheap shape check first.
    if text_looks_qualified(trimmed) && qualified_wildcard_seed_matches(&normalised, tainted) {
        return true;
    }
    normalised != trimmed && tainted.contains(&normalised)
}

/// True when `text`'s value comes from a wildcard-tainted ancestor
/// (`obj.*` seeded → `obj.field` matches). Distinct from
/// [`text_is_tainted`] because the call site must promote only the
/// descendant projection, not the whole assigned target.
fn actual_has_descendant_taint(text: &str, tainted: &TokenSet) -> bool {
    let normalised = normalise_qualified_text(text.trim());
    !normalised.is_empty() && qualified_wildcard_seed_matches(&normalised, tainted)
}

/// Insert `target` directly into the tainted set. Trivial wrapper kept
/// for parity with [`insert_descendant_target_taint`] so call sites
/// read symmetrically.
fn insert_target_taint(tainted: &mut TokenSet, target: &str) {
    tainted.insert(target.to_string());
}

/// Insert `target.*` (the wildcard descendant form) into the tainted
/// set. Skips qualified targets and already-wildcarded targets so we
/// don't generate `obj.field.*` or `obj.*.*` from re-entry.
fn insert_descendant_target_taint(tainted: &mut TokenSet, target: &str) {
    let target = normalise_qualified_text(target).trim().to_string();
    if target.is_empty() || text_looks_qualified(&target) || target.ends_with(".*") {
        return;
    }
    tainted.insert(format!("{target}.*"));
}

/// Collect every qualified-access base (the leftmost identifier of
/// each `a.b.c` form) appearing in `source_names`. Used to mask
/// structural occurrences of identifiers from the bare-token taint
/// check so `obj.field` doesn't taint a target via `obj` alone.
fn qualified_source_bases(source_names: &[String]) -> ahash::AHashSet<String> {
    let mut bases = ahash::AHashSet::new();
    for source in source_names {
        for base in qualified_access_bases(source) {
            bases.insert(base);
        }
    }
    bases
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "assignment_tests.rs"]
mod tests;
