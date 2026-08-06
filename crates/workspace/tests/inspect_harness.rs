//! Reusable in-process `inspect` harness.
//!
//! The CLI's `inspect` is the tool's headline feature — given a query it
//! must enumerate every cross-module flow that reaches the match. The
//! per-language suites in `inspect_lang_*.rs` pull these helpers in via
//! `#[path = "inspect_harness.rs"]` so the logic that powers `inspect`
//! is exercised directly (no release binary required).
//!
//! The helpers here deliberately mirror the CLI's semantics — if a
//! regression creeps into the chain walker, both the tests here and the
//! CLI output regress together.

#![allow(dead_code, unreachable_pub)]

use ahash::{AHashMap, AHashSet};
use bonsai_lang_api::{AdapterArc, Decl, DeclKind, FlowEvent, LanguageRegistry, RefKind};
use bonsai_workspace::Workspace;
use std::sync::Arc;

/// Build a workspace from an adapter and a set of `(path, source)` files.
pub fn ws_multi(adapter: AdapterArc, files: &[(&str, &str)]) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let ws = Workspace::new(registry);
    for (p, src) in files {
        ws.vfs().write((*p).to_string(), Arc::<str>::from(*src));
    }
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

// ---------------------------------------------------------------------------
// Callee / caller indexing (mirrors `build_callers_map` in the CLI)
// ---------------------------------------------------------------------------

/// Build a `callee -> {caller}` map for every edge visible in the
/// workspace, indexed by BOTH the full qualified callee text AND the
/// short tail name — so cross-class method calls like
/// `authService.runAdminCommand` resolve to `runAdminCommand`. Also
/// resolves per-file symbol aliases (`from x import y as z; z()` →
/// edge indexed under both `z` and `y`).
pub fn build_callers_map(ws: &Workspace) -> AHashMap<String, AHashSet<String>> {
    let global = ws.db().global_index();
    let mut map: AHashMap<String, AHashSet<String>> = AHashMap::new();
    let callable_names = callable_names(ws);
    for file in global.all_files() {
        let aliases = per_file_symbol_aliases(ws, file);
        for d in global.decls_in(file) {
            collect_call_edges(&d.flow_events, &d.name, &aliases, &callable_names, &mut map);
        }
    }
    map
}

fn callable_names(ws: &Workspace) -> AHashSet<String> {
    let global = ws.db().global_index();
    let mut out = AHashSet::new();
    for file in global.all_files() {
        for d in global.decls_in(file) {
            if matches!(
                d.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                out.insert(d.name.clone());
            }
        }
    }
    out
}

/// Mirror of the CLI's `per_file_symbol_aliases` — derives a
/// {local → original} map from each file's imports. Prefer the per-adapter
/// extractor (populates `alias` + `original_name` for forms like Python's
/// `from x import y as z`). An empty adapter result is authoritative.
fn per_file_symbol_aliases(ws: &Workspace, file: bonsai_common::FileId) -> AHashMap<String, String> {
    let mut map: AHashMap<String, String> = AHashMap::new();
    let imports = ws.db().imports_for(file);
    for imp in &imports {
        if let (Some(local), Some(original)) = (imp.alias.as_deref(), imp.original_name.as_deref()) {
            if local != original && !local.is_empty() && !original.is_empty() {
                map.insert(local.to_string(), original.to_string());
            }
        }
    }
    map
}

fn collect_call_edges(
    events: &[FlowEvent],
    caller: &str,
    aliases: &AHashMap<String, String>,
    callable_names: &AHashSet<String>,
    map: &mut AHashMap<String, AHashSet<String>>,
) {
    for e in events {
        match e {
            FlowEvent::Call {
                name, receiver, args, ..
            } => {
                map.entry(name.clone()).or_default().insert(caller.to_string());
                let short = short_tail(name);
                if short != name.as_str() {
                    map.entry(short.to_string())
                        .or_default()
                        .insert(caller.to_string());
                }
                if let Some(no_bang) = short.strip_suffix('!') {
                    map.entry(no_bang.to_string())
                        .or_default()
                        .insert(caller.to_string());
                }
                // Alias resolution: the short tail may be a local name
                // bound to an `from x import y as z` original — emit an
                // edge under the original symbol as well.
                if let Some(original) = aliases.get(short) {
                    map.entry(original.clone())
                        .or_default()
                        .insert(caller.to_string());
                }
                if receiver.is_some() {
                    for arg in args {
                        let callback = short_tail(arg.value_text.trim());
                        if callable_names.contains(callback) {
                            map.entry(callback.to_string())
                                .or_default()
                                .insert(caller.to_string());
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_call_edges(then_events, caller, aliases, callable_names, map);
                collect_call_edges(else_events, caller, aliases, callable_names, map);
            }
            FlowEvent::Loop { body, .. } => collect_call_edges(body, caller, aliases, callable_names, map),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_call_edges(body, caller, aliases, callable_names, map);
                collect_call_edges(catch_events, caller, aliases, callable_names, map);
                collect_call_edges(finally_events, caller, aliases, callable_names, map);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_call_edges(body, caller, aliases, callable_names, map);
            }
            _ => {}
        }
    }
}

fn short_tail(name: &str) -> &str {
    let last_dot = name.rfind('.').map(|i| i + 1).unwrap_or(0);
    let last_double_colon = name.rfind("::").map(|i| i + 2).unwrap_or(0);
    let last_arrow = name.rfind("->").map(|i| i + 2).unwrap_or(0);
    // Erlang `module:fn` — single colon. Skip if it's part of `::`.
    let last_erlang_colon = name
        .rfind(':')
        .filter(|&i| {
            let bytes = name.as_bytes();
            !(i > 0 && bytes[i - 1] == b':')
        })
        .map(|i| i + 1)
        .unwrap_or(0);
    let cut = last_dot
        .max(last_double_colon)
        .max(last_arrow)
        .max(last_erlang_colon);
    &name[cut..]
}

// ---------------------------------------------------------------------------
// Chain enumeration (mirrors CLI `enumerate_chains`)
// ---------------------------------------------------------------------------

/// Walk every incoming-edge from `target` back to unreached roots and
/// return one chain per (entry, path) pair. The chains read top-down:
/// `[entry, …, target]`.
pub fn enumerate_chains(ws: &Workspace, target: &str, max_chains: usize) -> Vec<Vec<String>> {
    let callers = build_callers_map(ws);
    let mut results: Vec<Vec<String>> = Vec::new();
    let mut stack: Vec<Vec<String>> = vec![vec![target.to_string()]];
    let mut visited = 0usize;
    while let Some(path_rev) = stack.pop() {
        if results.len() >= max_chains {
            break;
        }
        visited += 1;
        if visited > max_chains * 64 {
            break;
        }
        let head = path_rev.last().cloned().unwrap();
        let mut pushed_any_parent = false;
        if let Some(parents) = callers.get(&head) {
            for p in parents {
                if path_rev.contains(p) {
                    continue;
                }
                let mut next = path_rev.clone();
                next.push(p.clone());
                stack.push(next);
                pushed_any_parent = true;
            }
        }
        if !pushed_any_parent {
            // Either `head` has no callers at all, or every caller was
            // already on the path (self-cycle / mutual recursion). In
            // both cases we treat this path as a complete chain.
            if path_rev.len() > 1 {
                let mut chain = path_rev.clone();
                chain.reverse();
                results.push(chain);
            } else {
                results.push(vec![target.to_string()]);
            }
        }
    }
    results.sort();
    results.dedup();
    results.truncate(max_chains);
    results
}

/// Assert that at least one enumerated chain for `target` matches the
/// given expected sequence end-to-end.
#[track_caller]
pub fn assert_chain_contains(ws: &Workspace, target: &str, expected: &[&str]) {
    let chains = enumerate_chains(ws, target, 64);
    let found = chains
        .iter()
        .any(|c| c.iter().map(|s| s.as_str()).collect::<Vec<_>>() == expected);
    assert!(
        found,
        "expected chain {expected:?} reaching `{target}`, got:\n{:#?}",
        chains
    );
}

/// Assert that SOME chain reaches `target` from a root — i.e. not just
/// the single-element chain. Useful for tests that don't want to pin the
/// exact intermediate path.
#[track_caller]
pub fn assert_multi_step_chain_reaches(ws: &Workspace, target: &str) {
    let chains = enumerate_chains(ws, target, 64);
    let has_multi = chains.iter().any(|c| c.len() >= 2);
    assert!(
        has_multi,
        "expected at least one multi-step chain reaching `{target}`, got:\n{:#?}",
        chains
    );
}

/// Assert that a chain starting at `entry` reaches `target` (possibly
/// through any number of intermediate hops).
#[track_caller]
pub fn assert_chain_from_to(ws: &Workspace, entry: &str, target: &str) {
    let chains = enumerate_chains(ws, target, 64);
    let ok = chains.iter().any(|c| {
        c.first().map(|s| s.as_str()) == Some(entry) && c.last().map(|s| s.as_str()) == Some(target)
    });
    assert!(
        ok,
        "expected a chain from `{entry}` to `{target}`, got:\n{:#?}",
        chains
    );
}

// ---------------------------------------------------------------------------
// Inspect filter bundle — mirrors the CLI's `InspectFilters`.
// ---------------------------------------------------------------------------

/// Replica of the CLI's `InspectFilters` so per-language test suites
/// can assert on the same filter contract the binary honors.
#[derive(Copy, Clone, Default)]
pub struct InspectFilters<'a> {
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub file: Option<&'a str>,
    pub in_fn: Option<&'a str>,
}

/// Case-insensitive word-boundary match. See CLI's `name_token_match`.
pub fn name_token_match(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle_lc = needle.to_lowercase();
    let bytes = haystack.as_bytes();
    let n = bytes.len();
    let nl = needle_lc.len();
    if nl > n {
        return false;
    }
    let is_boundary = |i: usize| -> bool {
        if i == 0 {
            return true;
        }
        if !haystack.is_char_boundary(i) {
            return false;
        }
        let prev = bytes[i - 1];
        let cur = bytes[i];
        if !prev.is_ascii_alphanumeric() {
            return true;
        }
        let prev_lower = prev.is_ascii_lowercase() || prev.is_ascii_digit();
        let cur_upper = cur.is_ascii_uppercase();
        prev_lower && cur_upper
    };
    for i in 0..=(n - nl) {
        if !is_boundary(i) {
            continue;
        }
        if !haystack.is_char_boundary(i + nl) {
            continue;
        }
        if haystack[i..i + nl].eq_ignore_ascii_case(&needle_lc) {
            return true;
        }
    }
    false
}

/// Mirrors the CLI's filter semantics. Single filter → anywhere in the
/// flow. Both filters → hit must be an endpoint AND the other is
/// reachable. See CLI `chain_matches_filters` for the full rationale.
pub fn chain_matches_filters(
    _chain: &[String],
    hit_text: Option<&str>,
    reachable: &[String],
    filters: InspectFilters<'_>,
) -> bool {
    let hit_matches = |needle: &str| -> bool { hit_text.is_some_and(|t| name_token_match(t, needle)) };
    let reachable_matches = |needle: &str| -> bool { reachable.iter().any(|s| name_token_match(s, needle)) };
    let anywhere = |needle: &str| -> bool { hit_matches(needle) || reachable_matches(needle) };
    match (filters.from, filters.to) {
        (None, None) => true,
        (Some(from), None) => anywhere(from),
        (None, Some(to)) => anywhere(to),
        (Some(from), Some(to)) => {
            let hit_from = hit_matches(from);
            let hit_to = hit_matches(to);
            if !hit_from && !hit_to {
                return false;
            }
            if hit_from && hit_to {
                return true;
            }
            let other = if hit_from { to } else { from };
            anywhere(other)
        }
    }
}

/// Names the rendered flow touches — mirrors the CLI's
/// `flow_reachable_names`. Used by assert helpers to reason about what
/// `--from`/`--to` will actually see for a given chain.
pub fn flow_reachable_names(ws: &Workspace, extended_chain: &[String]) -> Vec<String> {
    let global = ws.db().global_index();
    let mut out: Vec<String> = Vec::new();
    for hop in extended_chain {
        out.push(hop.clone());
        let Some(d) = global
            .find_by_name(hop)
            .iter()
            .find_map(|s| global.decl_of(*s).cloned())
        else {
            continue;
        };
        let mut callees: Vec<String> = Vec::new();
        collect_callees_events(&d.flow_events, &mut callees);
        for callee in callees {
            out.push(callee.clone());
            let short = bonsai_lang_api::kit::short_name_of(&callee).to_string();
            if short != callee {
                out.push(short);
            }
        }
    }
    out
}

/// Collect the downstream closure of `target` — every callee (user +
/// external) reachable by recursing through user-defined callees.
pub fn downstream_callees_set(
    ws: &Workspace,
    target: &str,
    max_depth: usize,
    max_funcs: usize,
) -> Vec<String> {
    let global = ws.db().global_index();
    let mut visited: ahash::AHashSet<String> = ahash::AHashSet::new();
    visited.insert(target.to_string());
    let mut out: Vec<String> = Vec::new();
    fn recurse(
        global: &bonsai_index::GlobalIndex,
        name: &str,
        depth: usize,
        max_depth: usize,
        max_funcs: usize,
        visited: &mut ahash::AHashSet<String>,
        out: &mut Vec<String>,
    ) {
        if depth >= max_depth || out.len() >= max_funcs {
            return;
        }
        let Some(d) = global
            .find_by_name(name)
            .iter()
            .find_map(|s| global.decl_of(*s).cloned())
        else {
            return;
        };
        let mut callees: Vec<String> = Vec::new();
        collect_callees_events(&d.flow_events, &mut callees);
        for callee in callees {
            let short = bonsai_lang_api::kit::short_name_of(&callee).to_string();
            if visited.contains(&short) {
                continue;
            }
            visited.insert(short.clone());
            out.push(short.clone());
            if out.len() >= max_funcs {
                return;
            }
            let is_user = global.find_by_name(&short).iter().any(|s| {
                global.decl_of(*s).is_some_and(|dd| {
                    matches!(
                        dd.kind,
                        bonsai_lang_api::DeclKind::Function
                            | bonsai_lang_api::DeclKind::Method
                            | bonsai_lang_api::DeclKind::Constructor
                    )
                })
            });
            if is_user {
                recurse(global, &short, depth + 1, max_depth, max_funcs, visited, out);
            }
        }
    }
    recurse(&global, target, 0, max_depth, max_funcs, &mut visited, &mut out);
    out
}

fn collect_callees_events(events: &[bonsai_lang_api::FlowEvent], out: &mut Vec<String>) {
    for ev in events {
        match ev {
            bonsai_lang_api::FlowEvent::Call {
                name, receiver, args, ..
            } => {
                out.push(name.clone());
                if receiver.is_some() {
                    out.extend(
                        args.iter()
                            .map(|arg| short_tail(arg.value_text.trim()).to_string()),
                    );
                }
            }
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_callees_events(then_events, out);
                collect_callees_events(else_events, out);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. } => collect_callees_events(body, out),
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_callees_events(body, out);
                collect_callees_events(catch_events, out);
                collect_callees_events(finally_events, out);
            }
            _ => {}
        }
    }
}

/// Build the extended chain + reachable name-set for a given `target`.
/// Mirrors how the CLI prepares each chain for the filter: raw chain +
/// downstream user-defined callees of the target, then flatten to the
/// reachable names the filter matches against.
fn extended_reachable(ws: &Workspace, target: &str, chain: &[String]) -> Vec<String> {
    let downstream = downstream_callees_set(ws, target, 6, 12);
    let mut extended = chain.to_vec();
    for d in &downstream {
        if !extended.contains(d) {
            extended.push(d.clone());
        }
    }
    flow_reachable_names(ws, &extended)
}

/// Assert that at least one chain for `target` survives `filters`.
/// `hit_text` is the sink/match text the CLI passes through (for
/// decl hits it equals the decl name; for call/string hits it's the
/// hit's verbatim text).
#[track_caller]
pub fn assert_filters_keep(ws: &Workspace, target: &str, hit_text: &str, filters: InspectFilters<'_>) {
    let chains = enumerate_chains(ws, target, 64);
    let kept: Vec<&Vec<String>> = chains
        .iter()
        .filter(|c| {
            let reachable = extended_reachable(ws, target, c);
            chain_matches_filters(c, Some(hit_text), &reachable, filters)
        })
        .collect();
    assert!(
        !kept.is_empty(),
        "filters {{from:{:?}, to:{:?}}} dropped every chain for `{target}` (hit_text `{hit_text}`); chains were:\n{:#?}",
        filters.from,
        filters.to,
        chains
    );
}

/// Negative control: assert that `filters` drops every chain for
/// `target` — i.e. no flow survives the filter.
#[track_caller]
pub fn assert_filters_drop(ws: &Workspace, target: &str, hit_text: &str, filters: InspectFilters<'_>) {
    let chains = enumerate_chains(ws, target, 64);
    let kept: Vec<&Vec<String>> = chains
        .iter()
        .filter(|c| {
            let reachable = extended_reachable(ws, target, c);
            chain_matches_filters(c, Some(hit_text), &reachable, filters)
        })
        .collect();
    assert!(
        kept.is_empty(),
        "expected filters {{from:{:?}, to:{:?}}} to drop every chain for `{target}`, but these survived:\n{:#?}",
        filters.from,
        filters.to,
        kept
    );
}

/// Pin that a function named `expected` was indexed under that exact name.
/// Would catch regressions where the name extractor picks the wrong
/// identifier (e.g. C's `UserInfo *get_user(...)` being indexed as
/// `UserInfo` because `first_identifier_like_child` swallowed the return
/// type). Every language test that defines a function should call this so
/// the extractor is pinned.
#[track_caller]
pub fn assert_function_named(ws: &Workspace, expected: &str) {
    let global = ws.db().global_index();
    let hits: Vec<String> = global
        .find_by_name(expected)
        .iter()
        .filter_map(|s| global.decl_of(*s))
        .filter(|d| {
            matches!(
                d.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
        .map(|d| d.name.clone())
        .collect();
    assert!(
        !hits.is_empty(),
        "expected a function indexed as `{expected}`, but none was found. all indexed function-like decls: {:?}",
        all_function_names(ws)
    );
}

/// Pin that `unexpected` was NOT indexed as a function-like decl. Use this
/// to hard-fail when the name extractor accidentally picks a type or other
/// non-name identifier (e.g. asserting `UserInfo` is not indexed as a
/// function when the source only uses it as a return type).
#[track_caller]
pub fn assert_no_function_named(ws: &Workspace, unexpected: &str) {
    let global = ws.db().global_index();
    let hits: Vec<String> = global
        .find_by_name(unexpected)
        .iter()
        .filter_map(|s| global.decl_of(*s))
        .filter(|d| {
            matches!(
                d.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
        .map(|d| d.name.clone())
        .collect();
    assert!(
        hits.is_empty(),
        "expected NO function indexed as `{unexpected}`, but found: {hits:?}"
    );
}

fn all_function_names(ws: &Workspace) -> Vec<String> {
    let global = ws.db().global_index();
    let mut names: Vec<String> = Vec::new();
    for file in global.all_files() {
        for d in global.decls_in(file) {
            if matches!(
                d.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                names.push(d.name.clone());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Pin the token-boundary match. Every language should support short
/// needles matching longer names at token starts: `req` matches
/// `request`, `HandleRequest`, `handle_request`. Case-insensitive.
#[track_caller]
pub fn assert_fuzzy_substring(haystack_fn: &str, needle: &str) {
    assert!(
        name_token_match(haystack_fn, needle),
        "token-boundary match pin: expected `{needle}` to match `{haystack_fn}` at a token boundary (case-insensitive)"
    );
    // Pass the haystack through both hit_text and reachable so the
    // filter's "anywhere in flow" semantic gets a chance.
    let reachable = vec![haystack_fn.to_string()];
    let filters = InspectFilters {
        from: Some(needle),
        ..Default::default()
    };
    assert!(
        chain_matches_filters(&[], Some(haystack_fn), &reachable, filters),
        "chain_matches_filters rejected `--from {needle}` against `{haystack_fn}` — token match is broken"
    );
}

/// Pin that `--from` / `--to` match against non-call node types — hits
/// that surface strings, assignments, args, imports, decorators, or refs.
/// The match happens through `hit_text`, so a hit with text `q` and
/// filter `--from q` should pass regardless of chain context.
#[track_caller]
pub fn assert_hit_text_match(hit_text: &str, needle: &str) {
    let filters = InspectFilters {
        from: Some(needle),
        ..Default::default()
    };
    assert!(
        chain_matches_filters(&[], Some(hit_text), &[], filters),
        "expected `--from {needle}` to match against hit_text `{hit_text}`"
    );
}

/// Pin `--from a --to b` against sibling flows under a common entry:
/// `entry` calls (possibly transitively through user functions) both
/// `sibling_a` and `sibling_b`, and neither sibling reaches the other
/// directly. This is the regression shape where `--from malloc --to free`
/// used to return "no matches" on C micro — the two callees live in
/// different subtrees but share `entry` as the common root.
///
/// Uses `hit_text = sibling_a` (the sink the user is "inspecting") so the
/// match space covers the hit plus the entry's downstream closure.
/// Negative: pin that `--from X --to Y` drops a hit whose rendered flow
/// does NOT connect the two needles. Used to detect regressions where a
/// loosened filter surfaces unrelated hits (vars, strings, args) that
/// happen to share an entry with a real source-to-sink pair.
#[track_caller]
pub fn assert_filter_rejects_unrelated(
    ws: &Workspace,
    containing_fn: &str,
    hit_text: &str,
    from_needle: &str,
    to_needle: &str,
) {
    let filters = InspectFilters {
        from: Some(from_needle),
        to: Some(to_needle),
        file: None,
        in_fn: None,
    };
    let chains = enumerate_chains(ws, containing_fn, 64);
    let seed: Vec<Vec<String>> = if chains.is_empty() {
        vec![vec![containing_fn.to_string()]]
    } else {
        chains
    };
    for chain in &seed {
        let reachable = extended_reachable(ws, containing_fn, chain);
        assert!(
            !chain_matches_filters(chain, Some(hit_text), &reachable, filters),
            "expected filter {{from:{from_needle}, to:{to_needle}}} to REJECT hit `{hit_text}` in `{containing_fn}` (chain {chain:?}); reachable: {reachable:?}"
        );
    }
}

#[track_caller]
pub fn assert_sibling_flow_filter_keeps(ws: &Workspace, entry: &str, sibling_a: &str, sibling_b: &str) {
    let filters = InspectFilters {
        from: Some(sibling_a),
        to: Some(sibling_b),
        file: None,
        in_fn: None,
    };
    // Mirrors the CLI: for a hit inside the entry function, the
    // seed chain is just `[entry]`. Extend with the entry's downstream
    // user-defined callees and flatten to the reachable-name set. Both
    // needles must land in that scoped set — the same scope the
    // renderer inlines.
    let chain = vec![entry.to_string()];
    let reachable = extended_reachable(ws, entry, &chain);
    assert!(
        chain_matches_filters(&chain, Some(sibling_a), &reachable, filters),
        "sibling-flow filter failed: entry=`{entry}` \
         sibling_a=`{sibling_a}` sibling_b=`{sibling_b}`. \
         Reachable names from `{entry}` = {reachable:?}"
    );
}

// ---------------------------------------------------------------------------
// Query matching (mirrors CLI `inspect --query`)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Hits {
    pub decls: Vec<String>,
    /// (enclosing_fn, callee_name)
    pub calls: Vec<(String, String)>,
    /// (enclosing_fn, assign_target)
    pub assigns: Vec<(String, String)>,
    pub strings: Vec<String>,
    pub imports: Vec<String>,
    pub decorators: Vec<String>,
    pub refs: Vec<String>,
}

impl Hits {
    pub fn has_decl(&self, name: &str) -> bool {
        self.decls.iter().any(|n| n == name)
    }
    pub fn has_call(&self, in_fn: &str, needle: &str) -> bool {
        self.calls.iter().any(|(f, c)| f == in_fn && c.contains(needle))
    }
    pub fn has_assign(&self, in_fn: &str, target: &str) -> bool {
        self.assigns.iter().any(|(f, t)| f == in_fn && t.contains(target))
    }
    pub fn has_string(&self, needle: &str) -> bool {
        self.strings.iter().any(|s| s.contains(needle))
    }
    pub fn has_import(&self, needle: &str) -> bool {
        self.imports.iter().any(|m| m.contains(needle))
    }
    pub fn has_decorator(&self, needle: &str) -> bool {
        self.decorators.iter().any(|d| d.contains(needle))
    }
}

/// Case-insensitive substring match across every fact kind, equivalent
/// to `bonsai-ninja inspect <query>`.
pub fn query_hits(ws: &Workspace, query: &str) -> Hits {
    query_hits_impl(ws, query, false)
}

/// Regex match across every fact kind, equivalent to
/// `bonsai-ninja inspect --regex <pattern>`.
pub fn query_hits_regex(ws: &Workspace, pattern: &str) -> Hits {
    query_hits_impl(ws, pattern, true)
}

fn query_hits_impl(ws: &Workspace, pattern: &str, is_regex: bool) -> Hits {
    let q_lower = pattern.to_lowercase();
    let matcher = if is_regex {
        Some(regex::Regex::new(pattern).expect("valid regex"))
    } else {
        None
    };
    let is_match = |text: &str| -> bool {
        if let Some(m) = &matcher {
            m.is_match(text)
        } else {
            text.to_lowercase().contains(&q_lower)
        }
    };

    let mut hits = Hits::default();
    let global = ws.db().global_index();
    for file in global.all_files() {
        // Imports are exact adapter-lowered compiler facts. Empty means the
        // adapter found no imports; tests must not invent a parallel parser.
        let imports = ws.db().imports_for(file);
        for i in &imports {
            // Push the matched field so `has_import(needle)` sees a
            // string containing the needle. Production browse search
            // matches across module / alias / original_name; mirror
            // that here.
            if is_match(&i.module) {
                hits.imports.push(i.module.clone());
            }
            if let Some(alias) = i.alias.as_deref() {
                if is_match(alias) {
                    hits.imports.push(alias.to_string());
                }
            }
            if let Some(original) = i.original_name.as_deref() {
                if is_match(original) {
                    hits.imports.push(original.to_string());
                }
            }
        }
        let Some(idx) = global.file_index(file) else {
            continue;
        };
        for d in &idx.defs {
            if is_match(&d.name) {
                hits.decls.push(d.name.clone());
            }
            for s in &d.params {
                if is_match(s) {
                    // Exposed separately via assigns? We treat param hits
                    // as refs for the harness — close enough for the
                    // query-kind matrix.
                    hits.refs.push(format!("{}:{}", d.name, s));
                }
            }
            walk_events_for_hits(&d.flow_events, &d.name, &is_match, &mut hits);
        }
        for r in &idx.refs {
            if is_match(&r.name) {
                match r.kind {
                    RefKind::Decorator => hits.decorators.push(r.name.clone()),
                    RefKind::Call => {
                        hits.refs.push(r.name.clone());
                    }
                    _ => hits.refs.push(r.name.clone()),
                }
            }
        }
        for s in &idx.strings {
            if is_match(&s.text) {
                hits.strings.push(s.text.clone());
            }
        }
    }
    hits
}

fn walk_events_for_hits<F: Fn(&str) -> bool>(
    events: &[FlowEvent],
    in_fn: &str,
    is_match: &F,
    hits: &mut Hits,
) {
    for e in events {
        match e {
            FlowEvent::Call { name, .. } if is_match(name) => {
                hits.calls.push((in_fn.to_string(), name.clone()));
            }
            FlowEvent::Assign {
                target, source_name, ..
            } if is_match(target) || source_name.as_deref().is_some_and(is_match) => {
                hits.assigns.push((in_fn.to_string(), target.clone()));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_events_for_hits(then_events, in_fn, is_match, hits);
                walk_events_for_hits(else_events, in_fn, is_match, hits);
            }
            FlowEvent::Loop { body, .. } => walk_events_for_hits(body, in_fn, is_match, hits),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_events_for_hits(body, in_fn, is_match, hits);
                walk_events_for_hits(catch_events, in_fn, is_match, hits);
                walk_events_for_hits(finally_events, in_fn, is_match, hits);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_events_for_hits(body, in_fn, is_match, hits);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Decl / flow inspection helpers (used by a few tests to peek at the shape
// the tracer saw without leaning on the CLI renderer)
// ---------------------------------------------------------------------------

pub fn decl_by_name(ws: &Workspace, name: &str) -> Option<Decl> {
    let global = ws.db().global_index();
    global
        .find_by_name(name)
        .iter()
        .find_map(|s| global.decl_of(*s).cloned())
        .filter(|d| {
            matches!(
                d.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
}

/// Does `fn_name`'s flow include a call whose qualified name contains
/// `needle`?
/// Assert that `fn_name`'s flow captures a call to `expected`. Used by
/// per-lang flow-comprehensive tests to pin that each syntax construct
/// (if/else body, loop body, try/catch, short-circuit, ternary, etc.)
/// produces a walkable Call event for consumers like inspect/export.
#[track_caller]
pub fn assert_calls(ws: &Workspace, fn_name: &str, expected: &[&str]) {
    for needle in expected {
        assert!(
            calls_contains(ws, fn_name, needle),
            "flow coverage: `{fn_name}` is missing expected call `{needle}`. \
             Flow events: {:#?}",
            decl_by_name(ws, fn_name).map(|d| d.flow_events)
        );
    }
}

/// Assert that `fn_name`'s flow does NOT capture a call to `unexpected`.
/// Used to pin negative invariants (e.g., nested function bodies must
/// not leak into the outer function's flow).
#[track_caller]
pub fn assert_no_call(ws: &Workspace, fn_name: &str, unexpected: &str) {
    assert!(
        !calls_contains(ws, fn_name, unexpected),
        "flow coverage: `{fn_name}` should NOT capture call `{unexpected}`, but it did. \
         Flow events: {:#?}",
        decl_by_name(ws, fn_name).map(|d| d.flow_events)
    );
}

pub fn calls_contains(ws: &Workspace, fn_name: &str, needle: &str) -> bool {
    let Some(d) = decl_by_name(ws, fn_name) else {
        return false;
    };
    let mut found = false;
    find_call_in(&d.flow_events, needle, &mut found);
    found
}

fn find_call_in(events: &[FlowEvent], needle: &str, found: &mut bool) {
    for e in events {
        if *found {
            return;
        }
        match e {
            FlowEvent::Call { name, .. } if name.contains(needle) => {
                *found = true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                find_call_in(then_events, needle, found);
                find_call_in(else_events, needle, found);
            }
            FlowEvent::Loop { body, .. } => find_call_in(body, needle, found),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                find_call_in(body, needle, found);
                find_call_in(catch_events, needle, found);
                find_call_in(finally_events, needle, found);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                find_call_in(body, needle, found);
            }
            _ => {}
        }
    }
}
