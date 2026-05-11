//! Cross-function call graph + cached summaries (spec §15, §16).
//!
//! The call graph is a directed multi-graph from `FuncId` to `FuncId`. Each
//! edge carries its precision so downstream queries can decide how much to
//! trust it. Summaries are compositional cached facts derived from a
//! function's CFG plus the summaries of every target it calls.

pub mod chains;

pub use chains::{
    downstream_funcs_set, enumerate_chains_resolved, is_precise_chain, ChainTruncation,
    ResolvedChain,
};

use ahash::{AHashMap, AHashSet};
use bonsai_common::{callable_reference_variants, short_qualified_tail, FileId, FuncId, Precision, Span, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{AliasTarget, CallArg, CallKind, Decl, DeclKind, FlowEvent};
use bonsai_resolve::{
    callee_without_call_args, collect_method_candidates_for_class, enclosing_class_for_decl,
    export_name_variants, extend_alias_targets_with_declared_types, is_super_receiver,
    module_target_matches_decl_module_path, module_target_matches_path,
    namespace_alias_target_tail, prune_receiver_type_names_for_dispatch, push_unique_func,
    push_unique_string, qualified_module_alias_call, resolve_callable_with_context, resolve_class,
    ResolveContext,
};
use serde::{Deserialize, Serialize};

/// What kind of dispatch produced a call edge. The resolver
/// classifies every edge during graph construction so downstream
/// passes can choose how much to trust each one.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Name uniquely resolved to one callee (single matching
    /// decl in the global index). Carries [`Precision::Narrowed`].
    Direct,
    /// Name resolved to multiple candidate callees (cross-class
    /// methods, overloaded names, PHP `parent::__construct`).
    /// The edge fans out to every candidate; carries
    /// [`Precision::OverApproximate`].
    Virtual,
    /// Indirect dispatch through a function pointer / dynamic
    /// `getattr` / reflection. Adapter-emitted; analyses treat
    /// these as "may call any function with matching signature."
    Indirect,
    /// The call escapes to something outside the workspace
    /// (FFI, runtime-only symbol). Recorded so caller-count
    /// summaries reflect "this many calls were unresolved" but
    /// without a concrete target.
    Unknown,
}

/// One resolved edge in the call graph: a single
/// `FuncId → FuncId` link with the kind / precision tag the
/// resolver assigned at build time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: FuncId,
    pub to: FuncId,
    pub kind: EdgeKind,
    pub precision: Precision,
}

/// Generic callgraph container — a multi-graph of `FuncId → FuncId`
/// edges with O(1) `callers_of` / `callees_of` lookups via per-node
/// adjacency vectors.
///
/// Most callers want [`ResolvedCallGraph`], which wraps this with the
/// resolver-driven build pipeline. `CallGraph` itself is exposed for
/// callers that want to build edges from a different source (HIR
/// walker, trace replay, fixture data).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
    /// `caller → indices into `edges`` where the caller is `from`.
    outgoing: AHashMap<FuncId, Vec<usize>>,
    /// `callee → indices into `edges`` where the callee is `to`.
    incoming: AHashMap<FuncId, Vec<usize>>,
}

impl CallGraph {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an edge and update both adjacency indexes.
    pub fn add_edge(&mut self, edge: CallEdge) {
        let idx = self.edges.len();
        self.outgoing.entry(edge.from).or_default().push(idx);
        self.incoming.entry(edge.to).or_default().push(idx);
        self.edges.push(edge);
    }

    /// Edges where `func` is the caller.
    pub fn callees(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> {
        self.outgoing
            .get(&func)
            .into_iter()
            .flat_map(move |ids| ids.iter().map(move |i| &self.edges[*i]))
    }

    /// Edges where `func` is the callee.
    pub fn callers(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> {
        self.incoming
            .get(&func)
            .into_iter()
            .flat_map(move |ids| ids.iter().map(move |i| &self.edges[*i]))
    }

    /// Depth-first reachability from `start`. Cycles are broken by a
    /// visited set; order is DFS pre-order and deterministic.
    pub fn reachable(&self, start: FuncId) -> Vec<FuncId> {
        let mut visited: AHashSet<FuncId> = AHashSet::new();
        let mut stack = vec![start];
        let mut order = Vec::new();
        while let Some(func) = stack.pop() {
            if !visited.insert(func) {
                continue;
            }
            order.push(func);
            if let Some(ids) = self.outgoing.get(&func) {
                // Reverse so the first listed callee is popped first
                // (stable pre-order regardless of edge insertion order).
                for &idx in ids.iter().rev() {
                    stack.push(self.edges[idx].to);
                }
            }
        }
        order
    }
}

// ---------------------------------------------------------------------------
// ResolvedCallGraph — workspace-wide, name-resolved, FuncId-keyed graph.
//
// `CallGraph` above is a generic add-edges container; `ResolvedCallGraph`
// wraps it with the build pass that walks every decl's `flow_events` and
// resolves each `Call.name` to one or more concrete `FuncId`s via the
// global index + per-file alias map. This is the spine `bonsai_inspect`
// (and the CLI's `inspect` command) walks for chain enumeration.
//
// Build is closure-based on the per-file alias map so this crate stays
// independent of `bonsai_resolve` / `bonsai_db` / `bonsai_workspace` —
// any caller (today: `bonsai_workspace::resolved_call_graph`) plugs in
// the alias source it has access to.
// ---------------------------------------------------------------------------

/// Workspace-wide, name-resolved call graph keyed on `FuncId`.
///
/// Every edge corresponds to a textual `Call.name` somewhere in a
/// function's `flow_events` that the resolver mapped to one or more
/// concrete `FuncId`s. Resolution rules:
///
/// - exactly one candidate → [`EdgeKind::Direct`] / [`Precision::Narrowed`]
/// - multiple candidates (overload / cross-class / cross-module) →
///   [`EdgeKind::Virtual`] / [`Precision::OverApproximate`]
/// - zero candidates → not recorded (the call escapes to an unknown
///   target — the caller's flow events still surface the textual call
///   site for `inspect`'s render layer)
///
/// Walking the graph by `FuncId` means name collisions can no longer
/// stitch chains across unrelated decls (the `Pool::__construct` vs
/// `CurlFactory::__construct` problem) — they are different symbols
/// and therefore different graph nodes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolvedCallGraph {
    cg: CallGraph,
}

impl ResolvedCallGraph {
    /// Build the workspace's resolved call graph from every decl's
    /// flow events. Single-pass: O(total flow events × candidates per call).
    ///
    /// `aliases_for_file` is invoked once per file to obtain the
    /// `{local_name → original_name}` alias map. Pass `|_| AHashMap::new()`
    /// when alias rewriting isn't relevant (tests, single-file fixtures).
    pub fn build_with<F>(global: &GlobalIndex, aliases_for_file: F) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
    {
        Self::build_with_paths(global, aliases_for_file, |_| None)
    }

    /// Build with an additional `path_for_file` callback. Namespace
    /// imports whose module path points at a workspace file/package can
    /// then resolve `ns.fn()` to the function declared in that module
    /// without also turning external package calls like `fmt.Println`
    /// into bare-tail matches.
    pub fn build_with_paths<F, P>(global: &GlobalIndex, aliases_for_file: F, path_for_file: P) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        P: Fn(FileId) -> Option<String>,
    {
        Self::build_with_file_info(
            global,
            aliases_for_file,
            |_| AHashMap::new(),
            path_for_file,
            |_| &[],
        )
    }

    /// Build with path and export-aliases callbacks. The aliases
    /// callback returns the language's `module_export_aliases`
    /// capability (`&[]` for languages that don't declare any). The
    /// call graph uses the slice to expand a bare alias-tail into
    /// every fully-qualified shape that resolves to the same callee
    /// (e.g. JS/TS expose `exports.<n>` and `module.exports.<n>`).
    pub fn build_with_file_info<F, T, P, L>(
        global: &GlobalIndex,
        mut aliases_for_file: F,
        mut alias_targets_for_file: T,
        path_for_file: P,
        export_aliases_for_file: L,
    ) -> Self
    where
        F: FnMut(FileId) -> AHashMap<String, String>,
        T: FnMut(FileId) -> AHashMap<String, AliasTarget>,
        P: Fn(FileId) -> Option<String>,
        L: Fn(FileId) -> &'static [&'static str],
    {
        let mut cg = CallGraph::new();
        let alias_index = WorkspaceAliasIndex::build(global);
        for file in global.all_files() {
            let aliases = aliases_for_file(file);
            let file_alias_targets = alias_targets_for_file(file);
            let export_aliases = export_aliases_for_file(file);
            for decl in global.decls_in(file) {
                if !matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    continue;
                }
                let from = FuncId::new(decl.symbol.raw());
                let alias_targets = alias_targets_for_decl(&file_alias_targets, decl);
                let local_bindings = collect_local_callable_bindings_with_alias_index(
                    &decl.flow_events,
                    global,
                    decl,
                    &alias_targets,
                    &alias_index,
                );
                add_resolved_call_edges(
                    &decl.flow_events,
                    from,
                    decl,
                    global,
                    &aliases,
                    &alias_targets,
                    &local_bindings,
                    &path_for_file,
                    export_aliases,
                    &alias_index,
                    &mut cg,
                );
            }
        }
        Self { cg }
    }

    /// All `(caller, edge)` pairs that target `func`. Exposes the edge
    /// so chain enumeration can carry precision through the walk.
    pub fn callers_of(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> + '_ {
        self.cg.callers(func)
    }

    /// All `(callee, edge)` pairs `func` invokes.
    pub fn callees_of(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> + '_ {
        self.cg.callees(func)
    }

    /// Underlying `CallGraph` — mostly an escape hatch for callers that
    /// want to use `CallGraph::reachable` or iterate every edge.
    #[must_use]
    pub fn inner(&self) -> &CallGraph {
        &self.cg
    }
}

/// Walk one decl's `flow_events` and emit a [`CallEdge`] per resolved
/// call site. Recurses through every structural variant (`Branch`,
/// `Loop`, `Try`, `Defer`, `Using`).
#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
#[allow(clippy::too_many_arguments)] // stable parameter list — recursion calls hold it stable
fn add_resolved_call_edges(
    events: &[FlowEvent],
    from: FuncId,
    caller_decl: &Decl,
    global: &GlobalIndex,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    caller_export_aliases: &[&'static str],
    alias_index: &WorkspaceAliasIndex,
    cg: &mut CallGraph,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
                span,
                args,
                ..
            } => {
                let short = short_callee(name);
                let folded_receiver = receiver_name_from_call_name(name)
                    .filter(|candidate| folded_call_name_receiver_is_instance(name, candidate));
                let semantic_receiver = receiver.as_deref().or(folded_receiver);
                let mut candidates = local_bindings
                    .get(name.as_str())
                    .or_else(|| local_bindings.get(short))
                    .copied()
                    .into_iter()
                    .collect::<Vec<_>>();
                if candidates.is_empty() {
                    candidates = collect_receiver_method_targets(
                        global,
                        caller_decl,
                        alias_targets,
                        semantic_receiver,
                        receiver_types,
                        *call_kind,
                        name,
                        *span,
                    );
                }
                if candidates.is_empty() {
                    if let Some((alias_target, alias_tail)) =
                        namespace_alias_target_tail(name, alias_targets)
                    {
                        candidates = collect_workspace_module_targets(
                            global,
                            alias_target,
                            alias_tail,
                            path_for_file,
                            caller_export_aliases,
                            caller_decl,
                            alias_targets,
                        );
                    }
                }
                let unresolved_method_receiver =
                    candidates.is_empty() && *call_kind == CallKind::Method && semantic_receiver.is_some();
                if candidates.is_empty() {
                    candidates = collect_callable_targets_with_context_and_aliases(
                        global,
                        name,
                        caller_decl,
                        alias_targets,
                    );
                }
                if candidates.is_empty() {
                    if let Some((alias_target, alias_tail)) = qualified_alias_target_tail(name, aliases) {
                        candidates = collect_workspace_module_targets(
                            global,
                            alias_target,
                            alias_tail,
                            path_for_file,
                            caller_export_aliases,
                            caller_decl,
                            alias_targets,
                        );
                    }
                }
                if candidates.is_empty() && !unresolved_method_receiver {
                    // Bare-name fallback: try the short tail (and the
                    // alias-rewrite of it) BEFORE the colon-remote /
                    // module-alias bail-out. Erlang `module:function`
                    // and Elixir `Module.function` calls don't carry
                    // an `import` directive — the short tail is the
                    // only way to find the workspace decl. Visibility
                    // narrowing in `resolve_callable_with_context`
                    // still gates the candidate, so this doesn't
                    // leak unrelated bare-name matches.
                    //
                    // For Rust-style `Type::method` qualified calls,
                    // allow the bare-tail fallback ONLY when the
                    // qualifier (`Type`) resolves through the
                    // workspace's alias_targets to an in-workspace
                    // class / module. External types
                    // (`Command::new` → `std::process::Command`)
                    // would otherwise collapse onto a user-defined
                    // `Repository::new` that shares the bare suffix,
                    // fabricating cross-call edges. Module-alias
                    // calls like `store::persist` (where `store`
                    // aliases the workspace `storage` module) still
                    // get the short fallback.
                    let qualified_owner_in_workspace = if let Some(idx) = name.find("::") {
                        let qualifier = &name[..idx];
                        let qualifier_resolves = alias_targets
                            .get(qualifier)
                            .map(|t| match t {
                                AliasTarget::Namespace { module } => is_workspace_alias_target(alias_index, module),
                                AliasTarget::Member { module, member } => {
                                    // For Member-form aliases the local
                                    // name typically rebinds to
                                    // `module::member` (e.g.
                                    // `use crate::storage as store` →
                                    // store → Member { module="crate",
                                    // member="storage" }). Honour both
                                    // segments so `store::persist`
                                    // resolves through the workspace.
                                    is_workspace_alias_target(alias_index, module)
                                        || is_workspace_alias_target(alias_index, member)
                                }
                                AliasTarget::Type { .. } => true,
                            })
                            .unwrap_or(false);
                        qualifier_resolves
                    } else {
                        // No `::` — receiver / dotted form. Existing
                        // behaviour applies.
                        true
                    };
                    if qualified_owner_in_workspace {
                        let resolved_name = aliases.get(short).map(String::as_str).unwrap_or(short);
                        if resolved_name != name.as_str() {
                            candidates = collect_callable_targets_with_context_and_aliases(
                                global,
                                resolved_name,
                                caller_decl,
                                alias_targets,
                            );
                        }
                    }
                    if candidates.is_empty()
                        && (colon_remote_call(name) || qualified_module_alias_call(name, aliases))
                    {
                        continue;
                    }
                }
                if !candidates.is_empty() {
                    // No fan-out cap. Caps are heuristics, and per
                    // docs/contributing/design-patterns.mdx::Semantic Resolution
                    // Always the engine resolves callees by semantic
                    // identity (Visibility, module_path, receiver
                    // type, alias map). When that pipeline still
                    // produces many candidates, the workspace
                    // genuinely has that many — a cap would silently
                    // drop edges that downstream passes need. If
                    // fan-out is still too wide for a particular
                    // language, the right fix is enriching adapter
                    // facts (typed receivers, accurate module
                    // boundaries) until the resolver narrows
                    // semantically.
                    let (kind, precision) = if candidates.len() == 1 {
                        (EdgeKind::Direct, Precision::Narrowed)
                    } else {
                        (EdgeKind::Virtual, Precision::OverApproximate)
                    };
                    for to in candidates {
                        cg.add_edge(CallEdge {
                            from,
                            to,
                            kind,
                            precision,
                        });
                    }
                }
                add_callback_arg_edges(args, from, caller_decl, global, alias_targets, local_bindings, cg);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                add_resolved_call_edges(
                    then_events,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    alias_index,
                    cg,
                );
                add_resolved_call_edges(
                    else_events,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    alias_index,
                    cg,
                );
            }
            FlowEvent::Loop { body, .. } => {
                add_resolved_call_edges(
                    body,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    alias_index,
                    cg,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                add_resolved_call_edges(
                    body,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    alias_index,
                    cg,
                );
                add_resolved_call_edges(
                    catch_events,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    alias_index,
                    cg,
                );
                add_resolved_call_edges(
                    finally_events,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    alias_index,
                    cg,
                );
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                add_resolved_call_edges(
                    body,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    alias_index,
                    cg,
                );
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn add_callback_arg_edges(
    args: &[CallArg],
    from: FuncId,
    caller_decl: &Decl,
    global: &GlobalIndex,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    cg: &mut CallGraph,
) {
    let mut seen = AHashSet::new();
    for arg in args {
        for to in resolve_callable_arg(
            global,
            alias_targets,
            local_bindings,
            &arg.value_text,
            caller_decl,
        ) {
            if !seen.insert(to) {
                continue;
            }
            cg.add_edge(CallEdge {
                from,
                to,
                kind: EdgeKind::Indirect,
                precision: Precision::OverApproximate,
            });
        }
    }
}

/// Resolve an argument expression that might be a callable reference
/// (`&fn_name`, `Module::fn`, `:method_symbol`, …) to the workspace
/// functions it could point at.
fn resolve_callable_arg(
    global: &GlobalIndex,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    raw: &str,
    caller_decl: &Decl,
) -> Vec<FuncId> {
    let variants = callable_reference_variants(raw);
    let Some(first) = variants.first() else {
        return Vec::new();
    };
    // Lambda / template literals aren't callable references that
    // resolve to a workspace function — bail before we try.
    if first.contains("=>") || first.starts_with('`') {
        return Vec::new();
    }
    for variant in &variants {
        let trimmed = variant
            .trim()
            .trim_start_matches(bonsai_common::REFERENCE_SIGILS);
        if trimmed.is_empty() {
            continue;
        }
        let short = short_callee(trimmed);
        if let Some(local) = local_bindings
            .get(trimmed)
            .or_else(|| local_bindings.get(short))
            .copied()
        {
            return vec![local];
        }
        let mut targets =
            collect_callable_targets_with_context_and_aliases(global, trimmed, caller_decl, alias_targets);
        if targets.is_empty() && short != trimmed {
            targets =
                collect_callable_targets_with_context_and_aliases(global, short, caller_decl, alias_targets);
        }
        if !targets.is_empty() {
            return targets;
        }
    }
    Vec::new()
}

/// Build a `local_name → FuncId` map for callable assignments
/// inside `caller_decl`'s body. Resolution narrows by the caller's
/// `Visibility` / `module_path` context per
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`. Without
/// this filter, two unrelated codebases that each declare a
/// `static error(...)` (hiredis vs Lua) would collide on bare name.
pub fn collect_local_callable_bindings(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
) -> AHashMap<String, FuncId> {
    let alias_targets = alias_targets_for_decl(&AHashMap::new(), caller_decl);
    collect_local_callable_bindings_with_aliases(events, global, caller_decl, &alias_targets)
}

pub fn collect_local_callable_bindings_with_aliases(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> AHashMap<String, FuncId> {
    let mut bindings = AHashMap::new();
    collect_local_callable_bindings_into(events, global, caller_decl, alias_targets, None, &mut bindings);
    bindings
}

/// Same shape as [`collect_local_callable_bindings_with_aliases`]
/// but threads a precomputed [`WorkspaceAliasIndex`] for the
/// `Type::method` short-tail gate. `build_with_file_info` calls
/// this so the index is built once per callgraph build rather
/// than once per decl. External callers stick with the public
/// non-indexed variant above; the indexed form is internal to the
/// callgraph crate.
fn collect_local_callable_bindings_with_alias_index(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: &WorkspaceAliasIndex,
) -> AHashMap<String, FuncId> {
    let mut bindings = AHashMap::new();
    collect_local_callable_bindings_into(
        events,
        global,
        caller_decl,
        alias_targets,
        Some(alias_index),
        &mut bindings,
    );
    bindings
}

fn collect_local_callable_bindings_into(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: Option<&WorkspaceAliasIndex>,
    bindings: &mut AHashMap<String, FuncId>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
                    } => {
                // Skip RHS that is itself a call — we only bind names
                // pointing at a callable (e.g. `let f = some_func`).
                if source_call.is_some() {
                    continue;
                }
                if let Some(sym) = source_name
                    .as_deref()
                    .and_then(|name| {
                        resolve_callable_symbol_with_alias_index(
                            global,
                            name,
                            caller_decl,
                            alias_targets,
                            alias_index,
                        )
                    })
                    .or_else(|| {
                        source_names.iter().find_map(|name| {
                            resolve_callable_symbol_with_alias_index(
                                global,
                                name,
                                caller_decl,
                                alias_targets,
                                alias_index,
                            )
                        })
                    })
                {
                    bindings.insert(target.clone(), sym);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_local_callable_bindings_into(
                    then_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    bindings,
                );
                collect_local_callable_bindings_into(
                    else_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    bindings,
                );
            }
            FlowEvent::Loop { body, .. } => {
                collect_local_callable_bindings_into(body, global, caller_decl, alias_targets, alias_index, bindings);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_local_callable_bindings_into(body, global, caller_decl, alias_targets, alias_index, bindings);
                collect_local_callable_bindings_into(
                    catch_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    bindings,
                );
                collect_local_callable_bindings_into(
                    finally_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    bindings,
                );
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_local_callable_bindings_into(body, global, caller_decl, alias_targets, alias_index, bindings);
            }
            _ => {}
        }
    }
}

/// Resolve a local-binding RHS like `let f = some_func;` to a
/// callable [`FuncId`] in the caller's scope.
///
/// Per `docs/contributing/design-patterns.mdx::Semantic Resolution Always`,
/// resolution narrows by the caller's `Visibility` / `module_path`
/// context. This is what prevents the canonical cross-TU
/// regression: hiredis's `static error()` and Lua's
/// `static error()` no longer collide on bare name because each
/// is `Visibility::Private` and the resolver filters by
/// `decl_file == caller_file`. Returns `None` (sound under-
/// approximation) when no candidate matches the caller's scope.
fn resolve_callable_symbol(
    global: &GlobalIndex,
    raw: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Option<FuncId> {
    resolve_callable_symbol_with_alias_index(global, raw, caller_decl, alias_targets, None)
}

/// Same as [`resolve_callable_symbol`] but threads a precomputed
/// [`WorkspaceAliasIndex`] for the `Type::method` short-tail gate.
/// `build_with_file_info` builds the index once at the start of the
/// callgraph pass and passes `Some(&idx)`; standalone callers (legacy
/// taint engine, individual `dump-resolve` lookups) pass `None` and
/// pay the O(decls) scan that the helper falls back to.
fn resolve_callable_symbol_with_alias_index(
    global: &GlobalIndex,
    raw: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: Option<&WorkspaceAliasIndex>,
) -> Option<FuncId> {
    let variants = callable_reference_variants(raw);
    if variants.is_empty() {
        return None;
    }
    let caller_file = caller_decl_file(global, caller_decl)?;
    let caller_module = caller_decl.module_path.clone();
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(alias_targets);
    let owned_index: Option<WorkspaceAliasIndex> = if alias_index.is_none() {
        Some(WorkspaceAliasIndex::build(global))
    } else {
        None
    };
    let alias_index: &WorkspaceAliasIndex = alias_index
        .or(owned_index.as_ref())
        .expect("alias_index built above when not supplied");
    for variant in variants {
        let trimmed = variant
            .trim()
            .trim_start_matches(bonsai_common::REFERENCE_SIGILS);
        if trimmed.is_empty() {
            continue;
        }
        let short = short_callee(trimmed);
        // Try the qualified variant first. For Rust-style
        // `Type::method` qualified calls, allow the bare-tail
        // fallback ONLY when the qualifier resolves to an in-
        // workspace alias target; otherwise external types like
        // `Command::new` (`Command` aliases `std::process::Command`)
        // would collapse onto a user-defined `Repository::new`
        // that shares the bare suffix `new`.
        let allow_short_fallback = if let Some(idx) = trimmed.find("::") {
            let qualifier = &trimmed[..idx];
            alias_targets
                .get(qualifier)
                .map(|t| match t {
                    AliasTarget::Namespace { module } => is_workspace_alias_target(alias_index, module),
                    AliasTarget::Member { module, member } => {
                        is_workspace_alias_target(alias_index, module)
                            || is_workspace_alias_target(alias_index, member)
                    }
                    AliasTarget::Type { .. } => true,
                })
                .unwrap_or(false)
        } else {
            true
        };
        let candidates: &[&str] = if allow_short_fallback {
            &[trimmed, short]
        } else {
            &[trimmed]
        };
        for candidate in candidates {
            let resolved = resolve_callable_with_context(global, candidate, &ctx);
            if let [func] = resolved.as_slice() {
                return Some(*func);
            }
        }
    }
    None
}

/// Resolve a typed-receiver method call (`obj.method(...)`) to every
/// candidate method in the workspace. The receiver's type is read
/// from `caller_decl.type_aliases`; class lookup goes through the
/// semantic-identity resolver so visibility and module-path filters
/// apply. Empty when the caller's declaring file or the receiver
/// type is unavailable — sound under-approximation per
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
fn collect_receiver_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: CallKind,
    call_name: &str,
    call_span: Span,
) -> Vec<FuncId> {
    if call_kind != CallKind::Method {
        return Vec::new();
    }
    let Some(receiver) = receiver else {
        return Vec::new();
    };
    let method_name = short_callee(call_name);
    if is_super_receiver(receiver) {
        return collect_super_method_targets(global, caller_decl, alias_targets, method_name);
    }
    let mut receiver_type_names = receiver_types.to_vec();
    if receiver_type_names.is_empty() {
        receiver_type_names = receiver_type_names_for_expr(caller_decl, alias_targets, receiver);
        for type_name in assigned_receiver_type_names(
            global,
            caller_decl,
            alias_targets,
            receiver,
            Some(call_span),
        ) {
            push_unique_string(&mut receiver_type_names, type_name);
        }
        for type_name in receiver_call_return_type_names(
            global,
            caller_decl,
            alias_targets,
            receiver,
            Some(call_span),
        ) {
            push_unique_string(&mut receiver_type_names, type_name);
        }
    }
    if receiver_type_names.is_empty() {
        return Vec::new();
    }
    let caller_module = caller_decl.module_path.clone();
    // Without a known caller file we have nothing to narrow on, so
    // return empty rather than fan out to every workspace-wide
    // bare-name match.
    let (class_candidates, ctx): (Vec<SymbolId>, Option<ResolveContext<'_>>) =
        if let Some(caller_file) = caller_decl_file(global, caller_decl) {
            let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(alias_targets);
            receiver_type_names = prune_receiver_type_names_for_dispatch(receiver_type_names, global, &ctx);
            let mut seen = AHashSet::new();
            let mut classes = Vec::new();
            for receiver_type in receiver_type_names {
                for class_sym in resolve_class(global, &receiver_type, &ctx) {
                    if seen.insert(class_sym) {
                        classes.push(class_sym);
                    }
                }
            }
            (classes, Some(ctx))
        } else {
            (Vec::new(), None)
        };
    let Some(ctx) = ctx.as_ref() else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for class_sym in class_candidates {
        collect_method_candidates_for_class(global, class_sym, method_name, ctx, &mut seen, &mut targets);
    }
    targets
}

fn collect_super_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    method_name: &str,
) -> Vec<FuncId> {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let Some(class_decl) = enclosing_class_for_decl(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for base in &class_decl.bases {
        for class_sym in resolve_class(global, base, &ctx) {
            collect_method_candidates_for_class(
                global,
                class_sym,
                method_name,
                &ctx,
                &mut seen,
                &mut targets,
            );
        }
    }
    targets
}


fn receiver_call_return_type_names(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: &str,
    _call_span: Option<Span>,
) -> Vec<String> {
    let Some(inner_call) = receiver_inner_call_name(receiver) else {
        return Vec::new();
    };
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut funcs = Vec::new();
    let mut late_static_type: Option<String> = None;
    if let Some(receiver_name) = receiver_name_from_call_name(&inner_call) {
        let receiver_type = short_callee(receiver_name).trim_end_matches("()");
        if !receiver_type.is_empty() {
            late_static_type = Some(receiver_type.to_string());
        }
        let method_name = callee_without_call_args(short_callee(&inner_call));
        if !receiver_type.is_empty() && !resolve_class(global, receiver_type, &ctx).is_empty() {
            let mut seen = AHashSet::new();
            for class_sym in resolve_class(global, receiver_type, &ctx) {
                collect_method_candidates_for_class(
                    global,
                    class_sym,
                    method_name,
                    &ctx,
                    &mut seen,
                    &mut funcs,
                );
            }
        }
    } else {
        for func in resolve_callable_with_context(global, &inner_call, &ctx) {
            push_unique_func(&mut funcs, func);
        }
    }
    let mut out = Vec::new();
    for func in funcs {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        collect_constructed_return_type_names(
            global,
            caller_decl,
            alias_targets,
            decl,
            late_static_type.as_deref(),
            &mut out,
        );
    }
    out
}

/// Extract the inner call name from a `Foo.bar(args)`-shaped
/// receiver, returning `Foo.bar`. Mirrors
/// `bonsai_taint::inter::receiver_inner_call_name` shape-for-shape;
/// the only difference is the normalisation helper — see
/// [`normalize_receiver_alias_text`] for why callgraph's variant is
/// the structured-input simpler form.
fn receiver_inner_call_name(receiver: &str) -> Option<String> {
    let receiver = normalize_receiver_alias_text(receiver);
    let receiver = receiver.trim();
    if !receiver.ends_with(')') {
        return None;
    }
    let open = receiver.find('(')?;
    let callee = receiver[..open].trim();
    if callee.is_empty() || callee.contains('"') || callee.contains('\'') || callee.contains('`') {
        return None;
    }
    Some(callee.to_string())
}


fn receiver_name_from_call_name(call_name: &str) -> Option<&str> {
    call_name
        .rsplit_once('.')
        .or_else(|| call_name.rsplit_once("::"))
        .or_else(|| call_name.rsplit_once("->"))
        .map(|(receiver, _)| receiver.trim())
        .filter(|receiver| !receiver.is_empty())
}

fn folded_call_name_receiver_is_instance(call_name: &str, receiver: &str) -> bool {
    let receiver = normalize_receiver_alias_text(receiver);
    let bare = short_callee(&receiver);
    matches!(bare, "super" | "parent" | "base")
        || (!call_name.contains("::") && matches!(bare, "self" | "this"))
        || (!call_name.contains("::")
            && (receiver.starts_with("self.")
                || receiver.starts_with("this.")
                || receiver.starts_with("super.")
                || receiver.starts_with("parent.")
                || receiver.starts_with("base.")))
}

fn collect_constructed_return_type_names(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    decl: &Decl,
    late_static_type: Option<&str>,
    out: &mut Vec<String>,
) {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return;
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    collect_constructed_return_type_names_from_events(
        global,
        &ctx,
        decl,
        late_static_type,
        &decl.flow_events,
        out,
    );
}

fn collect_constructed_return_type_names_from_events(
    global: &GlobalIndex,
    ctx: &ResolveContext<'_>,
    decl: &Decl,
    late_static_type: Option<&str>,
    events: &[FlowEvent],
    out: &mut Vec<String>,
) {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text: Some(value_text),
                ..
            } => {
                if let Some(type_name) = constructed_return_type_from_text(global, ctx, value_text) {
                    push_unique_string(out, type_name);
                } else if bonsai_common::value_text_returns_self_constructor(value_text) {
                    if let Some(type_name) = late_static_type {
                        push_unique_string(out, type_name.to_string());
                    } else if let Some(parent) = decl.parent.and_then(|symbol| global.decl_of(symbol)) {
                        push_unique_string(out, parent.name.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_constructed_return_type_names_from_events(global, ctx, decl, late_static_type, then_events, out);
                collect_constructed_return_type_names_from_events(global, ctx, decl, late_static_type, else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_constructed_return_type_names_from_events(global, ctx, decl, late_static_type, body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_constructed_return_type_names_from_events(global, ctx, decl, late_static_type, body, out);
                collect_constructed_return_type_names_from_events(global, ctx, decl, late_static_type, catch_events, out);
                collect_constructed_return_type_names_from_events(global, ctx, decl, late_static_type, finally_events, out);
            }
            _ => {}
        }
    }
}

fn constructed_return_type_from_text(
    global: &GlobalIndex,
    ctx: &ResolveContext<'_>,
    value_text: &str,
) -> Option<String> {
    let mut text = value_text.trim();
    for keyword in bonsai_common::VALUE_TEXT_LEADING_KEYWORDS {
        text = text.strip_prefix(*keyword).unwrap_or(text).trim();
    }
    let candidate = text
        .split(['(', '{', '[', ' ', '\t', '\r', '\n'])
        .next()
        .unwrap_or(text)
        .trim();
    if candidate.is_empty()
        || !short_callee(candidate)
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
    {
        return None;
    }
    (!resolve_class(global, candidate, ctx).is_empty()).then(|| short_callee(candidate).to_string())
}






fn type_alias_for_receiver<'a>(decl: &'a Decl, receiver: &str) -> Option<&'a str> {
    let normalized = normalize_receiver_alias_text(receiver);
    let tail = short_callee(&normalized);
    let self_tail = format!("self.{tail}");
    let this_tail = format!("this.{tail}");
    decl.type_aliases
        .iter()
        .find(|alias| {
            alias.name == receiver
                || alias.name == normalized
                || alias.name == tail
                || alias.name == self_tail
                || alias.name == this_tail
        })
        .map(|alias| alias.type_name.as_str())
}

fn receiver_type_names_for_expr(
    decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(type_name) = type_alias_for_receiver(decl, receiver) {
        push_unique_string(&mut out, type_name.to_string());
    }
    let normalized = normalize_receiver_alias_text(receiver);
    let tail = short_callee(&normalized);
    let self_tail = format!("self.{tail}");
    let this_tail = format!("this.{tail}");
    for key in [
        receiver,
        normalized.as_str(),
        tail,
        self_tail.as_str(),
        this_tail.as_str(),
    ] {
        if let Some(AliasTarget::Type { type_name }) = alias_targets.get(key) {
            push_unique_string(&mut out, type_name.clone());
        }
    }
    out
}

fn assigned_receiver_type_names(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: &str,
    call_span: Option<Span>,
) -> Vec<String> {
    let receiver = normalize_receiver_alias_text(receiver);
    let mut out = Vec::new();
    collect_assigned_receiver_type_names(
        global,
        caller_decl,
        alias_targets,
        &caller_decl.flow_events,
        &receiver,
        call_span,
        &mut out,
    );
    out
}

fn collect_assigned_receiver_type_names(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    events: &[FlowEvent],
    receiver: &str,
    call_span: Option<Span>,
    out: &mut Vec<String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_name,
                source_names,
                span,
                ..
                    } => {
                if call_span.is_some_and(|call_span| span.start > call_span.start) {
                    continue;
                }
                if normalize_receiver_alias_text(target) != receiver {
                    continue;
                }
                if let Some(source_call) = source_call {
                    for type_name in receiver_call_return_type_names(
                        global,
                        caller_decl,
                        alias_targets,
                        &format!("{source_call}()"),
                        Some(*span),
                    ) {
                        push_unique_string(out, type_name);
                    }
                }
                for candidate in source_call
                    .iter()
                    .chain(source_name.iter())
                    .chain(source_names.iter())
                {
                    let candidate = normalize_receiver_alias_text(candidate);
                    if call_name_looks_type_constructor(&candidate)
                        && class_like_constructor_call(global, caller_decl, alias_targets, &candidate)
                    {
                        push_unique_string(out, short_callee(&candidate).to_string());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    then_events,
                    receiver,
                    call_span,
                    out,
                );
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    else_events,
                    receiver,
                    call_span,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    body,
                    receiver,
                    call_span,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    body,
                    receiver,
                    call_span,
                    out,
                );
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    catch_events,
                    receiver,
                    call_span,
                    out,
                );
                collect_assigned_receiver_type_names(
                    global,
                    caller_decl,
                    alias_targets,
                    finally_events,
                    receiver,
                    call_span,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn call_name_looks_type_constructor(name: &str) -> bool {
    short_callee(name)
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
}

fn class_like_constructor_call(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    callee_name: &str,
) -> bool {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return false;
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    if !resolve_class(global, callee_name, &ctx).is_empty() {
        return true;
    }
    let tail = short_callee(callee_name);
    tail != callee_name && !resolve_class(global, tail, &ctx).is_empty()
}

fn alias_targets_for_decl(
    file_alias_targets: &AHashMap<String, AliasTarget>,
    decl: &Decl,
) -> AHashMap<String, AliasTarget> {
    let mut map = file_alias_targets.clone();
    extend_alias_targets_with_declared_types(&mut map, &decl.type_aliases);
    bonsai_lang_api::extend_alias_map_with_flow_events(&mut map, &decl.flow_events);
    map
}


/// Receiver-alias normalisation used at callgraph build time.
/// Strips outer parentheses (`(repo).run()` → `repo.run()`),
/// reference sigils (`&str`, `*const T`), and rewrites C/C++/PHP
/// `->` member access to `.` form.
///
/// Intentionally simpler than `bonsai_taint::text::normalise_qualified_text`
/// — the taint engine's variant additionally handles bracket-depth-
/// aware string-literal masking and subscript rewriting (`obj['k']`
/// → `obj.k`) because it normalises arbitrary FlowEvent expression
/// texts. Callgraph's input is the structured `FlowEvent::Call.callee`
/// or `Call.receiver` field, which the adapter has already split out
/// of any subscript expression — so the simpler helper covers every
/// real shape that reaches edge construction.
fn normalize_receiver_alias_text(receiver: &str) -> String {
    let mut text = receiver.trim();
    while text.starts_with('(') && text.ends_with(')') && text.len() > 1 {
        text = text[1..text.len() - 1].trim();
    }
    text.trim_start_matches(bonsai_common::REFERENCE_SIGILS)
        .replace("->", ".")
        .trim()
        .trim_matches('.')
        .to_string()
}

fn caller_decl_file(global: &GlobalIndex, caller_decl: &Decl) -> Option<FileId> {
    global.declaring_file(caller_decl.symbol)
}

fn colon_remote_call(name: &str) -> bool {
    name.contains(':') && !name.contains("::")
}


fn qualified_alias_target_tail<'a>(
    name: &'a str,
    aliases: &'a AHashMap<String, String>,
) -> Option<(&'a str, &'a str)> {
    let (head, tail) = name.split_once(&['.', ':'][..])?;
    aliases.get(head).map(String::as_str).map(|target| (target, tail))
}


#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
/// Resolve a `module.fn` call where `module` is a local alias for a
/// workspace file or package. Returns every workspace function that
/// (a) has a name matching `alias_tail` (or one of the language's
/// export-alias prefixes), and (b) lives in a file whose path
/// matches the alias target.
fn collect_workspace_module_targets(
    global: &GlobalIndex,
    alias_target: &str,
    alias_tail: &str,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    caller_export_aliases: &[&'static str],
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<FuncId> {
    if alias_target.is_empty() || alias_tail.is_empty() {
        return Vec::new();
    }
    let mut seen_spans = AHashSet::new();
    let mut targets = Vec::new();
    for func in export_name_variants(alias_tail, caller_export_aliases)
        .into_iter()
        .flat_map(|name| {
            collect_callable_targets_with_context_and_aliases(global, &name, caller_decl, alias_targets)
        })
    {
        let sym = SymbolId::new(func.raw());
        let Some(file) = global.declaring_file(sym) else {
            continue;
        };
        let Some(decl) = global.decl_of(sym) else {
            continue;
        };
        // Module-namespace match: prefer the decl's canonical
        // `module_path` (the adapter's semantic-identity fact) before
        // falling back to file-path heuristics. Required for
        // languages whose modules and files use different
        // conventions — Elixir's `MyApp.AuthService` vs.
        // `my_app/auth_service.ex` is the canonical example: the
        // file-path match would silently miss the cross-module
        // edge. The semantic match is always sufficient when
        // adapters populate `module_path`.
        let semantic_match = module_target_matches_decl_module_path(alias_target, &decl.module_path);
        let in_target_file = semantic_match
            || path_for_file(file).is_some_and(|path| module_target_matches_path(alias_target, &path));
        if !in_target_file {
            continue;
        }
        if seen_spans.insert((file, decl.span.start, decl.span.end)) {
            targets.push(func);
        }
    }
    targets
}

// `module_target_matches_decl_module_path` lives in
// `bonsai_resolve` and is re-used here so callgraph and taint
// share the same canonical match. See `bonsai_resolve` for the
// suffix-aware semantic.


// Path / module-shape helpers live in `bonsai_resolve` so the
// callgraph and taint engine share one source of truth.

/// Resolve `name` against the global index and return every matching
/// callable (function, method, constructor) as a [`FuncId`]. Empty
/// when the name doesn't match any declared function in the workspace.
///
/// **Display-only.** Bypasses caller `Visibility` / `module_path`
/// narrowing and may return cross-TU collisions
/// (`docs/contributing/design-patterns.mdx::Semantic Resolution Always`). Reserve
/// for browse/dump/inspect display paths that already enumerate
/// every name match by design. Graph-construction paths must use
/// [`collect_callable_targets_with_context`].
pub fn collect_callable_targets(global: &GlobalIndex, name: &str) -> Vec<FuncId> {
    let mut targets = collect_callable_targets_exact(global, name);
    // Ruby method names ending in `!` are aliases for the bare-name
    // version on the same receiver; retry without the suffix.
    if targets.is_empty() {
        if let Some(no_bang) = name.strip_suffix('!') {
            targets = collect_callable_targets_exact(global, no_bang);
        }
    }
    targets
}

/// Caller-context-aware version of [`collect_callable_targets`]. Use
/// this from any path that builds graph edges, taint edges, or
/// findings. Returns empty when caller context is unavailable so the
/// caller can treat the call as external — see
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
pub fn collect_callable_targets_with_context(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
) -> Vec<FuncId> {
    collect_callable_targets_with_context_and_aliases(global, name, caller_decl, &AHashMap::new())
}

pub fn collect_callable_targets_with_context_and_aliases(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<FuncId> {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut targets = resolve_callable_with_context(global, name, &ctx);
    if targets.is_empty() {
        if let Some(no_bang) = name.strip_suffix('!') {
            targets = resolve_callable_with_context(global, no_bang, &ctx);
        }
    }
    targets
}

pub fn collect_call_event_targets_with_context_and_aliases(
    global: &GlobalIndex,
    name: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: CallKind,
    call_span: Span,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    caller_export_aliases: &[&'static str],
) -> Vec<FuncId> {
    let exact_targets =
        collect_callable_targets_with_context_and_aliases(global, name, caller_decl, alias_targets);
    if !exact_targets.is_empty() {
        return exact_targets;
    }
    let folded_receiver =
        receiver_name_from_call_name(name).filter(|candidate| folded_call_name_receiver_is_instance(name, candidate));
    let semantic_receiver = receiver.or(folded_receiver);
    let mut targets = collect_receiver_method_targets(
        global,
        caller_decl,
        alias_targets,
        semantic_receiver,
        receiver_types,
        call_kind,
        name,
        call_span,
    );
    if targets.is_empty() {
        if let Some((alias_target, alias_tail)) = namespace_alias_target_tail(name, alias_targets) {
            targets = collect_workspace_module_targets(
                global,
                alias_target,
                alias_tail,
                path_for_file,
                caller_export_aliases,
                caller_decl,
                alias_targets,
            );
        }
    }
    if targets.is_empty() && !(call_kind == CallKind::Method && semantic_receiver.is_some()) {
        targets = collect_callable_targets_with_context_and_aliases(
            global,
            name,
            caller_decl,
            alias_targets,
        );
        let short = short_callee(name);
        // For Rust-style `Type::method` qualified calls, allow the
        // bare-tail fallback ONLY when the qualifier resolves to
        // an in-workspace alias. See the matching guard at the
        // build-time call site above for the full rationale.
        // The legacy taint engine still routes through this entry
        // and doesn't share the callgraph build's WorkspaceAliasIndex,
        // so we build a local one — call-frequency here is bounded
        // by the legacy engine's per-source pass.
        let local_alias_index = WorkspaceAliasIndex::build(global);
        let allow_short_fallback = if let Some(idx) = name.find("::") {
            let qualifier = &name[..idx];
            alias_targets
                .get(qualifier)
                .map(|t| match t {
                    AliasTarget::Namespace { module } => is_workspace_alias_target(&local_alias_index, module),
                    AliasTarget::Member { module, member } => {
                        is_workspace_alias_target(&local_alias_index, module)
                            || is_workspace_alias_target(&local_alias_index, member)
                    }
                    AliasTarget::Type { .. } => true,
                })
                .unwrap_or(false)
        } else {
            true
        };
        if targets.is_empty() && short != name && allow_short_fallback {
            targets = collect_callable_targets_with_context_and_aliases(
                global,
                short,
                caller_decl,
                alias_targets,
            );
        }
    }
    targets
}

fn collect_callable_targets_exact(global: &GlobalIndex, name: &str) -> Vec<FuncId> {
    global
        // CONTEXTLESS_LOOKUP_JUSTIFICATION: display-only helper for
        // callers that intentionally enumerate every matching name;
        // callgraph construction uses collect_callable_targets_with_context.
        .find_by_name(name)
        .iter()
        .filter_map(|symbol| {
            global.decl_of(*symbol).and_then(|decl| {
                if matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    Some(FuncId::new(symbol.raw()))
                } else {
                    None
                }
            })
        })
        .collect()
}

/// Tail of a qualified call name. `"a.b.c"` → `"c"`; `"std::fs::read"`
/// → `"read"`; `"a->b"` → `"b"`. A plain identifier is returned
/// unchanged. Public so the resolver and inspect filter use the same
/// short-name semantics.
#[must_use]
pub fn short_callee(name: &str) -> &str {
    short_qualified_tail(name)
}

/// Precomputed index used by [`is_workspace_alias_target`] so the
/// `Type::method` short-tail gate doesn't pay an O(decls) scan per
/// call site. The two sets are built once per callgraph build (or
/// once per `resolve_callable_symbol` call when entered standalone)
/// and trusted across every alias lookup inside that pass.
///
/// * `class_names` — every `DeclKind::Class` decl's bare name.
///   Covers `AliasTarget::Type` rebindings (`let r: Repository`)
///   and Rust-style `Foo::method` where `Foo` is a user struct.
/// * `module_canonicals` — every decl's `module_path.segments`
///   joined with both `::` and `.` separators, so alias targets
///   spelled `crate::storage`, `storage`, or `app.storage` all
///   resolve. Stored as `(canonical, leading_segment)` so the
///   suffix-match in `is_workspace_alias_target` doesn't have to
///   call `ends_with(&format!(...))` per candidate.
#[derive(Default)]
struct WorkspaceAliasIndex {
    class_names: ahash::AHashSet<String>,
    /// Pairs of (canonical_module_path, language_separator).
    /// canonical is the joined module path, separator is `::` or
    /// `.` depending on which form the adapter records.
    module_canonicals: ahash::AHashSet<String>,
}

impl WorkspaceAliasIndex {
    fn build(global: &GlobalIndex) -> Self {
        let mut class_names: ahash::AHashSet<String> = ahash::AHashSet::default();
        let mut module_canonicals: ahash::AHashSet<String> = ahash::AHashSet::default();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if matches!(decl.kind, DeclKind::Class) {
                    class_names.insert(decl.name.clone());
                }
                if !decl.module_path.is_empty() {
                    let segs = &decl.module_path.segments;
                    module_canonicals.insert(segs.join("::"));
                    module_canonicals.insert(segs.join("."));
                }
            }
        }
        Self {
            class_names,
            module_canonicals,
        }
    }

    fn contains(&self, module: &str) -> bool {
        let trimmed = module.trim();
        if trimmed.is_empty() {
            return false;
        }
        if self.class_names.contains(trimmed) {
            return true;
        }
        let stripped = trimmed
            .trim_start_matches("crate::")
            .trim_start_matches("crate.");
        if self.module_canonicals.contains(trimmed) || self.module_canonicals.contains(stripped) {
            return true;
        }
        // Suffix-match: alias targets like `app` should also hit
        // `crate::app` / `pkg.app.sub`. Iterate the precomputed
        // canonical set and check ::trimmed / .trimmed suffixes.
        // O(canonicals) but bounded by file count, not decl count,
        // and each contains-check is hash-table-fast.
        let needle_cc = format!("::{trimmed}");
        let needle_dot = format!(".{trimmed}");
        let needle_cc_stripped = format!("::{stripped}");
        let needle_dot_stripped = format!(".{stripped}");
        for canonical in &self.module_canonicals {
            if canonical.ends_with(&needle_cc)
                || canonical.ends_with(&needle_dot)
                || canonical.ends_with(&needle_cc_stripped)
                || canonical.ends_with(&needle_dot_stripped)
            {
                return true;
            }
        }
        false
    }
}

/// True when `module` names something the workspace recognises —
/// either a known module path or a declared type / class name.
/// Memoised against a precomputed [`WorkspaceAliasIndex`] so the
/// short-tail gate is O(1) per call instead of O(decls). See the
/// index's docs for the rationale.
fn is_workspace_alias_target(idx: &WorkspaceAliasIndex, module: &str) -> bool {
    idx.contains(module)
}

/// True when `call_name` resolves to `target_func` from `caller_decl`'s
/// site context. Threads alias map + local callable bindings + global
/// resolver narrowing — same shape `inspect`'s chain-edge renderer
/// uses, exposed here so `bonsai_workspace::flow_ids` can answer the
/// same question without depending on `bonsai_inspect`.
///
/// Without this, syntactic `name == target || name.ends_with(".target")`
/// quietly drops aliased import calls — `from os.path import join as j;
/// j(req)` doesn't string-match `os.path.join`, so flow-id consumers
/// undercount chains while inspect renders them.
#[must_use]
pub fn call_resolves_to_func(
    global: &GlobalIndex,
    aliases: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller_decl: &Decl,
    call_name: &str,
    target_func: FuncId,
) -> bool {
    let short = short_qualified_tail(call_name);
    if local_bindings
        .get(call_name)
        .or_else(|| local_bindings.get(short))
        .is_some_and(|func| *func == target_func)
    {
        return true;
    }
    let mut candidates =
        collect_callable_targets_with_context_and_aliases(global, call_name, caller_decl, aliases);
    if candidates.is_empty() && short != call_name {
        candidates =
            collect_callable_targets_with_context_and_aliases(global, short, caller_decl, aliases);
    }
    candidates.contains(&target_func)
}

/// Walk `events` (recursing into Branch/Loop/Try/Defer/Using) and
/// return the span of the first `Call` (or `Assign::source_call`)
/// whose name resolves to `target_func`. Returns `None` when no
/// resolvable edge exists.
///
/// `aliases` is the caller's alias map (file-level imports + decl-
/// level type aliases + flow-event-extended aliases);
/// `local_bindings` is the result of [`collect_local_callable_bindings`].
#[must_use]
pub fn find_call_span_resolved(
    events: &[FlowEvent],
    target_func: FuncId,
    target_name: &str,
    global: &GlobalIndex,
    aliases: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller_decl: &Decl,
) -> Option<Span> {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                span,
                receiver,
                args,
                ..
            } if call_event_matches_target_func(
                name,
                receiver.as_deref(),
                args,
                target_func,
                target_name,
                global,
                aliases,
                local_bindings,
                caller_decl,
            ) =>
            {
                return Some(*span);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(span) = find_call_span_resolved(
                    then_events,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                ) {
                    return Some(span);
                }
                if let Some(span) = find_call_span_resolved(
                    else_events,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                ) {
                    return Some(span);
                }
            }
            FlowEvent::Loop { body, .. } => {
                if let Some(span) = find_call_span_resolved(
                    body,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                ) {
                    return Some(span);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(span) = find_call_span_resolved(
                    body,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                )
                .or_else(|| {
                    find_call_span_resolved(
                        catch_events,
                        target_func,
                        target_name,
                        global,
                        aliases,
                        local_bindings,
                        caller_decl,
                    )
                })
                .or_else(|| {
                    find_call_span_resolved(
                        finally_events,
                        target_func,
                        target_name,
                        global,
                        aliases,
                        local_bindings,
                        caller_decl,
                    )
                }) {
                    return Some(span);
                }
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(span) = find_call_span_resolved(
                    body,
                    target_func,
                    target_name,
                    global,
                    aliases,
                    local_bindings,
                    caller_decl,
                ) {
                    return Some(span);
                }
            }
            FlowEvent::Assign {
                source_call: Some(name),
                span,
                ..
            } if call_resolves_to_func(global, aliases, local_bindings, caller_decl, name, target_func) => {
                return Some(*span);
            }
            _ => {}
        }
    }
    None
}

#[allow(clippy::too_many_arguments)] // matches the per-call narrowing primitive
fn call_event_matches_target_func(
    name: &str,
    receiver: Option<&str>,
    args: &[CallArg],
    target_func: FuncId,
    _target_name: &str,
    global: &GlobalIndex,
    aliases: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller_decl: &Decl,
) -> bool {
    if call_resolves_to_func(global, aliases, local_bindings, caller_decl, name, target_func) {
        return true;
    }
    receiver.is_some()
        && args.iter().any(|arg| {
            call_resolves_to_func(
                global,
                aliases,
                local_bindings,
                caller_decl,
                arg.value_text.trim(),
                target_func,
            )
        })
}
