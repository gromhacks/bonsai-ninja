//! Cross-function call graph + cached summaries (spec §15, §16).
//!
//! The call graph is a directed multi-graph from `FuncId` to `FuncId`. Each
//! edge carries its precision so downstream queries can decide how much to
//! trust it. Summaries are compositional cached facts derived from a
//! function's CFG plus the summaries of every target it calls.

use ahash::{AHashMap, AHashSet};
use bonsai_common::{callable_reference_variants, short_qualified_tail, FileId, FuncId, Precision, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{AliasTarget, CallArg, CallKind, Decl, DeclKind, FlowEvent, TypeAliasBinding};
use bonsai_resolve::{resolve_callable_with_context, resolve_class, visibility_allows, ResolveContext};
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
#[derive(Clone, Debug, Default)]
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
                let local_bindings = collect_local_callable_bindings_with_aliases(
                    &decl.flow_events,
                    global,
                    decl,
                    &alias_targets,
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
    cg: &mut CallGraph,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                call_kind,
                args,
                ..
            } => {
                let short = short_callee(name);
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
                        receiver.as_deref(),
                        *call_kind,
                        name,
                    );
                }
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
                if candidates.is_empty() {
                    if is_erlang_remote_call(name) || qualified_module_alias_call(name, aliases) {
                        continue;
                    }
                    let resolved_name = aliases.get(short).map(String::as_str).unwrap_or(short);
                    // The full-name lookup at line 227 has already
                    // run; only retry when alias rewriting produced
                    // a different name to look up.
                    if resolved_name != name.as_str() {
                        candidates = collect_callable_targets_with_context_and_aliases(
                            global,
                            resolved_name,
                            caller_decl,
                            alias_targets,
                        );
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
                add_receiver_callback_edges(
                    receiver.as_deref(),
                    *call_kind,
                    args,
                    from,
                    caller_decl,
                    global,
                    alias_targets,
                    local_bindings,
                    cg,
                );
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
                    cg,
                );
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn add_receiver_callback_edges(
    receiver: Option<&str>,
    call_kind: CallKind,
    args: &[CallArg],
    from: FuncId,
    caller_decl: &Decl,
    global: &GlobalIndex,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    cg: &mut CallGraph,
) {
    if receiver.is_none() || call_kind != CallKind::Method {
        return;
    }
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
        let trimmed = variant.trim().trim_start_matches('&').trim_start_matches('*');
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
    collect_local_callable_bindings_into(events, global, caller_decl, alias_targets, &mut bindings);
    bindings
}

fn collect_local_callable_bindings_into(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
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
                    .and_then(|name| resolve_callable_symbol(global, name, caller_decl, alias_targets))
                    .or_else(|| {
                        source_names.iter().find_map(|name| {
                            resolve_callable_symbol(global, name, caller_decl, alias_targets)
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
                    bindings,
                );
                collect_local_callable_bindings_into(
                    else_events,
                    global,
                    caller_decl,
                    alias_targets,
                    bindings,
                );
            }
            FlowEvent::Loop { body, .. } => {
                collect_local_callable_bindings_into(body, global, caller_decl, alias_targets, bindings);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_local_callable_bindings_into(body, global, caller_decl, alias_targets, bindings);
                collect_local_callable_bindings_into(
                    catch_events,
                    global,
                    caller_decl,
                    alias_targets,
                    bindings,
                );
                collect_local_callable_bindings_into(
                    finally_events,
                    global,
                    caller_decl,
                    alias_targets,
                    bindings,
                );
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_local_callable_bindings_into(body, global, caller_decl, alias_targets, bindings);
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
    let variants = callable_reference_variants(raw);
    if variants.is_empty() {
        return None;
    }
    let caller_file = caller_decl_file(global, caller_decl)?;
    let caller_module = caller_decl.module_path.clone();
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(alias_targets);
    for variant in variants {
        let trimmed = variant.trim().trim_start_matches('&').trim_start_matches('*');
        if trimmed.is_empty() {
            continue;
        }
        let short = short_callee(trimmed);
        for candidate in [trimmed, short] {
            let resolved = resolve_callable_with_context(global, candidate, &ctx);
            if let Some(func) = resolved.into_iter().next() {
                return Some(func);
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
    call_kind: CallKind,
    call_name: &str,
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
    let receiver_types = receiver_type_names(caller_decl, alias_targets, receiver);
    if receiver_types.is_empty() {
        return Vec::new();
    }
    let caller_module = caller_decl.module_path.clone();
    // Without a known caller file we have nothing to narrow on, so
    // return empty rather than fan out to every workspace-wide
    // bare-name match.
    let (class_candidates, ctx): (Vec<SymbolId>, Option<ResolveContext<'_>>) =
        if let Some(caller_file) = caller_decl_file(global, caller_decl) {
            let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(alias_targets);
            let mut seen = AHashSet::new();
            let mut classes = Vec::new();
            for receiver_type in receiver_types {
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

fn collect_method_candidates_for_class(
    global: &GlobalIndex,
    class_sym: SymbolId,
    method_name: &str,
    ctx: &ResolveContext<'_>,
    seen: &mut AHashSet<SymbolId>,
    out: &mut Vec<FuncId>,
) {
    let Some(class_decl) = global.decl_of(class_sym) else {
        return;
    };
    if !matches!(
        class_decl.kind,
        DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
    ) {
        return;
    }
    let Some(class_file) = global.declaring_file(class_sym) else {
        return;
    };
    for decl in global.decls_in(class_file) {
        if decl.name != method_name {
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some(decl_file) = global.declaring_file(decl.symbol) else {
            continue;
        };
        if !visibility_allows(decl, decl_file, &decl.module_path, ctx) {
            continue;
        }
        // A method's parent link is the canonical signal; the
        // span-containment fallback covers adapters that haven't
        // yet populated `parent`.
        if (decl.parent == Some(class_sym) || span_contains(class_decl.span, decl.span))
            && seen.insert(decl.symbol)
        {
            out.push(FuncId::new(decl.symbol.raw()));
        }
    }
}

fn is_super_receiver(receiver: &str) -> bool {
    let receiver = receiver.trim().trim_start_matches(['&', '*']);
    let receiver = receiver.strip_suffix("()").unwrap_or(receiver).trim();
    matches!(receiver, "super" | "parent" | "base")
}

fn enclosing_class_for_decl<'a>(global: &'a GlobalIndex, decl: &Decl) -> Option<&'a Decl> {
    if let Some(parent) = decl.parent {
        if let Some(parent_decl) = global.decl_of(parent) {
            if matches!(
                parent_decl.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
            ) {
                return Some(parent_decl);
            }
        }
    }
    global
        .decls_in(decl.span.file)
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
            ) && span_contains(candidate.span, decl.span)
        })
        .min_by_key(|candidate| candidate.span.end.saturating_sub(candidate.span.start))
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

fn receiver_type_names(
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

fn alias_targets_for_decl(
    file_alias_targets: &AHashMap<String, AliasTarget>,
    decl: &Decl,
) -> AHashMap<String, AliasTarget> {
    let mut map = file_alias_targets.clone();
    extend_alias_targets_with_declared_types(&mut map, &decl.type_aliases);
    bonsai_lang_api::extend_alias_map_with_flow_events(&mut map, &decl.flow_events);
    map
}

fn extend_alias_targets_with_declared_types(
    alias_targets: &mut AHashMap<String, AliasTarget>,
    type_aliases: &[TypeAliasBinding],
) {
    for alias in type_aliases {
        if alias.name.is_empty() || alias.type_name.is_empty() {
            continue;
        }
        alias_targets
            .entry(alias.name.clone())
            .or_insert_with(|| AliasTarget::Type {
                type_name: alias.type_name.clone(),
            });
    }
}

fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

fn normalize_receiver_alias_text(receiver: &str) -> String {
    let mut text = receiver.trim();
    while text.starts_with('(') && text.ends_with(')') && text.len() > 1 {
        text = text[1..text.len() - 1].trim();
    }
    text.trim_start_matches(['&', '*'])
        .replace("->", ".")
        .trim()
        .trim_matches('.')
        .to_string()
}

fn caller_decl_file(global: &GlobalIndex, caller_decl: &Decl) -> Option<FileId> {
    global.declaring_file(caller_decl.symbol)
}

fn span_contains(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

fn is_erlang_remote_call(name: &str) -> bool {
    name.contains(':') && !name.contains("::")
}

fn qualified_module_alias_call(name: &str, aliases: &AHashMap<String, String>) -> bool {
    let Some((head, _)) = name.split_once(&['.', ':'][..]) else {
        return false;
    };
    aliases.contains_key(head)
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
        let in_target_file =
            path_for_file(file).is_some_and(|path| module_target_matches_path(alias_target, &path));
        if !in_target_file {
            continue;
        }
        let Some(decl) = global.decl_of(sym) else {
            continue;
        };
        if seen_spans.insert((file, decl.span.start, decl.span.end)) {
            targets.push(func);
        }
    }
    targets
}

fn export_name_variants(alias_tail: &str, caller_export_aliases: &[&'static str]) -> Vec<String> {
    let mut variants = vec![alias_tail.to_string()];
    // Each language's `LanguageCapabilities::module_export_aliases`
    // names the receivers under which an exported symbol is also
    // syntactically reachable. JS/TS declare `["exports", "module.exports"]`;
    // languages without this convention declare `&[]`, in which case
    // we just return the bare alias_tail with no expansion.
    for receiver in caller_export_aliases {
        variants.push(format!("{receiver}.{alias_tail}"));
    }
    variants
}

fn module_target_matches_path(alias_target: &str, file_path: &str) -> bool {
    let target = alias_target.replace('\\', "/");
    let path = file_path.replace('\\', "/");
    let target_parts = module_import_parts(&target);
    let path_parts = module_path_parts(&path);
    let Some(target_leaf) = target_parts.last() else {
        return false;
    };
    if path_parts
        .last()
        .is_some_and(|file| strip_extension(file) == target_leaf.as_str())
    {
        return true;
    }
    if path_parts
        .iter()
        .rev()
        .nth(1)
        .is_some_and(|parent| parent == target_leaf)
    {
        return true;
    }
    path_has_module_suffix(&path_parts, &target_parts)
}

fn module_import_parts(text: &str) -> Vec<String> {
    let parts: Vec<&str> = if text.contains('/') {
        text.split('/').collect()
    } else {
        text.split('.').collect()
    };
    parts
        .into_iter()
        .filter_map(|part| {
            let part = part.trim();
            (!part.is_empty() && part != "." && part != "..").then(|| strip_extension(part).to_string())
        })
        .collect()
}

fn module_path_parts(text: &str) -> Vec<String> {
    text.split('/')
        .filter_map(|part| {
            let part = part.trim();
            (!part.is_empty() && part != "." && part != "..").then(|| strip_extension(part).to_string())
        })
        .collect()
}

fn strip_extension(part: &str) -> &str {
    part.rsplit_once('.').map_or(part, |(stem, _)| stem)
}

fn path_has_module_suffix(path_parts: &[String], target_parts: &[String]) -> bool {
    if target_parts.is_empty() || target_parts.len() > path_parts.len() {
        return false;
    }
    path_parts
        .windows(target_parts.len())
        .any(|window| window == target_parts)
}

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

fn collect_callable_targets_exact(global: &GlobalIndex, name: &str) -> Vec<FuncId> {
    global
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
