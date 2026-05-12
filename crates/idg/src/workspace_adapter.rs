//! Phase 3b: workspace adapter that wires the [`stitch_idg`]
//! builder to the real [`bonsai_index::GlobalIndex`] +
//! [`bonsai_callgraph::ResolvedCallGraph`].
//!
//! This is the production entry point: callers build the IDG with
//! `WorkspaceIdgBuilder::new(global, call_graph).build()` and get
//! back an [`IdgWorkspace`] populated with one segment per source
//! file plus the cross-file edge index.
//!
//! ## Why this lives in the IDG crate (not a separate adapter
//! crate)
//!
//! `bonsai_idg` already depends on `bonsai_index` and
//! `bonsai_callgraph`; pulling the adapter into a sibling crate
//! would force a cycle. The adapter is small (~200 LoC) and the
//! [`CalleeResolver`] / [`FuncToSegment`] traits insulate the
//! [`stitch_idg`] core from this code, so unit tests still don't
//! need a workspace.

use ahash::AHashMap;
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{FileId, FuncId};
use bonsai_index::GlobalIndex;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::builder::{stitch_idg, CalleeResolver, FuncToSegment, ResolvedCallee};
use crate::transfer::{transfer_function_for, TransferOutput};
use crate::workspace::{IdgWorkspace, SegmentId};

/// Pre-computed maps that the [`WorkspaceIdgBuilder`] uses for
/// `FuncId → file → SegmentId` lookups during stitching.
struct WorkspaceMaps {
    /// `FuncId → SegmentId placeholder`. The placeholder maps 1:1
    /// to a file id (one segment per file). [`stitch_idg`] then
    /// translates placeholders to real `IdgWorkspace` segment ids
    /// during registration.
    func_to_seg: AHashMap<FuncId, SegmentId>,
    /// `FuncId → callee_name`, used by [`WorkspaceCalleeResolver`]
    /// to filter `ResolvedCallGraph::callees_of` candidates by
    /// name. The transfer pass records calls by their textual
    /// callee name (the only stable handle a flow event has); we
    /// match that against each callee's declared name to figure
    /// out which call edge in the graph corresponds to which call
    /// site.
    func_to_name: AHashMap<FuncId, String>,
}

impl WorkspaceMaps {
    fn build(global: &GlobalIndex) -> Self {
        let mut func_to_seg: AHashMap<FuncId, SegmentId> = AHashMap::new();
        let mut func_to_name: AHashMap<FuncId, String> = AHashMap::new();
        let mut file_to_seg: AHashMap<FileId, SegmentId> = AHashMap::new();
        let mut next_seg = 0u32;
        for file in global.all_files() {
            let seg = SegmentId(next_seg);
            next_seg = next_seg.wrapping_add(1);
            file_to_seg.insert(file, seg);
            for decl in global.functions_in(file) {
                let func = FuncId::new(decl.symbol.raw());
                func_to_seg.insert(func, seg);
                func_to_name.insert(func, decl.name.clone());
            }
        }
        Self {
            func_to_seg,
            func_to_name,
        }
    }
}

/// Resolves a call site against the [`ResolvedCallGraph`].
///
/// For caller `f` with a flow-event call to "g", this walks
/// `call_graph.callees_of(f)` and returns every edge whose target
/// has the declared name "g". The edge's `(kind, precision)` are
/// passed through verbatim — this is **not** a re-resolution, just
/// a filter over already-resolved candidates.
struct WorkspaceCalleeResolver<'a> {
    call_graph: &'a ResolvedCallGraph,
    func_to_name: &'a AHashMap<FuncId, String>,
    global: &'a GlobalIndex,
    /// Per-callee alternate call names. Built from each file's
    /// import alias map so a callee like `persist` aliased as
    /// `persistEnvelope` can be reached via either name. Without
    /// this, the strict `func_to_name` match in `resolve` rejects
    /// the alias-rewritten call site even though the callgraph
    /// already resolved the edge.
    func_to_call_names: &'a AHashMap<FuncId, Vec<String>>,
}

impl<'a> CalleeResolver for WorkspaceCalleeResolver<'a> {
    fn resolve(
        &self,
        caller: FuncId,
        _site: bonsai_common::Span,
        callee_name: &str,
        _receiver: Option<&str>,
        _receiver_types: &[String],
    ) -> Vec<ResolvedCallee> {
        let mut out = Vec::new();
        for edge in self.call_graph.callees_of(caller) {
            // Filter by callee name. Adapters surface call events
            // with whatever syntactic form the source used — bare
            // (`runPipeline(x)`), qualified (`Pipeline.runPipeline(x)`,
            // `Module::func(x)`), or arity-suffixed (`foo/2`). Match
            // against the decl's bare name, the callee event's bare
            // tail, or with arity stripped. The callgraph already
            // narrowed receiver types, so any name match here is a
            // legitimate dispatch target.
            if let Some(decl_name) = self.func_to_name.get(&edge.to) {
                let mut matched = names_match_for_callee(decl_name, callee_name);
                if !matched {
                    // Alias-aware fallback: each FuncId tracks
                    // every textual name it can be called as,
                    // built from import-alias maps. The callgraph
                    // already resolved this edge through the same
                    // alias maps, so when the bare decl name
                    // doesn't match, an alias-name match is
                    // legitimate.
                    if let Some(call_names) = self.func_to_call_names.get(&edge.to) {
                        matched = call_names.iter().any(|n| names_match_for_callee(n, callee_name));
                    }
                }
                if matched {
                    out.push(ResolvedCallee {
                        func: edge.to,
                        edge_kind: edge.kind,
                        precision: edge.precision,
                    });
                }
            }
        }
        // Constructor fallback: when `callee_name` resolves to a
        // class decl but no callgraph edge points at a callable in
        // it (TS / Ruby / JS / C# auto-properties don't surface an
        // explicit `constructor` decl for inheriting classes), walk
        // the class's `bases` chain and route to the nearest
        // ancestor with a real constructor. Without this, every
        // `new SubClass(args)` call site stays disconnected from
        // the base-class field-init body, so a tainted argument
        // never reaches the field write — and the field-flow
        // stitcher (Phase 3c) has nothing to chain off.
        if out.is_empty() {
            self.resolve_class_constructor_fallback(callee_name, &mut out);
        }
        out
    }

    fn callback_bindings(&self, host: FuncId, param_idx: u8) -> Vec<ResolvedCallee> {
        // For every caller of `host`, walk its flow events looking
        // for Call sites that resolve to `host`, and pick the
        // argument at `param_idx`. The arg's text might be a
        // function name (e.g., `run(executor, t)` → arg 0 text is
        // "executor"). Resolve that name through the workspace's
        // func name index to get the bound FuncId. Each
        // resolution becomes a callback ResolvedCallee that the
        // IDG stitcher can use to wire CallArg(callback-call) →
        // bound-func.Param edges.
        let host_name = match self.func_to_name.get(&host) {
            Some(n) => n.clone(),
            None => return Vec::new(),
        };
        let mut out: Vec<ResolvedCallee> = Vec::new();
        let mut seen: ahash::AHashSet<FuncId> = ahash::AHashSet::new();
        let bare_host = host_name
            .rsplit_once(['.', ':'])
            .map(|(_, tail)| tail.to_string())
            .unwrap_or_else(|| host_name.clone());
        for edge in self.call_graph.callers_of(host) {
            let caller = edge.from;
            let Some(caller_decl) = self.global.decl_of(bonsai_common::SymbolId::new(caller.raw())) else {
                continue;
            };
            // Find Call events in caller's flow events whose name
            // matches host's name (or its bare suffix); take the
            // arg at param_idx.
            let mut found_args: Vec<String> = Vec::new();
            collect_arg_text_for_callee(
                &caller_decl.flow_events,
                &host_name,
                &bare_host,
                param_idx as usize,
                &mut found_args,
            );
            for arg_text in found_args {
                // Adapters express callback bindings with various
                // syntactic prefixes — strip them before matching
                // against function names: perl `\&foo`, elixir
                // `&foo/N`, ruby `:foo`, java `Cls::method`,
                // python `pkg.module.foo`. Keep `&` `\\` `:` `&`
                // out of the candidate name; final form is the
                // last bare identifier in the expression.
                let bound_name = strip_callback_syntax(&arg_text);
                if bound_name.is_empty() {
                    continue;
                }
                for (&candidate_func, candidate_name) in self.func_to_name.iter() {
                    if (candidate_name == bound_name || matches_qualified_tail(candidate_name, bound_name))
                        && seen.insert(candidate_func)
                    {
                        out.push(ResolvedCallee {
                            func: candidate_func,
                            edge_kind: bonsai_callgraph::EdgeKind::Indirect,
                            precision: bonsai_common::Precision::Narrowed,
                        });
                    }
                }
            }
        }
        out
    }
}

impl<'a> WorkspaceCalleeResolver<'a> {
    /// Walk the class hierarchy for `callee_name`, looking for a
    /// `DeclKind::Constructor` (or `Function` named "constructor"
    /// / `"__init__"` / `"initialize"`) we can route an
    /// unresolved `new ClassName(args)` call to. TS / JS / Ruby /
    /// C# auto-properties don't surface explicit constructor
    /// decls for inheriting classes — without this fallback,
    /// every `new SubClass(args)` site stays disconnected from
    /// the base-class field-init body, so a tainted argument
    /// never reaches the field write and field-flow stitching has
    /// nothing to chain off.
    fn resolve_class_constructor_fallback(&self, callee_name: &str, out: &mut Vec<ResolvedCallee>) {
        use bonsai_lang_api::DeclKind;
        let trimmed = callee_name.trim();
        if trimmed.is_empty() {
            return;
        }
        let bare = bare_class_name(trimmed);
        if bare.is_empty() {
            return;
        }
        let mut frontier: Vec<bonsai_common::SymbolId> = Vec::new();
        let mut seen: ahash::AHashSet<bonsai_common::SymbolId> = ahash::AHashSet::default();
        let mut all_class_by_name: ahash::AHashMap<String, bonsai_common::SymbolId> =
            ahash::AHashMap::default();
        for file in self.global.all_files() {
            for decl in self.global.decls_in(file) {
                if matches!(decl.kind, DeclKind::Class) {
                    all_class_by_name.entry(decl.name.clone()).or_insert(decl.symbol);
                }
            }
        }
        if let Some(&start) = all_class_by_name.get(bare) {
            frontier.push(start);
        }
        while let Some(class_sym) = frontier.pop() {
            if !seen.insert(class_sym) {
                continue;
            }
            let Some(class_decl) = self.global.decl_of(class_sym) else {
                continue;
            };
            for file in self.global.all_files() {
                for decl in self.global.decls_in(file) {
                    if decl.parent != Some(class_sym) {
                        continue;
                    }
                    let is_ctor = matches!(decl.kind, DeclKind::Constructor)
                        || (matches!(decl.kind, DeclKind::Function | DeclKind::Method)
                            && (decl.name == "constructor"
                                || decl.name == "__init__"
                                || decl.name == "initialize"));
                    if !is_ctor {
                        continue;
                    }
                    let func = FuncId::new(decl.symbol.raw());
                    if !out.iter().any(|c| c.func == func) {
                        out.push(ResolvedCallee {
                            func,
                            edge_kind: bonsai_callgraph::EdgeKind::Indirect,
                            precision: bonsai_common::Precision::Narrowed,
                        });
                    }
                }
            }
            if !out.is_empty() {
                return;
            }
            for base_name in &class_decl.bases {
                if let Some(&base_sym) = all_class_by_name.get(base_name.as_str()) {
                    frontier.push(base_sym);
                }
            }
        }
    }
}

/// Strip adapter-specific callback-binding syntax from `text`,
/// returning the bare function name. Handles perl `\&foo`, elixir
/// `&foo/N`, ruby `:foo` / `:"foo"` / `method(:foo)`, java
/// `Cls::method`, python `module.foo`, javascript bare `foo`,
/// erlang `fun foo/N` / `fun M:foo/N`. Returns empty when `text`
/// doesn't look like a name reference.
fn strip_callback_syntax(text: &str) -> &str {
    let mut s = text.trim();
    // Ruby `method(:foo)` / Python `partial(foo)` / Erlang
    // `fun(foo)`: when the text is a wrapper-call form, recurse
    // into the parenthesised inner expression.
    if let Some(open) = s.find('(') {
        if let Some(close) = s.rfind(')') {
            if open < close {
                let prefix = s[..open].trim();
                if matches!(prefix, "method" | "partial" | "fun") {
                    s = s[open + 1..close].trim();
                }
            }
        }
    }
    // Erlang `fun foo/N` (no parens).
    if let Some(rest) = s.strip_prefix("fun ") {
        s = rest.trim();
    }
    // Strip leading code-reference markers.
    while let Some(rest) = s
        .strip_prefix('\\')
        .or_else(|| s.strip_prefix('&'))
        .or_else(|| s.strip_prefix(':'))
    {
        s = rest;
    }
    // Strip trailing `/N` arity (elixir `&foo/2`, erlang `foo/N`).
    if let Some(idx) = s.find('/') {
        if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            s = &s[..idx];
        }
    }
    // Pick the last `::` / `.`-qualified segment (java
    // `Cls::method` → `method`; python `pkg.foo` → `foo`;
    // erlang `M:foo` → `foo`).
    if let Some(stripped) = s.rsplit_once("::") {
        s = stripped.1;
    }
    if let Some(stripped) = s.rsplit_once('.') {
        s = stripped.1;
    }
    // Strip stray quotes (ruby `:"foo"`).
    s = s.trim_matches(|c: char| c == '"' || c == '\'').trim();
    // Final guard: if the result still has spaces or punctuation,
    // it isn't a clean identifier — bail out.
    if s.is_empty() || !s.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return "";
    }
    s
}

/// True when `name` (a workspace func decl name) ends with `tail`
/// after a `.` or `::` qualifier — handles `Module::executor`
/// matching against bare-name binding `executor`.
fn matches_qualified_tail(name: &str, tail: &str) -> bool {
    if name == tail {
        return true;
    }
    name.rsplit_once(['.', ':'])
        .map(|(_, suffix)| suffix == tail)
        .unwrap_or(false)
}

/// Match `decl_name` (the callee function's declared bare name)
/// against `event_name` (the callee text recorded on the call
/// site's flow event). Handles three forms in addition to exact
/// equality:
///   * Qualified prefix: `Pipeline.runPipeline` / `Module::func`
///     should match decl `runPipeline` / `func`.
///   * Arity suffix: erlang / elixir `foo/2` should match decl `foo`.
///   * Both at once: `mod:foo/2` matches decl `foo`.
fn names_match_for_callee(decl_name: &str, event_name: &str) -> bool {
    if decl_name == event_name {
        return true;
    }
    let mut tail = event_name;
    // Strip PHP-style instance-method-chain prefix (`Foo::wrap($x)->run`
    // → `run`). The `->` separator doesn't fall through the
    // `.`/`:` split below, so check it first.
    if let Some(idx) = tail.rfind("->") {
        tail = &tail[idx + 2..];
    }
    if let Some((_head, rest)) = tail.rsplit_once(['.', ':']) {
        tail = rest;
    }
    if let Some(idx) = tail.find('/') {
        if tail[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            tail = &tail[..idx];
        }
    }
    if decl_name == tail {
        return true;
    }
    matches_qualified_tail(decl_name, tail)
}

/// Walk `events`, find every Call event whose callee name matches
/// `host_name` or its bare suffix `bare_host`, and append the
/// `arg_idx`-th argument's `value_text` plus every `source_names`
/// entry to `out`. Both are surfaced because adapters express
/// callback bindings differently — perl `\&executor` lands in
/// `value_text` only, ruby `:foo` lands in both, java `Cls::m`
/// lands in `value_text` while the bare name is in `source_names`.
/// Adding all candidate textual handles keeps callback resolution
/// adapter-agnostic.
fn collect_arg_text_for_callee(
    events: &[bonsai_lang_api::FlowEvent],
    host_name: &str,
    bare_host: &str,
    arg_idx: usize,
    out: &mut Vec<String>,
) {
    use bonsai_lang_api::FlowEvent;
    let push_arg = |arg: &bonsai_lang_api::CallArg, out: &mut Vec<String>| {
        out.push(arg.value_text.clone());
        for name in &arg.source_names {
            if !name.is_empty() {
                out.push(name.clone());
            }
        }
        if let Some(place) = arg.place.as_deref() {
            if !place.is_empty() {
                out.push(place.to_string());
            }
        }
    };
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } => {
                if name == host_name || matches_qualified_tail(name, bare_host) {
                    if let Some(arg) = args.get(arg_idx) {
                        push_arg(arg, out);
                    }
                }
            }
            FlowEvent::Assign {
                source_call,
                source_call_args,
                ..
            } => {
                if let Some(callee) = source_call {
                    if callee == host_name || matches_qualified_tail(callee, bare_host) {
                        if let Some(text) = source_call_args.get(arg_idx) {
                            out.push(text.clone());
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_arg_text_for_callee(then_events, host_name, bare_host, arg_idx, out);
                collect_arg_text_for_callee(else_events, host_name, bare_host, arg_idx, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_arg_text_for_callee(body, host_name, bare_host, arg_idx, out);
                collect_arg_text_for_callee(catch_events, host_name, bare_host, arg_idx, out);
                collect_arg_text_for_callee(finally_events, host_name, bare_host, arg_idx, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_arg_text_for_callee(body, host_name, bare_host, arg_idx, out);
            }
            _ => {}
        }
    }
}

/// `FuncToSegment` view onto the precomputed [`WorkspaceMaps`].
struct WorkspaceFuncToSegment<'a> {
    func_to_seg: &'a AHashMap<FuncId, SegmentId>,
}

impl<'a> FuncToSegment for WorkspaceFuncToSegment<'a> {
    fn segment_for(&self, func: FuncId) -> Option<SegmentId> {
        self.func_to_seg.get(&func).copied()
    }
}

/// Build a workspace IDG from a global index and resolved
/// callgraph. The transfer pass runs in parallel across functions
/// (rayon), then the serial stitching phase wires cross-function
/// edges.
///
/// Returns the populated [`IdgWorkspace`].
///
/// # Example
///
/// ```ignore
/// let global: Arc<GlobalIndex> = db.global_index();
/// let call_graph: ResolvedCallGraph =
///     ResolvedCallGraph::build_with(&global, alias_provider);
/// let idg: IdgWorkspace =
///     bonsai_idg::workspace_adapter::build(&global, &call_graph);
/// ```
#[must_use]
pub fn build(global: &GlobalIndex, call_graph: &ResolvedCallGraph) -> IdgWorkspace {
    build_with_aliases(global, call_graph, |_| AHashMap::new())
}

/// Build with a per-file alias provider. Used by the workspace
/// layer to thread `bonsai_resolve::alias_map_for_file` (which
/// reads each file's `ImportSpec` list) into the IDG resolver,
/// so alias-renamed call sites still resolve to their underlying
/// callee. Callers that don't have alias data (tests, fixtures)
/// can use [`build`].
pub fn build_with_aliases<F>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    mut aliases_for_file: F,
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
{
    let maps = WorkspaceMaps::build(global);
    let outputs = run_transfer_in_parallel(global);
    // Build `func_to_call_names`: every textual name a func can be
    // called as. Decl name plus every alias declared in any file
    // that imports the func by a renamed identifier. We invert the
    // per-file `{local_name → original_name}` map: when a file
    // imports `persist as persistEnvelope`, every persist FuncId
    // gains the alias `persistEnvelope` so the IDG resolver
    // accepts call sites that spell it that way.
    let mut func_to_call_names: AHashMap<FuncId, Vec<String>> = AHashMap::new();
    let mut name_to_funcs: AHashMap<String, Vec<FuncId>> = AHashMap::new();
    for (func, name) in &maps.func_to_name {
        name_to_funcs.entry(name.clone()).or_default().push(*func);
    }
    for file in global.all_files() {
        let aliases = aliases_for_file(file);
        for (alias, original) in aliases {
            if let Some(funcs) = name_to_funcs.get(&original) {
                for func in funcs {
                    let entry = func_to_call_names.entry(*func).or_default();
                    if !entry.contains(&alias) {
                        entry.push(alias.clone());
                    }
                }
            }
        }
    }
    // Function-pointer / closure aliasing: when a decl's body
    // contains `let f = some_func;` and later calls `f(...)`, the
    // adapter records the call's `name` as `"f"`. The resolved
    // callgraph already adds the edge through `local_bindings`, but
    // the IDG `WorkspaceCalleeResolver.resolve` matches by callee
    // name and would reject `f` against the decl name `some_func`.
    // Mirror the alias-rename treatment: every local binding
    // surfaced anywhere in the workspace contributes its lhs as an
    // additional call-name for the callable's FuncId.
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            ) {
                continue;
            }
            let bindings = bonsai_callgraph::collect_local_callable_bindings(&decl.flow_events, global, decl);
            for (alias, func) in bindings {
                let entry = func_to_call_names.entry(func).or_default();
                if !entry.contains(&alias) {
                    entry.push(alias);
                }
            }
        }
    }
    let resolver = WorkspaceCalleeResolver {
        call_graph,
        func_to_name: &maps.func_to_name,
        global,
        func_to_call_names: &func_to_call_names,
    };
    let f2s = WorkspaceFuncToSegment {
        func_to_seg: &maps.func_to_seg,
    };
    let mut ws = stitch_idg(outputs, &resolver, &f2s);
    stitch_receiver_field_flow(&mut ws, global);
    stitch_receiver_method_propagation(&mut ws, global, call_graph);
    ws
}

/// Phase 3d: implicit-receiver propagation through method calls.
/// When a caller calls a method with a tainted receiver, the
/// closure needs to enter the callee and taint its reads of class
/// fields. The IDG transfer pass models the receiver-bridge as a
/// `Place::CallArg{site, idx=u8::MAX}` slot in the caller, but
/// nothing connects that slot into the callee's body. This phase
/// stitches each receiver-bridge slot to every `Place::Read{name,
/// path: []}` inside the callee whose canonical name matches a
/// field written by ANY peer method of the callee's parent class.
/// The "field" predicate is identical to Phase 3c — same
/// canonical-name table — so a Ruby `repo.run` tainted-receiver
/// reaches `Repository#cmd`'s `@data` Read the same way it
/// reaches a peer-method's Write of `@data`.
fn stitch_receiver_method_propagation(
    ws: &mut IdgWorkspace,
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
) {
    use crate::edge::IdgEdgeKind;
    use bonsai_common::SymbolId;
    use bonsai_lang_api::DeclKind;
    // Group decls by parent so we know each class's known fields.
    // Reuse the field-flow scoping (parent-only buckets) so we
    // don't over-link free functions. Walk the inheritance chain
    // via `decl.bases` so a subclass method that reads a base
    // class's field still finds the field-write in the base
    // class's bucket. Mirror Phase 3c's traversal.
    let class_by_name: ahash::AHashMap<String, SymbolId> = global
        .all_files()
        .flat_map(|file| global.decls_in(file).iter())
        .filter(|decl| matches!(decl.kind, DeclKind::Class))
        .map(|decl| (decl.name.clone(), decl.symbol))
        .collect();
    let mut by_class: ahash::AHashMap<SymbolId, Vec<FuncId>> = ahash::AHashMap::default();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let Some(parent) = decl.parent else { continue };
            let func = FuncId::new(decl.symbol.raw());
            by_class.entry(parent).or_default().push(func);
            // Climb the inheritance chain so the func appears in
            // each ancestor's bucket too — a `Repository#run`
            // needs to be paired with `BaseRepository#cmd`'s
            // Place::Return when Phase 3d looks for class fields
            // available to Run's call sites.
            let mut visited: ahash::AHashSet<SymbolId> = ahash::AHashSet::default();
            visited.insert(parent);
            let mut frontier: Vec<SymbolId> = vec![parent];
            while let Some(class_sym) = frontier.pop() {
                let Some(class_decl) = global.decl_of(class_sym) else {
                    continue;
                };
                for base_name in &class_decl.bases {
                    let Some(&base_sym) = class_by_name.get(base_name.as_str()) else {
                        continue;
                    };
                    if !visited.insert(base_sym) {
                        continue;
                    }
                    by_class.entry(base_sym).or_default().push(func);
                    frontier.push(base_sym);
                }
            }
        }
    }
    let mut sorted_classes: Vec<SymbolId> = by_class.keys().copied().collect();
    sorted_classes.sort_by_key(|s| s.raw());
    for class_sym in sorted_classes {
        let funcs = match by_class.get(&class_sym) {
            Some(v) => v.clone(),
            None => continue,
        };
        // Discover the class's writable field set. Use the same
        // canonicalisation as Phase 3c so sigil'd / qualified
        // writes bucket onto the same key as bare-name reads.
        let mut field_names: ahash::AHashSet<String> = ahash::AHashSet::default();
        for func in &funcs {
            collect_field_write_names(ws, *func, &mut field_names);
            // Also include the function's own decl name as a
            // potential field key — getters / property
            // accessors (`def cmd; @data[:cmd]; end`,
            // `get cmd() => this._data.cmd`) return values that
            // peers consume by name. Without this, a peer
            // method's `Read("cmd")` doesn't pair with the
            // getter's Return.
            if let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) {
                let canonical = canonical_field_name(&decl.name);
                if !canonical.is_empty() {
                    field_names.insert(canonical);
                }
            }
        }
        if field_names.is_empty() {
            continue;
        }
        let mut sorted_funcs = funcs;
        sorted_funcs.sort_by_key(|f| f.raw());
        for callee in sorted_funcs {
            // Locate every `Place::Read{name, path: []}` ws_node in
            // `callee` whose canonical name is one of the class's
            // writable fields.
            let mut read_nodes = collect_field_read_nodes(ws, callee, &field_names);
            // Also include every recv-slot CallArg in the callee's
            // body. This carries the receiver-tainted state through
            // intermediate methods that don't read class fields
            // directly (`AuditedRepository.run()` body is just
            // `return super.run()` — no field reads, but its super
            // recv-slot needs to be tainted so the next Phase 3d
            // pair `(run, super.run)` finds the recv-slot in the
            // closure).
            let recv_targets = collect_recv_slot_nodes(ws, callee);
            for n in &recv_targets {
                if !read_nodes.contains(n) {
                    read_nodes.push(*n);
                }
            }
            // Super-chain enrichment: if the callee's body is a thin
            // override that delegates via `super` / `super()` (Ruby's
            // bare-`super` keyword, Java/C# `super.method()`, etc.),
            // its own read_nodes can be empty even though the actual
            // method body lives in a parent class. Fold in read_nodes
            // from same-name methods of ancestor classes so the
            // receiver-bridge from the caller still bridges to a
            // field read somewhere in the inheritance chain. We also
            // track which ancestor funcs contributed so the
            // field_flow link emission below records them as
            // additional readers — that way the cross_call_edges_in_closure
            // pass emits caller→ancestor-callee edges too, so the
            // chain renderer surfaces the canonical super-resolved
            // call sequence.
            let delegates = callee_body_delegates_via_super(global, callee);
            let mut super_chain_funcs: Vec<FuncId> = Vec::new();
            if read_nodes.is_empty() || delegates {
                let extras = collect_super_chain_read_nodes_and_funcs(
                    ws,
                    global,
                    callee,
                    &class_by_name,
                    &field_names,
                );
                for (n, f) in extras {
                    if !read_nodes.contains(&n) {
                        read_nodes.push(n);
                    }
                    if !super_chain_funcs.contains(&f) && f != callee {
                        super_chain_funcs.push(f);
                    }
                }
            }
            if read_nodes.is_empty() {
                continue;
            }
            // For each caller of `callee` whose call-site receiver
            // is bare, find the receiver-bridge `CallArg{site,
            // idx=u8::MAX}` ws_node in the caller's segment and
            // emit edges into each field-Read of the callee.
            for edge in call_graph.callers_of(callee) {
                let caller = edge.from;
                let recv_slots = recv_slots_for_call_to(ws, global, caller, callee);
                let mut emitted_link_for_call = false;
                for (recv_ws, callee_target) in recv_slots {
                    if let Some(target) = callee_target {
                        add_edge_between_ws_nodes(
                            ws,
                            recv_ws,
                            target,
                            IdgEdgeKind::IntraRead,
                            bonsai_common::Precision::OverApproximate,
                        );
                    } else {
                        for read_ws in &read_nodes {
                            add_edge_between_ws_nodes(
                                ws,
                                recv_ws,
                                *read_ws,
                                IdgEdgeKind::IntraRead,
                                bonsai_common::Precision::OverApproximate,
                            );
                        }
                    }
                    if !emitted_link_for_call {
                        let recv_span = ws_node_span(ws, recv_ws)
                            .unwrap_or_else(|| bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 0));
                        // Super-chain pick: if the callee delegates
                        // via `super` and an ancestor's method has
                        // the actual body (field reads), emit ONE
                        // link to the DEEPEST ancestor with real
                        // body. The cross-call edge then renders the
                        // canonical chain through the parent's
                        // method (e.g. Ruby's
                        // `persist → Repository.run` instead of
                        // `persist → AuditedRepository.run` which
                        // just delegates). Keeping a single link
                        // avoids multiplying the finding count
                        // (one finding per chain shape).
                        let reader_func = super_chain_funcs.last().copied().unwrap_or(callee);
                        ws.field_flow_mut().push(crate::workspace::FieldFlowLink {
                            writer: caller,
                            reader: reader_func,
                            writer_ws_node: recv_ws.0,
                            reader_ws_node: read_nodes.first().map(|w| w.0).unwrap_or(0),
                            via_span: recv_span,
                        });
                        emitted_link_for_call = true;
                    }
                }
            }
        }
    }
}

/// Collect the canonical names of every `Place::Write{path-empty}`
/// or qualified `Place::Write{name="self"/"this", path=[field, ..]}`
/// in `func`'s segment, PLUS the canonical name of the func itself
/// (so peer-class getters / property accessors expose their decl
/// name as a field key — `def cmd` returning a tainted value
/// surfaces "cmd" as a field-readable name on the class).
fn collect_field_write_names(ws: &IdgWorkspace, func: FuncId, out: &mut ahash::AHashSet<String>) {
    use crate::place::Place;
    let Some(seg_id) = ws.segment_for_func(func) else {
        return;
    };
    let Some(segment) = ws.segment(seg_id) else {
        return;
    };
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        let canonical = match place {
            Place::Write { name, path, .. } if path.is_empty() => {
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                canonical_field_name(s)
            }
            Place::Write { name, path, .. } if !path.is_empty() => {
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                if !is_implicit_receiver_name(s) {
                    continue;
                }
                let head_id = path[0];
                let Some(head) = segment.strings.get(head_id) else {
                    continue;
                };
                head.to_string()
            }
            _ => continue,
        };
        if canonical.is_empty() {
            continue;
        }
        // Verify the place actually has a node interned for this
        // func — segment.places is shared across funcs in the same
        // segment, so the field-name set may mention places that
        // belong to other funcs. Skip those.
        let pid = crate::node::PlaceId(pid_idx as u32);
        if segment.nodes.lookup(func, pid).is_some() {
            out.insert(canonical);
        }
    }
}

/// Collect every `Place::Read{name, path: []}` ws_node in `func`'s
/// segment whose canonical name lies in `field_names`. Used by
/// Phase 3d to find receiver-state targets to wire from method
/// callers.
fn collect_field_read_nodes(
    ws: &IdgWorkspace,
    func: FuncId,
    field_names: &ahash::AHashSet<String>,
) -> Vec<crate::WsNodeId> {
    use crate::place::Place;
    let Some(seg_id) = ws.segment_for_func(func) else {
        return Vec::new();
    };
    let Some(segment) = ws.segment(seg_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        let Place::Read { name, path } = place else {
            continue;
        };
        if !path.is_empty() {
            continue;
        }
        let Some(s) = segment.strings.get(*name) else {
            continue;
        };
        let canonical = canonical_field_name(s);
        if !field_names.contains(&canonical) {
            continue;
        }
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(local) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        let Some(ws_node) = ws_node_for(ws, seg_id, local) else {
            continue;
        };
        out.push(ws_node);
    }
    out.sort();
    out.dedup();
    out
}

/// Collect every `Place::CallArg{site, idx=u8::MAX or 0}` ws_node
/// in `func`'s segment. Used by Phase 3d to bridge receiver state
/// through methods whose body is a one-liner like
/// `return super.method()` — they have no field reads of their own,
/// but their downstream recv-slots need to inherit the caller's
/// taint so the next-level `(method, super.method)` pair sees its
/// recv-slot in the closure.
///
/// Returns every recv-slot in the body (idx = `u8::MAX` or 0).
/// Earlier work attempted to narrow this to "implicit-receiver
/// shapes only" (calls whose receiver is `self` / `this` /
/// `super` / a class field), but field-name heuristics across the
/// 21-language surface couldn't reliably distinguish receiver-
/// shared shapes (csharp `_repo.Run()`, python free-function
/// `pipeline = Pipeline(); pipeline.run()`) from incidental
/// `helper.format()`-style locals. The broad inclusion is
/// load-bearing for the mega_flow chains; the worst-case over-link
/// only propagates taint into fields the IDG can prove exist, so
/// the practical inflation is bounded.
/// True when `callee`'s body delegates via `super` / `super()` —
/// the body either contains a `FlowEvent::Call { name: "super"|... }`
/// event OR is essentially empty (no field reads, no recv slots) and
/// inherits a same-name method from a base class. Used by Phase 3d
/// to fold ancestor `read_nodes` into the override's bridge set.
fn callee_body_delegates_via_super(global: &GlobalIndex, callee: FuncId) -> bool {
    use bonsai_lang_api::FlowEvent;
    let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(callee.raw())) else {
        return false;
    };
    fn walk(events: &[FlowEvent]) -> bool {
        for e in events {
            match e {
                FlowEvent::Call { name, receiver, .. } => {
                    if name == "super"
                        || name.starts_with("super.")
                        || name.starts_with("super(")
                        || name.starts_with("super::")
                        || receiver.as_deref() == Some("super")
                    {
                        return true;
                    }
                }
                FlowEvent::Return {
                    value_text,
                    value_name,
                    ..
                } => {
                    if value_name.as_deref() == Some("super")
                        || value_text
                            .as_deref()
                            .map(|s| {
                                let t = s.trim();
                                t == "super"
                                    || t.starts_with("super")
                                        && !t.contains(|c: char| {
                                            c.is_ascii_alphanumeric()
                                                && c != 's'
                                                && c != 'u'
                                                && c != 'p'
                                                && c != 'e'
                                                && c != 'r'
                                        })
                            })
                            .unwrap_or(false)
                    {
                        return true;
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if walk(then_events) || walk(else_events) {
                        return true;
                    }
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => {
                    if walk(body) {
                        return true;
                    }
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if walk(body) || walk(catch_events) || walk(finally_events) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
    walk(&decl.flow_events)
}

/// Collect `read_nodes` from every ancestor class's method of the
/// same name as `callee`. The caller of `callee` may have only the
/// override in its callgraph adjacency, but the actual taint flow
/// reaches the parent body via `super`. Walks `decl.bases`
/// transitively.
fn collect_super_chain_read_nodes_and_funcs(
    ws: &IdgWorkspace,
    global: &GlobalIndex,
    callee: FuncId,
    class_by_name: &ahash::AHashMap<String, bonsai_common::SymbolId>,
    field_names: &ahash::AHashSet<String>,
) -> Vec<(crate::WsNodeId, FuncId)> {
    let Some(callee_decl) = global.decl_of(bonsai_common::SymbolId::new(callee.raw())) else {
        return Vec::new();
    };
    let Some(parent_sym) = callee_decl.parent else {
        return Vec::new();
    };
    let method_name = callee_decl.name.clone();
    let mut out: Vec<(crate::WsNodeId, FuncId)> = Vec::new();
    let mut visited: ahash::AHashSet<bonsai_common::SymbolId> = ahash::AHashSet::default();
    visited.insert(parent_sym);
    let mut frontier: Vec<bonsai_common::SymbolId> = Vec::new();
    if let Some(parent_decl) = global.decl_of(parent_sym) {
        for base_name in &parent_decl.bases {
            if let Some(&base_sym) = class_by_name.get(base_name.as_str()) {
                if visited.insert(base_sym) {
                    frontier.push(base_sym);
                }
            }
        }
    }
    while let Some(class_sym) = frontier.pop() {
        // For every method in this class with the same name as
        // `callee`, fold in its read_nodes.
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if decl.parent != Some(class_sym) {
                    continue;
                }
                if decl.name != method_name {
                    continue;
                }
                let other = FuncId::new(decl.symbol.raw());
                let mut nodes = collect_field_read_nodes(ws, other, field_names);
                let recv = collect_recv_slot_nodes(ws, other);
                for n in recv {
                    if !nodes.contains(&n) {
                        nodes.push(n);
                    }
                }
                for n in nodes {
                    if !out.iter().any(|(existing_n, _)| *existing_n == n) {
                        out.push((n, other));
                    }
                }
            }
        }
        if let Some(class_decl) = global.decl_of(class_sym) {
            for base_name in &class_decl.bases {
                if let Some(&base_sym) = class_by_name.get(base_name.as_str()) {
                    if visited.insert(base_sym) {
                        frontier.push(base_sym);
                    }
                }
            }
        }
    }
    out
}

fn collect_recv_slot_nodes(ws: &IdgWorkspace, func: FuncId) -> Vec<crate::WsNodeId> {
    use crate::place::Place;
    let Some(seg_id) = ws.segment_for_func(func) else {
        return Vec::new();
    };
    let Some(segment) = ws.segment(seg_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        let Place::CallArg { idx, .. } = place else {
            continue;
        };
        if *idx != u8::MAX && *idx != 0 {
            continue;
        }
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(local) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        let Some(ws_node) = ws_node_for(ws, seg_id, local) else {
            continue;
        };
        out.push(ws_node);
    }
    out.sort();
    out.dedup();
    out
}

/// Return every receiver-bridge `Place::CallArg{site, idx=u8::MAX}`
/// ws_node in `caller`'s segment whose call-site resolves to
/// `callee`. The second tuple element is `None` for the generic
/// fan-out case (caller-side receiver-bridge taints all of
/// callee's field reads). Future work could narrow this to a
/// specific Read node when the callee's parameter list pins the
/// field reference precisely.
fn recv_slots_for_call_to(
    ws: &IdgWorkspace,
    global: &GlobalIndex,
    caller: FuncId,
    callee: FuncId,
) -> Vec<(crate::WsNodeId, Option<crate::WsNodeId>)> {
    use crate::place::Place;
    use bonsai_common::SymbolId;
    let mut out: Vec<(crate::WsNodeId, Option<crate::WsNodeId>)> = Vec::new();
    let Some(caller_decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return out;
    };
    let Some(callee_decl) = global.decl_of(SymbolId::new(callee.raw())) else {
        return out;
    };
    let bare_callee = bare_decl_name(&callee_decl.name);
    let mut call_spans: Vec<bonsai_common::Span> = Vec::new();
    collect_method_call_spans(
        &caller_decl.flow_events,
        &callee_decl.name,
        bare_callee,
        &mut call_spans,
    );
    if call_spans.is_empty() {
        return out;
    }
    let Some(seg_id) = ws.segment_for_func(caller) else {
        return out;
    };
    let Some(segment) = ws.segment(seg_id) else {
        return out;
    };
    for span in call_spans {
        // Emit edges from BOTH the receiver-bridge slot
        // (`idx=u8::MAX`) and the synthetic args-empty slot
        // (`idx=0`). The transfer pass's `args.is_empty()`
        // fallback (in walk_call) creates a `CallArg{site, idx=0}`
        // that funnels every name token from the call expression
        // — receivers spelled with `super` / `base` / `this` may
        // route through that slot rather than the dedicated
        // `idx=u8::MAX` bridge, depending on adapter shape. Trying
        // both keeps the receiver-state edge alive across that
        // ambiguity.
        for try_idx in [u8::MAX, 0u8] {
            let place = Place::CallArg {
                site: crate::CallSiteId(span),
                idx: try_idx,
            };
            let Some(pid) = segment.places.lookup(&place) else {
                continue;
            };
            let Some(local) = segment.nodes.lookup(caller, pid) else {
                continue;
            };
            let Some(ws_node) = ws_node_for(ws, seg_id, local) else {
                continue;
            };
            out.push((ws_node, None));
        }
    }
    out
}

/// Strip generic / qualified prefix off a class-like callee name.
/// Handles `AuditedRepository<T>` → `AuditedRepository`,
/// `mod.Foo` → `Foo`, `Foo::Bar` → `Bar`. Empty input or
/// non-identifier residue returns empty.
fn bare_class_name(name: &str) -> &str {
    let trimmed = name.trim();
    let mut s = trimmed;
    // Drop generic suffix.
    if let Some(idx) = s.find('<') {
        s = &s[..idx];
    }
    // Pick last `::` / `.` component.
    if let Some((_, tail)) = s.rsplit_once("::") {
        s = tail;
    }
    if let Some((_, tail)) = s.rsplit_once('.') {
        s = tail;
    }
    s = s.trim();
    if s.is_empty() || !s.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return "";
    }
    s
}

/// Bare-name tail of a qualified decl name (`Class.method` →
/// `method`). Mirrors `bonsai_callgraph::short_callee` semantics
/// without the dependency cycle.
fn bare_decl_name(name: &str) -> &str {
    let mut s = name;
    // Strip PHP-style instance-method-chain suffix prefix
    // (`Foo::wrap($x)->run` → `run`).
    if let Some(idx) = s.rfind("->") {
        s = &s[idx + 2..];
    }
    s.rsplit_once(['.', ':', '\\']).map(|(_, tail)| tail).unwrap_or(s)
}

/// Walk `events`, find every `FlowEvent::Call` whose callee name
/// matches `decl_name` or `bare_decl_name(decl_name)`, and append
/// the call's site span. Used by Phase 3d to locate the
/// receiver-bridge CallArg slot in a caller.
fn collect_method_call_spans(
    events: &[bonsai_lang_api::FlowEvent],
    decl_name: &str,
    bare: &str,
    out: &mut Vec<bonsai_common::Span>,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } => {
                let n = name.as_str();
                let n_bare = bare_decl_name(n);
                if n == decl_name || n_bare == bare || n == bare {
                    out.push(*span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_method_call_spans(then_events, decl_name, bare, out);
                collect_method_call_spans(else_events, decl_name, bare, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_method_call_spans(body, decl_name, bare, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_method_call_spans(body, decl_name, bare, out);
                collect_method_call_spans(catch_events, decl_name, bare, out);
                collect_method_call_spans(finally_events, decl_name, bare, out);
            }
            _ => {}
        }
    }
}

/// Phase 3c: cross-method instance-field flow. The IDG transfer
/// pass models writes / reads of receiver fields (`self.cmd`,
/// `@cmd`, `$this->cmd`, ...) as per-method `Place::Write{name=...}`
/// / `Place::Read{name=...}` nodes, but each method is its own
/// segment — without an explicit cross-method edge, a write in one
/// method never reaches a read in another even when both belong to
/// the same class. Stitch those edges here: group decls by parent
/// (class), find every (writer-method, reader-method) pair that
/// touches the same field name (with sigil-aware aliasing), and
/// emit `Write(field)` → `Read(field)` edges. Same-segment pairs
/// land in the segment's intra-edge list; cross-segment pairs
/// flow through `cross_file_mut`.
fn stitch_receiver_field_flow(ws: &mut IdgWorkspace, global: &GlobalIndex) {
    use crate::edge::IdgEdgeKind;
    use bonsai_common::SymbolId;
    use bonsai_lang_api::DeclKind;
    // Group function-shaped decls by parent symbol id. Decls
    // without a parent collapse into a single "no-parent" bucket
    // keyed by file (an adapter that doesn't surface class parents
    // — e.g. ruby today — still wants intra-file methods of the
    // same class to share field flow). The bucket key is
    // `Some(parent)` when known, else `None` paired with the
    // file id for a coarse fallback.
    // Group methods by every parent class in their inheritance
    // chain. A method `Repository#run` that reads `_data` should
    // be paired with `BaseRepository#constructor`'s Write of
    // `_data`, even though `run`'s direct `decl.parent` is
    // `Repository`. Walk the bases up via `decl.bases` (textual
    // class names) and resolve them to SymbolIds via the global
    // index, so each method appears in its OWN class bucket AND
    // every ancestor bucket. The `(None, file)` bucket is still
    // skipped — module-level free functions don't share fields.
    let mut by_class: ahash::AHashMap<(Option<SymbolId>, bonsai_common::FileId), Vec<FuncId>> =
        ahash::AHashMap::default();
    let class_by_name: ahash::AHashMap<String, SymbolId> = global
        .all_files()
        .flat_map(|file| global.decls_in(file).iter())
        .filter(|decl| matches!(decl.kind, DeclKind::Class))
        .map(|decl| (decl.name.clone(), decl.symbol))
        .collect();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let func = FuncId::new(decl.symbol.raw());
            // Direct parent bucket.
            by_class.entry((decl.parent, file)).or_default().push(func);
            // Every base class bucket. Walk recursively so
            // `AuditedRepository` -> `Repository` -> `BaseRepository`
            // surfaces all three.
            if let Some(parent_sym) = decl.parent {
                let mut visited: ahash::AHashSet<SymbolId> = ahash::AHashSet::default();
                visited.insert(parent_sym);
                let mut frontier: Vec<SymbolId> = vec![parent_sym];
                while let Some(class_sym) = frontier.pop() {
                    let Some(class_decl) = global.decl_of(class_sym) else {
                        continue;
                    };
                    for base_name in &class_decl.bases {
                        let Some(&base_sym) = class_by_name.get(base_name.as_str()) else {
                            continue;
                        };
                        if !visited.insert(base_sym) {
                            continue;
                        }
                        by_class.entry((Some(base_sym), file)).or_default().push(func);
                        frontier.push(base_sym);
                    }
                }
            }
        }
    }
    // Sort keys for determinism (ws_node ids are positional).
    let mut sorted_keys: Vec<(Option<SymbolId>, bonsai_common::FileId)> = by_class.keys().copied().collect();
    sorted_keys.sort_by_key(|(p, f)| (p.map(|s| s.raw()).unwrap_or(u32::MAX), f.raw()));
    for key in sorted_keys {
        // Skip parent-less buckets entirely — module-level free
        // functions in the same file aren't peer methods of a
        // shared class and shouldn't share a field namespace. The
        // earlier "len < 2" relaxation was too loose: in Python
        // (`def top(): cmd = mid()`) it linked unrelated free
        // functions through bare-name reads. Field-flow only
        // makes sense when the adapter has a real class scope to
        // attach the field to.
        if key.0.is_none() {
            continue;
        }
        let funcs = by_class.get(&key).cloned().unwrap_or_default();
        let mut funcs = funcs;
        funcs.sort_by_key(|f| f.raw());
        // Cross-method bucketing recognises reads of bare names that
        // aren't in any constructor's FieldWrite list (locals
        // reassigned to instance state mid-method). Over-approximate
        // bucketing handles these cases without per-adapter coverage.
        let mut writes_by_field: ahash::AHashMap<String, Vec<(FuncId, crate::WsNodeId)>> =
            ahash::AHashMap::default();
        let mut reads_by_field: ahash::AHashMap<String, Vec<(FuncId, crate::WsNodeId)>> =
            ahash::AHashMap::default();
        for func in &funcs {
            collect_field_nodes(ws, *func, &mut writes_by_field, &mut reads_by_field);
        }
        // Property-getter return values that match a canonical
        // field name. C# / TypeScript / Python expose
        // `this._data.cmd` via a `cmd` property; the IDG models
        // the getter's body as `Place::Return`, but the consumer
        // site (`const c = this.cmd`) emits an Assign with a bare
        // `cmd` source_name — bridge_read falls through to the
        // shared `Place::Read{name="cmd"}` node and never reaches
        // the property's Return value. Stitch each peer-class
        // method whose name matches a field key onto its
        // Place::Return so the canonical-name bucket includes the
        // getter's output as an additional writer.
        for func in &funcs {
            let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
                continue;
            };
            let canonical = canonical_field_name(&decl.name);
            if canonical.is_empty() {
                continue;
            }
            let Some(seg_id) = ws.segment_for_func(*func) else {
                continue;
            };
            let Some(segment) = ws.segment(seg_id) else {
                continue;
            };
            let Some(pid) = segment.places.lookup(&crate::place::Place::Return) else {
                continue;
            };
            let Some(local) = segment.nodes.lookup(*func, pid) else {
                continue;
            };
            let Some(ws_node) = ws_node_for(ws, seg_id, local) else {
                continue;
            };
            let entry = writes_by_field.entry(canonical).or_default();
            if !entry.iter().any(|(of, on)| *of == *func && *on == ws_node) {
                entry.push((*func, ws_node));
            }
        }
        let mut field_keys: Vec<String> = writes_by_field
            .keys()
            .chain(reads_by_field.keys())
            .cloned()
            .collect();
        field_keys.sort();
        field_keys.dedup();

        for field in &field_keys {
            let writers = writes_by_field.get(field).cloned().unwrap_or_default();
            let readers = reads_by_field.get(field).cloned().unwrap_or_default();
            for (w_func, w_ws) in &writers {
                for (r_func, r_ws) in &readers {
                    if w_func == r_func {
                        // Same-method writer/reader — already wired
                        // through the per-function transfer pass's
                        // bridge_read fallback, no need to re-emit.
                        continue;
                    }
                    add_edge_between_ws_nodes(
                        ws,
                        *w_ws,
                        *r_ws,
                        IdgEdgeKind::IntraAssign,
                        bonsai_common::Precision::OverApproximate,
                    );
                    // Record the link so the query layer can lift
                    // it into a synthetic CrossCallEdge for the
                    // security-analysis lineage walk. Without this
                    // the IDG forward closure correctly reaches the
                    // reader's CallArg(sink) but the lineage can't
                    // attribute the chain to (writer, reader)
                    // because no cross-call edge with callee=reader
                    // ever appears in `call_records`. The synthetic
                    // edge fills that role with `arg_idx = u8::MAX`
                    // and `param_idx = u8::MAX` so it can't be
                    // confused with a real positional-arg edge.
                    let writer_span = ws_node_span(ws, *w_ws)
                        .unwrap_or_else(|| bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 0));
                    ws.field_flow_mut().push(crate::workspace::FieldFlowLink {
                        writer: *w_func,
                        reader: *r_func,
                        writer_ws_node: w_ws.0,
                        reader_ws_node: r_ws.0,
                        via_span: writer_span,
                    });
                }
            }
        }
    }
}

/// Resolve every `Place::Write{name, path: empty}` and
/// `Place::Read{name, path: empty}` ws_node in `func`'s segment
/// into the right field-name bucket. Sigil-stripped aliases (`@cmd`
/// → also bucketed under `cmd`, `$this->cmd` → `cmd`) collapse
/// language-specific instance-variable spelling into a shared
/// canonical name so a Ruby `@cmd = X` writer matches a Python
/// `self.cmd` reader's bare-field bucket when they live in peer
/// methods of the same class.
fn collect_field_nodes(
    ws: &IdgWorkspace,
    func: FuncId,
    writes_by_field: &mut ahash::AHashMap<String, Vec<(FuncId, crate::WsNodeId)>>,
    reads_by_field: &mut ahash::AHashMap<String, Vec<(FuncId, crate::WsNodeId)>>,
) {
    use crate::place::Place;
    let Some(seg_id) = ws.segment_for_func(func) else {
        return;
    };
    let Some(segment) = ws.segment(seg_id) else {
        return;
    };
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        // Three place shapes contribute to field flow:
        //   * `Place::Write { name, path: [] }` where `name` is
        //     sigil'd (`@cmd`, `$cmd`) or qualified (`self.cmd`).
        //     Bare locals fall through.
        //   * `Place::Write { name = "self"/"this"/etc, path = ["field", ..] }`
        //     — `this.cmd = X` style assignments. Canonical key is
        //     the FIRST path segment.
        //   * `Place::Read { name, path: [] }` — accepts both
        //     sigil'd and bare names because adapters tokenise
        //     receiver-field reads inconsistently. Bare-tail reads
        //     only pair with sigil'd / qualified writes via the
        //     canonical key at edge-emit time.
        let (is_write, canonical) = match place {
            Place::Write { name, path, .. } if path.is_empty() => {
                // Accept bare-name Writes in any class-grouped
                // method as potential field writes — adapters spell
                // class fields differently across languages
                // (Ruby `@cmd`, Python `self.cmd`, C# `Data`,
                // Java `this.data`), and pre-filtering on sigil
                // shape locks out PascalCase / camelCase fields
                // (C#, Java property style). Edges only emit when
                // a peer method reads the same canonical key, so
                // a local variable named `a` in method-A only
                // generates a synthetic edge if method-B also
                // reads `a` — the over-approximation that
                // introduces is dwarfed by the under-approximation
                // of skipping every PascalCase field write.
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                (true, canonical_field_name(s))
            }
            Place::Write { name, path, .. } if !path.is_empty() => {
                // Qualified writes (`this.cmd = X`, `self.cmd = X`)
                // canonicalize to the first path segment so peer
                // methods reading bare `cmd` match.
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                if !is_implicit_receiver_name(s) {
                    continue;
                }
                let head_id = path[0];
                let Some(head) = segment.strings.get(head_id) else {
                    continue;
                };
                (true, head.to_string())
            }
            Place::Read { name, path } if path.is_empty() => {
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                (false, canonical_field_name(s))
            }
            _ => continue,
        };
        if canonical.is_empty() {
            continue;
        }
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(local) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        let Some(ws_node) = ws_node_for(ws, seg_id, local) else {
            continue;
        };
        if is_write {
            writes_by_field
                .entry(canonical)
                .or_default()
                .push((func, ws_node));
        } else {
            reads_by_field.entry(canonical).or_default().push((func, ws_node));
        }
    }
}

/// Resolve a segment-local `(SegmentId, crate::node::NodeId)` to its workspace
/// `Wscrate::node::NodeId` via the IDG service's unified address space.
/// Implemented inline because the workspace doesn't itself expose
/// the unified map — only [`IdgQueryService`] does, and the
/// adapter runs before service construction. Falls through to the
/// segment's nodes vector to recover the workspace position.
fn ws_node_for(
    ws: &IdgWorkspace,
    seg_id: crate::SegmentId,
    local: crate::node::NodeId,
) -> Option<crate::WsNodeId> {
    // Walk segments in order, summing counts up to seg_id, and
    // adding the local node index. Mirrors `build_unified` in
    // [`IdgQueryService`] — both must agree on the address-space
    // layout.
    let mut offset: u32 = 0;
    for (other_id, other_seg) in ws.segments() {
        if other_id == seg_id {
            return Some(crate::WsNodeId(offset + local.0));
        }
        offset = offset.saturating_add(other_seg.nodes.len() as u32);
    }
    None
}

/// True when `name` is one of the language-specific implicit
/// receivers used in qualified field writes (`this.cmd = X`,
/// `self.cmd = X`). Lets the field-flow stitcher recognize the
/// `Place::Write { name = "this", path = ["cmd"] }` shape and
/// canonicalize it onto the bare `cmd` field key.
fn is_implicit_receiver_name(name: &str) -> bool {
    matches!(name.trim(), "self" | "this" | "$this" | "Self")
}

/// Strip language-specific sigils and receiver prefixes off a
/// field name so peer methods spelling the same field differently
/// (Ruby `@cmd` vs Python `self.cmd` vs PHP `$this->cmd`) all
/// bucket into the same canonical key.
fn canonical_field_name(name: &str) -> String {
    let mut s = name.trim();
    if let Some(rest) = s.strip_prefix("@@") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix('@') {
        s = rest;
    } else if let Some(rest) = s.strip_prefix('$') {
        s = rest;
    } else if let Some(rest) = s.strip_prefix('&') {
        s = rest;
    }
    if let Some(rest) = s.strip_prefix("self.") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("this.") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("$this->") {
        s = rest;
    }
    s.to_string()
}

/// Push a new IDG edge from `from` to `to` (workspace ids). Routes
/// the edge through the segment's intra-edge list when both
/// endpoints share a segment, else through the workspace's
/// cross-file index. Mirrors `place_inter_edge` in builder.rs;
/// duplicated here because the field-flow stitcher runs after
/// `stitch_idg` returns and operates on workspace ids rather than
/// segment-local crate::node::NodeIds.
fn add_edge_between_ws_nodes(
    ws: &mut IdgWorkspace,
    from: crate::WsNodeId,
    to: crate::WsNodeId,
    kind: crate::edge::IdgEdgeKind,
    precision: bonsai_common::Precision,
) {
    let Some((from_seg, from_local)) = ws_node_to_local(ws, from) else {
        return;
    };
    let Some((to_seg, to_local)) = ws_node_to_local(ws, to) else {
        return;
    };
    let edge = crate::edge::IdgEdge {
        from: from_local,
        to: to_local,
        meta: crate::edge::EdgeMeta {
            precision,
            kind,
            call_kind: bonsai_callgraph::EdgeKind::Indirect,
            via_span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 0),
        },
    };
    if from_seg == to_seg {
        if let Some(seg) = ws.segment_mut(from_seg) {
            seg.add_edge(edge);
        }
    } else {
        ws.cross_file_mut().push(crate::workspace::CrossFileEdge {
            from_segment: from_seg,
            to_segment: to_seg,
            edge,
        });
    }
}

/// Resolve the source-span of the `Place` behind `ws_node`. Used
/// by the field-flow stitcher to attribute the synthetic
/// CrossCallEdge to the writer's assignment site, so the
/// downstream lineage `via_span` reads coherently in find rendering.
fn ws_node_span(ws: &IdgWorkspace, ws_node: crate::WsNodeId) -> Option<bonsai_common::Span> {
    use crate::place::Place;
    let (seg_id, local) = ws_node_to_local(ws, ws_node)?;
    let segment = ws.segment(seg_id)?;
    let node = segment.nodes.get(local)?;
    let place = segment.places.places.get(node.place.0 as usize)?;
    match place {
        Place::Write { span, .. } => Some(*span),
        Place::CallArg { site, .. } | Place::CallRet { site } => Some(site.0),
        _ => None,
    }
}

/// Reverse [`ws_node_for`] — given a workspace `WsNodeId`, find
/// the (segment, local) pair it lives in. Walks segments in order
/// and subtracts each segment's node count until the offset
/// places `ws_node` within the current segment.
fn ws_node_to_local(
    ws: &IdgWorkspace,
    ws_node: crate::WsNodeId,
) -> Option<(crate::SegmentId, crate::node::NodeId)> {
    let mut remaining = ws_node.0;
    for (seg_id, segment) in ws.segments() {
        let count = segment.nodes.len() as u32;
        if remaining < count {
            return Some((seg_id, crate::node::NodeId(remaining)));
        }
        remaining = remaining.saturating_sub(count);
    }
    None
}

/// Run the transfer pass on every function in the workspace, in
/// parallel. Each function's transfer is independent (it only
/// reads its own `Decl`), so this is embarrassingly parallel via
/// rayon.
fn run_transfer_in_parallel(global: &GlobalIndex) -> Vec<TransferOutput> {
    // Collect every (FileId, decl-index) pair so rayon can split
    // them across threads. Each transfer call produces a
    // `TransferOutput` with its own embedded name pool — the
    // segment merge re-interns names into the segment-level pool,
    // so per-call name spaces don't conflict.
    let mut funcs: Vec<(FileId, &bonsai_lang_api::Decl)> = Vec::new();
    for file in global.all_files() {
        for decl in global.functions_in(file) {
            funcs.push((file, decl));
        }
    }
    funcs
        .into_par_iter()
        .map(|(_file, decl)| transfer_function_for(decl))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::AHashMap;
    use bonsai_common::{Span, SymbolId};
    use bonsai_lang_api::{Decl, DeclKind, FlowEvent, ModulePath, Visibility};

    fn span(file: u32, start: u64, end: u64) -> Span {
        Span::new(FileId::new(file), start, end)
    }

    fn empty_decl(symbol: u32, file: u32, name: &str) -> Decl {
        Decl {
            symbol: SymbolId::new(symbol),
            kind: DeclKind::Function,
            name: name.to_string(),
            qualified_name: None,
            module_path: ModulePath::default(),
            span: span(file, 0, 100),
            name_span: span(file, 0, 10),
            visibility: Visibility::Public,
            parent: None,
            body_span: Some(span(file, 10, 100)),
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
        }
    }

    fn build_index(decls: Vec<Decl>) -> GlobalIndex {
        // Group decls by their file id, build one `DeclIndex` per
        // file, and insert all of them. `GlobalIndex::insert` is
        // per-file, not per-decl.
        let mut by_file: AHashMap<FileId, Vec<Decl>> = AHashMap::new();
        for d in decls {
            by_file.entry(d.span.file).or_default().push(d);
        }
        let mut idx = GlobalIndex::new();
        for (file, defs) in by_file {
            idx.insert(bonsai_lang_api::DeclIndex {
                file,
                defs,
                refs: Vec::new(),
                strings: Vec::new(),
                comments: Vec::new(),
            });
        }
        idx
    }

    #[test]
    fn empty_workspace_produces_empty_idg() {
        let idx = GlobalIndex::new();
        let cg = ResolvedCallGraph::default();
        let ws = build(&idx, &cg);
        assert_eq!(ws.segment_count(), 0);
    }

    #[test]
    fn one_function_one_file_yields_one_segment() {
        let mut decl = empty_decl(1, 0, "f");
        decl.params = vec!["x".to_string()];
        let idx = build_index(vec![decl]);
        let cg = ResolvedCallGraph::default();
        let ws = build(&idx, &cg);
        assert_eq!(ws.segment_count(), 1);
        // GlobalIndex remaps SymbolId on insert, so the FuncId
        // we look up is the post-remap one (0 — first symbol
        // inserted into a fresh GlobalIndex).
        assert!(ws.segment_for_func(FuncId::new(0)).is_some());
    }

    #[test]
    fn two_files_with_call_creates_cross_file_edges_when_callgraph_resolves() {
        // file 0: f calls g
        let mut f = empty_decl(1, 0, "f");
        f.flow_events = vec![FlowEvent::Call {
            span: span(0, 20, 30),
            name: "g".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![bonsai_lang_api::CallArg {
                span: span(0, 22, 23),
                name: None,
                value_text: "x".to_string(),
                place: Some("x".to_string()),
                source_names: Vec::new(),
            }],
        }];
        // file 1: g(arg) returns arg
        let mut g = empty_decl(2, 1, "g");
        g.params = vec!["arg".to_string()];
        g.flow_events = vec![FlowEvent::Return {
            span: span(1, 50, 60),
            value_name: Some("arg".to_string()),
            value_text: None,
        }];

        let idx = build_index(vec![f, g]);
        // Build a real ResolvedCallGraph by walking the flow
        // events. The resolver finds the call to "g" and emits
        // an edge — that's what production code does too.
        let cg = ResolvedCallGraph::build_with(&idx, |_| AHashMap::new());

        let ws = build(&idx, &cg);
        assert_eq!(ws.segment_count(), 2);
        // Two cross-file edges: CallArg→Param, Return→CallRet.
        assert_eq!(ws.cross_file().len(), 2);
    }

    #[test]
    fn unresolved_call_skipped_silently() {
        let mut f = empty_decl(1, 0, "f");
        f.flow_events = vec![FlowEvent::Call {
            span: span(0, 20, 30),
            name: "missing".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: Vec::new(),
        }];
        let idx = build_index(vec![f]);
        let cg = ResolvedCallGraph::default();
        let ws = build(&idx, &cg);
        assert_eq!(ws.segment_count(), 1);
        assert!(ws.cross_file().is_empty());
    }
}
