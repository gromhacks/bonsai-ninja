//! Phase 3b: workspace adapter that wires the [`crate::builder::stitch_idg`]
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
//! [`crate::builder::stitch_idg`] core from this code, so unit tests still don't
//! need a workspace.

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{callable_reference_variants, FileId, FuncId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{FlowEvent, ModulePath};
use parking_lot::RwLock;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{path::Path, time::Instant};

use crate::builder::{
    stitch_idg_with_selective_field_forwarding_mode, CalleeResolver, FuncToSegment, ResolvedCallee,
};
use crate::transfer::{
    declared_receiver_names, receiver_name_matches, transfer_function_for_with_options, TransferOptions,
    TransferOutput,
};
use crate::workspace::{IdgWorkspace, SegmentId};

type FieldReadNodesByFunc = AHashMap<FuncId, AHashMap<String, Vec<crate::WsNodeId>>>;
type RecvNodesByFunc = AHashMap<FuncId, Vec<crate::WsNodeId>>;
type RecvSlot = (crate::WsNodeId, Option<crate::WsNodeId>);
type RecvSlotsByCall = AHashMap<(FuncId, bonsai_common::Span), Vec<RecvSlot>>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum LocalScopeKey {
    Module(ModulePath),
    Directory(String),
    File(FileId),
}

impl LocalScopeKey {
    fn has_project_boundary(&self) -> bool {
        matches!(self, Self::Module(_) | Self::Directory(_))
    }
}

/// Pre-computed maps that `WorkspaceIdgBuilder` uses for
/// `FuncId → file → SegmentId` lookups during stitching.
struct WorkspaceMaps {
    /// `FuncId → SegmentId placeholder`. The placeholder maps 1:1
    /// to a file id (one segment per file). [`crate::builder::stitch_idg`] then
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
    /// `FuncId → language id` for production workspaces. Synthetic
    /// tests that do not provide language metadata leave entries
    /// absent, and the resolver then keeps legacy permissive behavior.
    func_to_language: AHashMap<FuncId, &'static str>,
    /// Callback binding lookup: stripped callback argument name /
    /// declared-name tail → candidate functions.
    funcs_by_callback_name: AHashMap<String, Vec<FuncId>>,
    /// Scoped callback binding lookup by module path. Used before the
    /// global name bucket so copied packages with identical helper
    /// names do not cross-wire callbacks.
    funcs_by_callback_name_module: AHashMap<(String, ModulePath), Vec<FuncId>>,
    /// Scoped callback binding lookup by source directory. This is the
    /// fallback when adapters have no module path but the workspace VFS
    /// can still identify a local project/package directory.
    funcs_by_callback_name_directory: AHashMap<(String, String), Vec<FuncId>>,
    /// Scoped callback binding lookup by file. This preserves precise
    /// single-file callback flows when neither module nor directory
    /// metadata is available.
    funcs_by_callback_name_file: AHashMap<(String, FileId), Vec<FuncId>>,
    func_to_module: AHashMap<FuncId, ModulePath>,
    func_to_directory: AHashMap<FuncId, String>,
    func_to_file: AHashMap<FuncId, FileId>,
    func_to_scope: AHashMap<FuncId, LocalScopeKey>,
    symbol_to_scope: AHashMap<bonsai_common::SymbolId, LocalScopeKey>,
    /// Source directory for every declaration symbol. A declaration may
    /// use a module scope (for example a PHP namespace or Python module),
    /// but its imported base class can still live in the same project
    /// directory under a different module scope. This secondary key lets
    /// inheritance lookup make that narrow cross-module hop without
    /// falling back to every same-named class in the workspace.
    symbol_to_directory: AHashMap<bonsai_common::SymbolId, String>,
    /// `FileId → language id`, used for class/constructor fallback
    /// where the candidate is still a `SymbolId` rather than a
    /// `FuncId`.
    file_to_language: AHashMap<FileId, &'static str>,
}

impl WorkspaceMaps {
    fn build_with_languages_for_files<F>(
        global: &GlobalIndex,
        language_for_file: F,
        path_for_file: &dyn Fn(FileId) -> Option<String>,
        included_files: Option<&AHashSet<FileId>>,
        included_funcs: Option<&AHashSet<FuncId>>,
    ) -> Self
    where
        F: Fn(FileId) -> Option<&'static str>,
    {
        let mut func_to_seg: AHashMap<FuncId, SegmentId> = AHashMap::new();
        let mut func_to_name: AHashMap<FuncId, String> = AHashMap::new();
        let mut func_to_language: AHashMap<FuncId, &'static str> = AHashMap::new();
        let mut funcs_by_callback_name: AHashMap<String, Vec<FuncId>> = AHashMap::new();
        let mut funcs_by_callback_name_module: AHashMap<(String, ModulePath), Vec<FuncId>> = AHashMap::new();
        let mut funcs_by_callback_name_directory: AHashMap<(String, String), Vec<FuncId>> = AHashMap::new();
        let mut funcs_by_callback_name_file: AHashMap<(String, FileId), Vec<FuncId>> = AHashMap::new();
        let mut func_to_module: AHashMap<FuncId, ModulePath> = AHashMap::new();
        let mut func_to_directory: AHashMap<FuncId, String> = AHashMap::new();
        let mut func_to_file: AHashMap<FuncId, FileId> = AHashMap::new();
        let mut func_to_scope: AHashMap<FuncId, LocalScopeKey> = AHashMap::new();
        let mut symbol_to_scope: AHashMap<bonsai_common::SymbolId, LocalScopeKey> = AHashMap::new();
        let mut symbol_to_directory: AHashMap<bonsai_common::SymbolId, String> = AHashMap::new();
        let mut file_to_language: AHashMap<FileId, &'static str> = AHashMap::new();
        let mut file_to_seg: AHashMap<FileId, SegmentId> = AHashMap::new();
        let mut next_seg = 0u32;
        for file in global.all_files() {
            if included_files.is_some_and(|files| !files.contains(&file)) {
                continue;
            }
            let language = language_for_file(file);
            let file_directory = path_for_file(file).and_then(|path| parent_dir_key(path.as_str()));
            if let Some(language) = language {
                file_to_language.insert(file, language);
            }
            let seg = SegmentId(next_seg);
            next_seg = next_seg.wrapping_add(1);
            file_to_seg.insert(file, seg);
            for decl in global.decls_in(file) {
                symbol_to_scope.insert(
                    decl.symbol,
                    local_scope_key_for_decl(file, decl, file_directory.as_deref()),
                );
                if let Some(directory) = &file_directory {
                    symbol_to_directory.insert(decl.symbol, directory.clone());
                }
            }
            for decl in global.functions_in(file) {
                let func = FuncId::new(decl.symbol.raw());
                if included_funcs.is_some_and(|funcs| !funcs.contains(&func)) {
                    continue;
                }
                func_to_seg.insert(func, seg);
                func_to_name.insert(func, decl.name.clone());
                func_to_module.insert(func, decl.module_path.clone());
                func_to_file.insert(func, file);
                func_to_scope.insert(
                    func,
                    local_scope_key_for_decl(file, decl, file_directory.as_deref()),
                );
                if let Some(directory) = &file_directory {
                    func_to_directory.insert(func, directory.clone());
                }
                add_callback_name_index_entries(
                    &mut funcs_by_callback_name,
                    &mut funcs_by_callback_name_module,
                    &mut funcs_by_callback_name_directory,
                    &mut funcs_by_callback_name_file,
                    func,
                    &decl.name,
                    &decl.module_path,
                    file_directory.as_deref(),
                    file,
                );
                if let Some(language) = language {
                    func_to_language.insert(func, language);
                }
            }
        }
        Self {
            func_to_seg,
            func_to_name,
            func_to_language,
            funcs_by_callback_name,
            funcs_by_callback_name_module,
            funcs_by_callback_name_directory,
            funcs_by_callback_name_file,
            func_to_module,
            func_to_directory,
            func_to_file,
            func_to_scope,
            symbol_to_scope,
            symbol_to_directory,
            file_to_language,
        }
    }
}

fn local_scope_key_for_decl(
    file: FileId,
    decl: &bonsai_lang_api::Decl,
    directory: Option<&str>,
) -> LocalScopeKey {
    if !decl.module_path.is_empty() {
        return LocalScopeKey::Module(decl.module_path.clone());
    }
    if let Some(directory) = directory {
        return LocalScopeKey::Directory(directory.to_string());
    }
    LocalScopeKey::File(file)
}

#[allow(clippy::too_many_arguments)]
fn add_callback_name_index_entries(
    index: &mut AHashMap<String, Vec<FuncId>>,
    module_index: &mut AHashMap<(String, ModulePath), Vec<FuncId>>,
    directory_index: &mut AHashMap<(String, String), Vec<FuncId>>,
    file_index: &mut AHashMap<(String, FileId), Vec<FuncId>>,
    func: FuncId,
    decl_name: &str,
    module_path: &ModulePath,
    directory: Option<&str>,
    file: FileId,
) {
    add_callback_name_index_entry(
        index,
        module_index,
        directory_index,
        file_index,
        func,
        decl_name,
        module_path,
        directory,
        file,
    );
    if let Some((_, tail)) = decl_name.rsplit_once(['.', ':']) {
        add_callback_name_index_entry(
            index,
            module_index,
            directory_index,
            file_index,
            func,
            tail,
            module_path,
            directory,
            file,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_callback_name_index_entry(
    index: &mut AHashMap<String, Vec<FuncId>>,
    module_index: &mut AHashMap<(String, ModulePath), Vec<FuncId>>,
    directory_index: &mut AHashMap<(String, String), Vec<FuncId>>,
    file_index: &mut AHashMap<(String, FileId), Vec<FuncId>>,
    func: FuncId,
    name: &str,
    module_path: &ModulePath,
    directory: Option<&str>,
    file: FileId,
) {
    let name = name.trim();
    if name.is_empty() {
        return;
    }
    let name = name.to_string();
    let funcs = index.entry(name.to_string()).or_default();
    if !funcs.contains(&func) {
        funcs.push(func);
    }
    if !module_path.is_empty() {
        let funcs = module_index
            .entry((name.clone(), module_path.clone()))
            .or_default();
        if !funcs.contains(&func) {
            funcs.push(func);
        }
    }
    if let Some(directory) = directory {
        let funcs = directory_index
            .entry((name.clone(), directory.to_string()))
            .or_default();
        if !funcs.contains(&func) {
            funcs.push(func);
        }
    }
    let funcs = file_index.entry((name, file)).or_default();
    if !funcs.contains(&func) {
        funcs.push(func);
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
    func_to_language: &'a AHashMap<FuncId, &'static str>,
    funcs_by_callback_name: &'a AHashMap<String, Vec<FuncId>>,
    funcs_by_callback_name_module: &'a AHashMap<(String, ModulePath), Vec<FuncId>>,
    funcs_by_callback_name_directory: &'a AHashMap<(String, String), Vec<FuncId>>,
    funcs_by_callback_name_file: &'a AHashMap<(String, FileId), Vec<FuncId>>,
    func_to_module: &'a AHashMap<FuncId, ModulePath>,
    func_to_directory: &'a AHashMap<FuncId, String>,
    func_to_file: &'a AHashMap<FuncId, FileId>,
    func_to_scope: &'a AHashMap<FuncId, LocalScopeKey>,
    symbol_to_scope: &'a AHashMap<bonsai_common::SymbolId, LocalScopeKey>,
    symbol_to_directory: &'a AHashMap<bonsai_common::SymbolId, String>,
    call_edges_by_site: &'a AHashMap<CallSiteEdgeKey, Vec<IndexedCallEdge>>,
    file_to_language: &'a AHashMap<FileId, &'static str>,
    class_symbols_by_name: &'a AHashMap<String, Vec<bonsai_common::SymbolId>>,
    class_symbols_by_name_scope: &'a AHashMap<(String, LocalScopeKey), Vec<bonsai_common::SymbolId>>,
    /// Type declarations addressed by an import's local binding in a
    /// particular caller file. This is the class/type counterpart of
    /// `func_to_call_names`: it lets expression-oriented grammars resolve
    /// `ImportedClass(args)` from import symbols instead of guessing from
    /// call spelling.
    class_symbols_by_import_alias_file: &'a AHashMap<(FileId, String), Vec<bonsai_common::SymbolId>>,
    class_constructors_by_parent: &'a AHashMap<bonsai_common::SymbolId, Vec<FuncId>>,
    class_methods_by_parent: &'a AHashMap<bonsai_common::SymbolId, Vec<FuncId>>,
    /// Per-caller local callable bindings (`let f = <lambda/function>`),
    /// keyed caller → binding name → bound FuncId. Lets `resolve` connect
    /// invocation-shaped calls on a locally-bound callable — `f(args)`,
    /// `f.accept(args)`, `f.call(args)`, `f.(args)` — to the bound
    /// function when no callgraph edge exists at the site. The legacy
    /// the compatibility API historically resolved these through a local-binding scan;
    /// without this fallback, lambda bodies are unreachable for adapters
    /// whose functional-invocation forms the callgraph doesn't model.
    local_callable_bindings: &'a AHashMap<FuncId, AHashMap<String, FuncId>>,
    callback_cache: RwLock<AHashMap<(FuncId, u32), Vec<ResolvedCallee>>>,
    ancestor_dispatch_cache: RwLock<AHashMap<(FuncId, FuncId), bool>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct CallSiteEdgeKey {
    caller: FuncId,
    site: bonsai_common::Span,
}

#[derive(Clone, Copy, Debug)]
struct IndexedCallEdge {
    to: FuncId,
    edge_kind: bonsai_callgraph::EdgeKind,
    precision: bonsai_common::Precision,
}

fn call_edges_by_site_for_funcs(
    call_graph: &ResolvedCallGraph,
    global: &GlobalIndex,
    included_funcs: Option<&AHashSet<FuncId>>,
) -> AHashMap<CallSiteEdgeKey, Vec<IndexedCallEdge>> {
    let mut out: AHashMap<CallSiteEdgeKey, Vec<IndexedCallEdge>> = AHashMap::new();
    for edge in &call_graph.inner().edges {
        if included_funcs.is_some_and(|funcs| !funcs.contains(&edge.from) || !funcs.contains(&edge.to)) {
            continue;
        }
        let indexed = IndexedCallEdge {
            to: edge.to,
            edge_kind: edge.kind,
            precision: edge.precision,
        };
        push_call_edge_site(&mut out, edge.from, edge.span, indexed);
        if let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(edge.from.raw())) {
            for call_span in call_event_spans_matching_edge(&decl.flow_events, edge.span) {
                push_call_edge_site(&mut out, edge.from, call_span, indexed);
            }
        }
    }
    out
}

fn push_call_edge_site(
    out: &mut AHashMap<CallSiteEdgeKey, Vec<IndexedCallEdge>>,
    caller: FuncId,
    site: bonsai_common::Span,
    edge: IndexedCallEdge,
) {
    let rows = out.entry(CallSiteEdgeKey { caller, site }).or_default();
    if !rows.iter().any(|existing| {
        existing.to == edge.to && existing.edge_kind == edge.edge_kind && existing.precision == edge.precision
    }) {
        rows.push(edge);
    }
}

fn call_event_spans_matching_edge(
    events: &[FlowEvent],
    edge_span: bonsai_common::Span,
) -> Vec<bonsai_common::Span> {
    let mut out = Vec::new();
    // Prefer a call event whose own syntax span matches the callgraph edge.
    // Only fall back to an argument span when no such nested/outer call exists.
    // Otherwise an edge for `factory()` inside `host(factory())` is indexed on
    // both calls merely because the outer argument contains the inner span,
    // and the IDG mistakes the factory for the host's resolved callee.
    collect_call_event_spans_matching_edge(events, edge_span, false, &mut out);
    if out.is_empty() {
        collect_call_event_spans_matching_edge(events, edge_span, true, &mut out);
    }
    out.sort_by_key(|span| (span.file.raw(), span.start, span.end));
    out.dedup();
    out
}

fn collect_call_event_spans_matching_edge(
    events: &[FlowEvent],
    edge_span: bonsai_common::Span,
    include_arg_spans: bool,
    out: &mut Vec<bonsai_common::Span>,
) {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if call_site_spans_match(edge_span, *span)
                    || (include_arg_spans
                        && args.iter().any(|arg| call_site_spans_match(edge_span, arg.span)))
                {
                    out.push(*span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_call_event_spans_matching_edge(then_events, edge_span, include_arg_spans, out);
                collect_call_event_spans_matching_edge(else_events, edge_span, include_arg_spans, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_call_event_spans_matching_edge(body, edge_span, include_arg_spans, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_call_event_spans_matching_edge(body, edge_span, include_arg_spans, out);
                collect_call_event_spans_matching_edge(catch_events, edge_span, include_arg_spans, out);
                collect_call_event_spans_matching_edge(finally_events, edge_span, include_arg_spans, out);
            }
            _ => {}
        }
    }
}

impl<'a> CalleeResolver for WorkspaceCalleeResolver<'a> {
    fn resolve(
        &self,
        caller: FuncId,
        site: bonsai_common::Span,
        callee_name: &str,
        receiver: Option<&str>,
        receiver_types: &[String],
        call_kind: bonsai_lang_api::CallKind,
    ) -> Vec<ResolvedCallee> {
        let mut out = Vec::new();
        let mut seen: ahash::AHashSet<(FuncId, bonsai_callgraph::EdgeKind, bonsai_common::Precision)> =
            ahash::AHashSet::default();
        let exact_key = CallSiteEdgeKey { caller, site };
        if let Some(edges) = self.call_edges_by_site.get(&exact_key) {
            for edge in edges {
                if !edge.precision.is_semantic() {
                    continue;
                }
                if !self.funcs_share_language(caller, edge.to) {
                    continue;
                }
                // Direct/virtual/constructor edges are the compiler-resolved
                // target of this exact call site, even when aliases make the
                // source spelling differ from the declaration. An Indirect
                // edge can instead be a higher-order callable-argument edge
                // attached to the host call (`xs.reduce(callback, init)` ->
                // `callback`). That edge describes a callback invocation, not
                // the host call's own return semantics. Admit it here only
                // when its target still matches the syntactic callee; local
                // callable bindings and callback parameters are resolved by
                // the dedicated fallbacks below.
                if edge.edge_kind == bonsai_callgraph::EdgeKind::Indirect {
                    self.push_resolved_edge_if_name_matches(
                        &mut out,
                        &mut seen,
                        edge.to,
                        edge.edge_kind,
                        edge.precision,
                        callee_name,
                    );
                } else {
                    Self::push_resolved_edge(&mut out, &mut seen, edge.to, edge.edge_kind, edge.precision);
                }
            }
        } else {
            for edge in self.call_graph.callees_of(caller) {
                if !call_site_spans_match(edge.span, site) {
                    continue;
                }
                if !edge.precision.is_semantic() {
                    continue;
                }
                if !self.funcs_share_language(caller, edge.to) {
                    continue;
                }
                if edge.kind == bonsai_callgraph::EdgeKind::Indirect {
                    Self::push_resolved_edge(&mut out, &mut seen, edge.to, edge.kind, edge.precision);
                } else {
                    self.push_resolved_edge_if_name_matches(
                        &mut out,
                        &mut seen,
                        edge.to,
                        edge.kind,
                        edge.precision,
                        callee_name,
                    );
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
        if out.is_empty()
            && self.call_site_denotes_declared_class(caller, callee_name, receiver, receiver_types, call_kind)
        {
            self.resolve_class_constructor_fallback(caller, callee_name, receiver, receiver_types, &mut out);
        }
        // Adapter-derived receiver types can identify methods inherited
        // from a class declared in another file even when the callgraph has
        // no direct edge. Walk only that type's declared base chain; no
        // constructor or API spelling is interpreted here.
        if out.is_empty() {
            self.resolve_typed_receiver_method_fallback(caller, callee_name, receiver_types, &mut out);
        }
        // Local-callable-binding fallback: `let f = <lambda>` then
        // `f(args)` / `f.accept(args)` / `f.call(args)` / `f.(args)`.
        // The callgraph models these for some adapters but not all
        // functional-invocation forms; when nothing else resolved and
        // the receiver (method form) or the bare callee name (direct
        // form) is a local callable binding of this caller, route to
        // the bound function. Indirect + Narrowed mirrors how the
        // callgraph classifies value-typed dispatch.
        if out.is_empty() {
            if let Some(bindings) = self.local_callable_bindings.get(&caller) {
                // Elixir/Erlang dot-call `f.(args)` reaches here as
                // `callee_name = "f."` with no receiver; strip the trailing
                // dot/parens (mirrors builder.rs:1056) so `f.` looks up the
                // binding `f`. The `.`/`:` guard then only rejects genuinely
                // qualified names (`mod.fun`, `Mod::fun`).
                let stripped_callee = callee_name.trim().trim_end_matches(['.', '(', ')']);
                let binding_name = receiver
                    .map(str::trim)
                    .filter(|receiver| !receiver.is_empty())
                    .or_else(|| {
                        (!stripped_callee.is_empty()
                            && !stripped_callee.contains(['.', ':'])
                            && !stripped_callee.contains("->"))
                        .then_some(stripped_callee)
                    });
                if let Some(name) = binding_name {
                    if let Some(&func) = bindings.get(name) {
                        if self.funcs_share_language(caller, func) {
                            Self::push_resolved_edge(
                                &mut out,
                                &mut seen,
                                func,
                                bonsai_callgraph::EdgeKind::Indirect,
                                bonsai_common::Precision::Narrowed,
                            );
                        }
                    }
                }
            }
        }
        out
    }

    fn callback_bindings(&self, host: FuncId, param_idx: u32) -> Vec<ResolvedCallee> {
        self.callback_bindings_indexed(host, param_idx)
    }

    fn callable_arg(&self, caller: FuncId, arg_text: &str) -> Vec<ResolvedCallee> {
        let mut out = Vec::new();
        let mut seen = ahash::AHashSet::new();
        for bound_name in callable_reference_variants(arg_text) {
            for candidate_func in self.callback_candidate_funcs_for_bound_name(&bound_name, caller, caller) {
                if !self.funcs_share_language(caller, candidate_func) {
                    continue;
                }
                if seen.insert(candidate_func) {
                    out.push(ResolvedCallee {
                        func: candidate_func,
                        edge_kind: bonsai_callgraph::EdgeKind::Indirect,
                        precision: bonsai_common::Precision::Narrowed,
                    });
                }
            }
        }
        out
    }

    fn callable_args_in_span(&self, caller: FuncId, arg_span: bonsai_common::Span) -> Vec<ResolvedCallee> {
        let mut out = Vec::new();
        let mut seen = ahash::AHashSet::new();
        for edge in self.call_graph.callees_of(caller) {
            if edge.kind != bonsai_callgraph::EdgeKind::Indirect
                || edge.span.file != arg_span.file
                || edge.span.start < arg_span.start
                || edge.span.end > arg_span.end
                || !edge.precision.is_semantic()
                || !self.funcs_share_language(caller, edge.to)
            {
                continue;
            }
            Self::push_resolved_edge(&mut out, &mut seen, edge.to, edge.kind, edge.precision);
        }
        out
    }

    fn receiver_type_for(&self, func: FuncId) -> Option<String> {
        let decl = self.global.decl_of(bonsai_common::SymbolId::new(func.raw()))?;
        let parent = decl.parent?;
        self.global.decl_of(parent).map(|decl| decl.name.clone())
    }

    fn is_constructor_func(&self, func: FuncId) -> bool {
        use bonsai_lang_api::DeclKind;
        let Some(decl) = self.global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
            return false;
        };
        matches!(decl.kind, DeclKind::Constructor)
    }

    fn is_ancestor_dispatch(&self, caller: FuncId, callee: FuncId) -> bool {
        let key = (caller, callee);
        if let Some(cached) = self.ancestor_dispatch_cache.read().get(&key).copied() {
            return cached;
        }
        let result = self.callee_parent_is_declared_ancestor(caller, callee);
        self.ancestor_dispatch_cache.write().insert(key, result);
        result
    }

    fn is_local_callable_binding(&self, caller: FuncId, callee: FuncId) -> bool {
        self.local_callable_bindings
            .get(&caller)
            .is_some_and(|bindings| bindings.values().any(|bound| *bound == callee))
    }
}

impl WorkspaceCalleeResolver<'_> {
    fn callee_parent_is_declared_ancestor(&self, caller: FuncId, callee: FuncId) -> bool {
        let Some(caller_parent) = self
            .global
            .decl_of(bonsai_common::SymbolId::new(caller.raw()))
            .and_then(|decl| decl.parent)
        else {
            return false;
        };
        let Some(callee_parent) = self
            .global
            .decl_of(bonsai_common::SymbolId::new(callee.raw()))
            .and_then(|decl| decl.parent)
        else {
            return false;
        };
        if caller_parent == callee_parent || !self.funcs_share_language(caller, callee) {
            return false;
        }

        let mut visited = ahash::AHashSet::default();
        let mut ancestors = vec![caller_parent];
        while let Some(class_symbol) = ancestors.pop() {
            if !visited.insert(class_symbol) {
                continue;
            }
            let Some(class_decl) = self.global.decl_of(class_symbol) else {
                continue;
            };
            for base_name in &class_decl.bases {
                for base_symbol in self.class_candidates_for_ancestry(class_symbol, base_name) {
                    if base_symbol == callee_parent {
                        return true;
                    }
                    if !visited.contains(&base_symbol) {
                        ancestors.push(base_symbol);
                    }
                }
            }
        }
        false
    }

    fn push_resolved_edge(
        out: &mut Vec<ResolvedCallee>,
        seen: &mut ahash::AHashSet<(FuncId, bonsai_callgraph::EdgeKind, bonsai_common::Precision)>,
        to: FuncId,
        edge_kind: bonsai_callgraph::EdgeKind,
        precision: bonsai_common::Precision,
    ) {
        let candidate_key = (to, edge_kind, precision);
        if seen.insert(candidate_key) {
            out.push(ResolvedCallee {
                func: to,
                edge_kind,
                precision,
            });
        }
    }

    fn push_resolved_edge_if_name_matches(
        &self,
        out: &mut Vec<ResolvedCallee>,
        seen: &mut ahash::AHashSet<(FuncId, bonsai_callgraph::EdgeKind, bonsai_common::Precision)>,
        to: FuncId,
        edge_kind: bonsai_callgraph::EdgeKind,
        precision: bonsai_common::Precision,
        callee_name: &str,
    ) {
        let Some(decl_name) = self.func_to_name.get(&to) else {
            return;
        };
        let mut matched = names_match_for_callee(decl_name, callee_name);
        if !matched {
            // Alias-aware fallback: each FuncId tracks every textual
            // name it can be called as, built from import-alias maps.
            // The callgraph already resolved this edge through the
            // same alias maps, so when the bare decl name doesn't
            // match, an alias-name match is legitimate.
            if let Some(call_names) = self.func_to_call_names.get(&to) {
                matched = call_names.iter().any(|n| names_match_for_callee(n, callee_name));
            }
        }
        // A site-specific semantic callgraph edge to a declaration already
        // is the compiler's resolution result. Constructor declarations are
        // commonly named `__init__`/`initialize` while the call expression is
        // spelled with the owning type, so textual name equality is neither
        // necessary nor correct here.
        if !matched && self.is_constructor_func(to) {
            matched = true;
        }
        if matched {
            Self::push_resolved_edge(out, seen, to, edge_kind, precision);
        }
    }

    /// Classify a constructor target from semantic declaration facts.
    ///
    /// Most adapters expose allocation syntax directly as
    /// `CallKind::Constructor`. Python and several expression-oriented
    /// grammars instead parse `ImportedClass(args)` as an ordinary call: the
    /// CST alone cannot know whether the identifier denotes a class or a
    /// function. In that case, perform the compiler-style symbol lookup here
    /// and accept the call only when the scoped target is an actual class
    /// declaration. No constructor/API spelling is inferred from the text.
    fn call_site_denotes_declared_class(
        &self,
        caller: FuncId,
        callee_name: &str,
        receiver: Option<&str>,
        _receiver_types: &[String],
        call_kind: bonsai_lang_api::CallKind,
    ) -> bool {
        if matches!(call_kind, bonsai_lang_api::CallKind::Constructor) {
            return true;
        }
        if !matches!(call_kind, bonsai_lang_api::CallKind::Function) || receiver.is_some() {
            return false;
        }
        // A bare function call may inherit the enclosing class in
        // `receiver_types` as contextual type information. That type is not
        // the call target (`sink(value)` inside `Repository` must never be
        // interpreted as `Repository(...)`). For expression-oriented class
        // calls, classify solely from the callee/import symbol. Explicit
        // constructor syntax returned above may still use receiver/type facts
        // in the normal constructor fallback.
        self.constructor_fallback_class_names(caller, callee_name, None, &[])
            .into_iter()
            .flat_map(|class_name| self.class_candidates_for_func_scope(caller, &class_name))
            .any(|symbol| self.symbol_shares_language_with_func(caller, symbol))
    }
}

impl WorkspaceCalleeResolver<'_> {
    fn callback_bindings_indexed(&self, host: FuncId, param_idx: u32) -> Vec<ResolvedCallee> {
        let cache_key = (host, param_idx);
        if let Some(cached) = self.callback_cache.read().get(&cache_key).cloned() {
            return cached;
        }
        // For every caller of `host`, walk its flow events looking
        // for Call sites that resolve to `host`, and pick the
        // argument at `param_idx`. The arg's text might be a
        // function name (e.g., `run(executor, t)` → arg 0 text is
        // "executor"). Resolve that name through the workspace's
        // callback-name index to get the bound FuncId. Each
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
                // Use the same syntax-derived callable-reference variants
                // as the callgraph instead of maintaining a second list of
                // wrapper/API spellings in the IDG.
                for bound_name in callable_reference_variants(&arg_text) {
                    for candidate_func in
                        self.callback_candidate_funcs_for_bound_name(&bound_name, caller, host)
                    {
                        if !self.funcs_share_language(host, candidate_func)
                            || !self.funcs_share_language(caller, candidate_func)
                        {
                            continue;
                        }
                        if seen.insert(candidate_func) {
                            out.push(ResolvedCallee {
                                func: candidate_func,
                                edge_kind: bonsai_callgraph::EdgeKind::Indirect,
                                precision: bonsai_common::Precision::Narrowed,
                            });
                        }
                    }
                }
            }
        }
        self.callback_cache.write().insert(cache_key, out.clone());
        out
    }
}

impl<'a> WorkspaceCalleeResolver<'a> {
    fn exception_type_assignability(
        &self,
        func: FuncId,
        thrown: &str,
        caught: &str,
    ) -> Option<bonsai_common::Precision> {
        let thrown = bonsai_lang_api::kit::canonical_simple_type_name(thrown);
        let caught = bonsai_lang_api::kit::canonical_simple_type_name(caught);
        if thrown.is_empty() || caught.is_empty() {
            return None;
        }
        if thrown == caught {
            return Some(bonsai_common::Precision::Exact);
        }
        let Some(scope) = self.func_to_scope.get(&func).cloned() else {
            return Some(bonsai_common::Precision::Narrowed);
        };
        let thrown_decls = self
            .class_symbols_by_name_scope
            .get(&(thrown, scope.clone()))
            .cloned()
            .unwrap_or_default();
        let caught_is_declared = self
            .class_symbols_by_name_scope
            .get(&(caught.clone(), scope.clone()))
            .is_some_and(|decls| !decls.is_empty());
        // Missing dependencies are an explicit unknown-type boundary. Keep a
        // narrowed edge rather than pretending two external spellings are
        // disjoint; when both declarations are present, their parsed base
        // graph can prove assignability or disjointness exactly.
        if thrown_decls.is_empty() || !caught_is_declared {
            return Some(bonsai_common::Precision::Narrowed);
        }
        let mut frontier = thrown_decls;
        let mut visited = AHashSet::new();
        while let Some(symbol) = frontier.pop() {
            if !visited.insert(symbol) {
                continue;
            }
            let Some(decl) = self.global.decl_of(symbol) else {
                continue;
            };
            for base in &decl.bases {
                let base = bonsai_lang_api::kit::canonical_simple_type_name(base);
                if base == caught {
                    return Some(bonsai_common::Precision::Exact);
                }
                if let Some(symbols) = self.class_symbols_by_name_scope.get(&(base, scope.clone())) {
                    frontier.extend(symbols.iter().copied());
                }
            }
        }
        None
    }

    fn callback_candidate_funcs_for_bound_name(
        &self,
        bound_name: &str,
        caller: FuncId,
        host: FuncId,
    ) -> Vec<FuncId> {
        let mut out = Vec::new();
        let mut seen: AHashSet<FuncId> = AHashSet::new();
        let mut saw_project_scope = false;

        if let Some(module) = self.func_to_module.get(&caller) {
            if !module.is_empty() {
                saw_project_scope = true;
                self.extend_callback_candidates_from_module(bound_name, module, &mut out, &mut seen);
            }
        }
        if let Some(module) = self.func_to_module.get(&host) {
            if !module.is_empty() {
                saw_project_scope = true;
                self.extend_callback_candidates_from_module(bound_name, module, &mut out, &mut seen);
            }
        }
        if !out.is_empty() {
            return out;
        }

        if let Some(directory) = self.func_to_directory.get(&caller) {
            saw_project_scope = true;
            self.extend_callback_candidates_from_directory(bound_name, directory, &mut out, &mut seen);
        }
        if let Some(directory) = self.func_to_directory.get(&host) {
            saw_project_scope = true;
            self.extend_callback_candidates_from_directory(bound_name, directory, &mut out, &mut seen);
        }
        if !out.is_empty() {
            return out;
        }

        if let Some(file) = self.func_to_file.get(&caller) {
            self.extend_callback_candidates_from_file(bound_name, *file, &mut out, &mut seen);
        }
        if let Some(file) = self.func_to_file.get(&host) {
            self.extend_callback_candidates_from_file(bound_name, *file, &mut out, &mut seen);
        }
        if !out.is_empty() || saw_project_scope {
            return out;
        }

        if let Some(candidate_funcs) = self.funcs_by_callback_name.get(bound_name) {
            out.extend(candidate_funcs.iter().copied());
        }
        out
    }

    fn extend_callback_candidates_from_module(
        &self,
        bound_name: &str,
        module: &ModulePath,
        out: &mut Vec<FuncId>,
        seen: &mut AHashSet<FuncId>,
    ) {
        if let Some(candidates) = self
            .funcs_by_callback_name_module
            .get(&(bound_name.to_string(), module.clone()))
        {
            extend_unique_funcs(out, seen, candidates.iter().copied());
        }
    }

    fn extend_callback_candidates_from_directory(
        &self,
        bound_name: &str,
        directory: &str,
        out: &mut Vec<FuncId>,
        seen: &mut AHashSet<FuncId>,
    ) {
        if let Some(candidates) = self
            .funcs_by_callback_name_directory
            .get(&(bound_name.to_string(), directory.to_string()))
        {
            extend_unique_funcs(out, seen, candidates.iter().copied());
        }
    }

    fn extend_callback_candidates_from_file(
        &self,
        bound_name: &str,
        file: FileId,
        out: &mut Vec<FuncId>,
        seen: &mut AHashSet<FuncId>,
    ) {
        if let Some(candidates) = self
            .funcs_by_callback_name_file
            .get(&(bound_name.to_string(), file))
        {
            extend_unique_funcs(out, seen, candidates.iter().copied());
        }
    }

    fn class_candidates_for_func_scope(&self, func: FuncId, name: &str) -> Vec<bonsai_common::SymbolId> {
        if let Some(file) = self.func_to_file.get(&func) {
            if let Some(candidates) = self
                .class_symbols_by_import_alias_file
                .get(&(*file, name.to_string()))
            {
                if !candidates.is_empty() {
                    return candidates.clone();
                }
            }
        }
        let mut saw_project_scope = false;
        if let Some(scope) = self.func_to_scope.get(&func) {
            saw_project_scope = scope.has_project_boundary();
            if let Some(candidates) = self
                .class_symbols_by_name_scope
                .get(&(name.to_string(), scope.clone()))
            {
                if !candidates.is_empty() {
                    return candidates.clone();
                }
            }
        }
        // Synthetic constructors/accessors are nested under their owning
        // class declaration. Their function-local scope key can differ from
        // sibling class declarations even though compiler lookup starts in
        // the owner's lexical scope. Consult that parent symbol before a
        // project boundary forbids any workspace-wide fallback.
        if let Some(parent) = self
            .global
            .decl_of(bonsai_common::SymbolId::new(func.raw()))
            .and_then(|decl| decl.parent)
        {
            if let Some(parent_scope) = self.symbol_to_scope.get(&parent) {
                if let Some(candidates) = self
                    .class_symbols_by_name_scope
                    .get(&(name.to_string(), parent_scope.clone()))
                {
                    if !candidates.is_empty() {
                        return candidates.clone();
                    }
                }
            }
        }
        if saw_project_scope {
            return Vec::new();
        }
        self.class_symbols_by_name.get(name).cloned().unwrap_or_default()
    }

    fn class_candidates_for_symbol_scope(
        &self,
        symbol: bonsai_common::SymbolId,
        name: &str,
    ) -> Vec<bonsai_common::SymbolId> {
        let mut saw_project_scope = false;
        if let Some(scope) = self.symbol_to_scope.get(&symbol) {
            saw_project_scope = scope.has_project_boundary();
            if let Some(candidates) = self
                .class_symbols_by_name_scope
                .get(&(name.to_string(), scope.clone()))
            {
                if !candidates.is_empty() {
                    return candidates.clone();
                }
            }
        }
        if saw_project_scope {
            return Vec::new();
        }
        self.class_symbols_by_name.get(name).cloned().unwrap_or_default()
    }

    fn class_candidates_for_ancestry(
        &self,
        symbol: bonsai_common::SymbolId,
        name: &str,
    ) -> Vec<bonsai_common::SymbolId> {
        let scoped = self.class_candidates_for_symbol_scope(symbol, name);
        if !scoped.is_empty() {
            return scoped;
        }
        let candidates_for_name = self
            .class_symbols_by_name
            .get(name)
            .into_iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        if let Some(directory) = self.symbol_to_directory.get(&symbol) {
            let same_directory = candidates_for_name
                .iter()
                .copied()
                .filter(|candidate| self.symbol_to_directory.get(candidate) == Some(directory))
                .collect::<Vec<_>>();
            if same_directory.len() == 1 {
                return same_directory;
            }
            if same_directory.len() > 1 {
                return Vec::new();
            }
        }
        let symbol_language = self
            .global
            .declaring_file(symbol)
            .and_then(|file| self.file_to_language.get(&file))
            .copied();
        let mut candidates = candidates_for_name
            .into_iter()
            .filter(|candidate| {
                symbol_language.is_none_or(|language| {
                    self.global
                        .declaring_file(*candidate)
                        .and_then(|file| self.file_to_language.get(&file))
                        .is_none_or(|candidate_language| *candidate_language == language)
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|candidate| candidate.raw());
        candidates.dedup();
        // A cross-scope hop is only semantic when the explicit base name
        // identifies one class in the same language. Multiple modules may
        // legitimately declare the same class name; without an import-target
        // fact choosing between them would be an over-approximation.
        if candidates.len() == 1 {
            candidates
        } else {
            Vec::new()
        }
    }

    fn class_candidates_for_typed_receiver(
        &self,
        caller: FuncId,
        name: &str,
    ) -> Vec<bonsai_common::SymbolId> {
        let scoped = self.class_candidates_for_func_scope(caller, name);
        if !scoped.is_empty() {
            return scoped;
        }
        let Some(caller_file) = self.func_to_file.get(&caller) else {
            return Vec::new();
        };
        self.class_symbols_by_name
            .get(name)
            .into_iter()
            .flatten()
            .copied()
            .filter(|symbol| self.global.declaring_file(*symbol).as_ref() == Some(caller_file))
            .collect()
    }

    fn funcs_share_language(&self, left: FuncId, right: FuncId) -> bool {
        match (
            self.func_to_language.get(&left),
            self.func_to_language.get(&right),
        ) {
            (Some(left), Some(right)) => left == right,
            _ => true,
        }
    }

    fn symbol_shares_language_with_func(&self, func: FuncId, symbol: bonsai_common::SymbolId) -> bool {
        let Some(func_language) = self.func_to_language.get(&func) else {
            return true;
        };
        let Some(file) = self.global.declaring_file(symbol) else {
            return true;
        };
        let Some(symbol_language) = self.file_to_language.get(&file) else {
            return true;
        };
        func_language == symbol_language
    }

    /// Walk the class hierarchy for an adapter-classified constructor
    /// call, looking only for `DeclKind::Constructor` facts. Some adapters
    /// do not surface an explicit constructor declaration for an inheriting
    /// class, so the nearest declared base constructor supplies the field
    /// initialization body.
    fn resolve_class_constructor_fallback(
        &self,
        caller: FuncId,
        callee_name: &str,
        receiver: Option<&str>,
        receiver_types: &[String],
        out: &mut Vec<ResolvedCallee>,
    ) {
        let callee_class_names = self.constructor_fallback_class_names(caller, callee_name, None, &[]);
        let callee_resolves_to_class = callee_class_names.iter().any(|class_name| {
            self.class_candidates_for_func_scope(caller, class_name)
                .into_iter()
                .any(|symbol| self.symbol_shares_language_with_func(caller, symbol))
        });
        let class_names = if callee_resolves_to_class {
            callee_class_names
        } else {
            self.constructor_fallback_class_names(caller, callee_name, receiver, receiver_types)
        };
        if class_names.is_empty() {
            return;
        }

        for class_name in class_names {
            let mut frontier: Vec<bonsai_common::SymbolId> = Vec::new();
            let mut seen: ahash::AHashSet<bonsai_common::SymbolId> = ahash::AHashSet::default();
            let candidates = self.class_candidates_for_func_scope(caller, &class_name);
            if let Some(start) = candidates
                .into_iter()
                .find(|symbol| self.symbol_shares_language_with_func(caller, *symbol))
            {
                frontier.push(start);
            }
            while let Some(class_sym) = frontier.pop() {
                if !seen.insert(class_sym) {
                    continue;
                }
                let Some(class_decl) = self.global.decl_of(class_sym) else {
                    continue;
                };
                if let Some(constructors) = self.class_constructors_by_parent.get(&class_sym) {
                    for &func in constructors {
                        if !self.funcs_share_language(caller, func) {
                            continue;
                        }
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
                    let candidates = self.class_candidates_for_symbol_scope(class_sym, base_name);
                    if let Some(base_sym) = candidates
                        .into_iter()
                        .find(|symbol| self.symbol_shares_language_with_func(caller, *symbol))
                    {
                        frontier.push(base_sym);
                    }
                }
            }
        }
    }

    fn resolve_typed_receiver_method_fallback(
        &self,
        caller: FuncId,
        callee_name: &str,
        receiver_types: &[String],
        out: &mut Vec<ResolvedCallee>,
    ) {
        let Some(class_name) = receiver_types.iter().find_map(|receiver_type| {
            let class_name = bare_class_name(receiver_type);
            (!class_name.is_empty()).then_some(class_name)
        }) else {
            return;
        };
        let mut frontier = self.class_candidates_for_typed_receiver(caller, class_name);
        frontier.retain(|symbol| self.symbol_shares_language_with_func(caller, *symbol));
        let mut seen = ahash::AHashSet::default();

        while !frontier.is_empty() {
            let mut next = Vec::new();
            let mut methods = Vec::new();
            for class_sym in frontier.drain(..) {
                if !seen.insert(class_sym) {
                    continue;
                }
                if let Some(candidates) = self.class_methods_by_parent.get(&class_sym) {
                    for &func in candidates {
                        if self.funcs_share_language(caller, func)
                            && self
                                .func_to_name
                                .get(&func)
                                .is_some_and(|name| names_match_for_callee(name, callee_name))
                        {
                            methods.push(func);
                        }
                    }
                }
                let Some(class_decl) = self.global.decl_of(class_sym) else {
                    continue;
                };
                for base_name in &class_decl.bases {
                    for base_sym in self.class_candidates_for_ancestry(class_sym, base_name) {
                        if !seen.contains(&base_sym)
                            && self.symbol_shares_language_with_func(caller, base_sym)
                        {
                            next.push(base_sym);
                        }
                    }
                }
            }
            // Stop at the nearest inheritance depth that declares the
            // method. This preserves normal override/shadow semantics and
            // still supports multiple bases at the same depth.
            if !methods.is_empty() {
                methods.sort_unstable_by_key(|func| func.raw());
                methods.dedup();
                for func in methods {
                    out.push(ResolvedCallee {
                        func,
                        edge_kind: bonsai_callgraph::EdgeKind::Indirect,
                        precision: bonsai_common::Precision::Narrowed,
                    });
                }
                return;
            }
            next.sort_unstable_by_key(|symbol| symbol.raw());
            next.dedup();
            frontier = next;
        }
    }

    fn constructor_fallback_class_names(
        &self,
        caller: FuncId,
        callee_name: &str,
        receiver: Option<&str>,
        receiver_types: &[String],
    ) -> Vec<String> {
        let mut out = Vec::new();
        let trimmed = callee_name.trim();
        if trimmed.is_empty() {
            return out;
        }
        // Constructor syntax may surface a bare class reference or a
        // qualified member reference. Collect its identifier segments and
        // let scoped class-declaration lookup determine which segment denotes
        // the constructed type. The syntactic callee is authoritative and
        // must be tried before contextual receiver types: inside a subclass
        // constructor, `Base(args)` delegates to `Base`, not back to the
        // enclosing subclass merely because its implicit receiver is typed as
        // that subclass.
        for segment in trimmed
            .split(['.', ':', '\\'])
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
        {
            let class_name = bare_class_name(segment);
            if !class_name.is_empty() {
                push_unique_class_name(&mut out, class_name.to_string());
            }
        }
        for receiver_type in receiver_types {
            let class_name = bare_class_name(receiver_type);
            if !class_name.is_empty() {
                push_unique_class_name(&mut out, class_name.to_string());
            }
        }
        if let Some(receiver) = receiver {
            let class_name = bare_class_name(receiver);
            if !class_name.is_empty() {
                push_unique_class_name(&mut out, class_name.to_string());
            }
        }
        if out.is_empty() {
            if let Some(owner) = self.receiver_type_for(caller) {
                let class_name = bare_class_name(&owner);
                if !class_name.is_empty() {
                    push_unique_class_name(&mut out, class_name.to_string());
                }
            }
        }
        out
    }
}

fn extend_unique_funcs(
    out: &mut Vec<FuncId>,
    seen: &mut AHashSet<FuncId>,
    funcs: impl IntoIterator<Item = FuncId>,
) {
    for func in funcs {
        if seen.insert(func) {
            out.push(func);
        }
    }
}

fn parent_dir_key(path: &str) -> Option<String> {
    let parent = Path::new(path).parent()?;
    let parent = parent.to_string_lossy();
    if parent.is_empty() {
        None
    } else {
        Some(parent.into_owned())
    }
}

fn funcs_share_language(
    func_to_language: &AHashMap<FuncId, &'static str>,
    left: FuncId,
    right: FuncId,
) -> bool {
    match (func_to_language.get(&left), func_to_language.get(&right)) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn file_language(file_to_language: &AHashMap<FileId, &'static str>, file: FileId) -> Option<&'static str> {
    file_to_language.get(&file).copied()
}

fn call_site_spans_match(edge_span: bonsai_common::Span, event_span: bonsai_common::Span) -> bool {
    if edge_span == event_span {
        return true;
    }
    if edge_span.file != event_span.file {
        return false;
    }
    span_contains(edge_span, event_span) || span_contains(event_span, edge_span)
}

fn call_site_has_no_explicit_args(global: &GlobalIndex, func: FuncId, span: bonsai_common::Span) -> bool {
    let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
        return false;
    };
    let mut saw_empty_match = false;
    let mut saw_non_empty_match = false;
    scan_call_site_arg_presence(
        &decl.flow_events,
        span,
        &mut saw_empty_match,
        &mut saw_non_empty_match,
    );
    saw_empty_match && !saw_non_empty_match
}

fn scan_call_site_arg_presence(
    events: &[bonsai_lang_api::FlowEvent],
    span: bonsai_common::Span,
    saw_empty_match: &mut bool,
    saw_non_empty_match: &mut bool,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call {
                span: event_span,
                args,
                ..
            } => {
                if call_site_spans_match(span, *event_span) {
                    if args.is_empty() {
                        *saw_empty_match = true;
                    } else {
                        *saw_non_empty_match = true;
                    }
                }
            }
            FlowEvent::Assign {
                span: event_span,
                source_call,
                source_call_args,
                ..
            } => {
                if source_call.is_some() && call_site_spans_match(span, *event_span) {
                    if source_call_args.is_empty() {
                        *saw_empty_match = true;
                    } else {
                        *saw_non_empty_match = true;
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                scan_call_site_arg_presence(then_events, span, saw_empty_match, saw_non_empty_match);
                scan_call_site_arg_presence(else_events, span, saw_empty_match, saw_non_empty_match);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                scan_call_site_arg_presence(body, span, saw_empty_match, saw_non_empty_match);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                scan_call_site_arg_presence(body, span, saw_empty_match, saw_non_empty_match);
                scan_call_site_arg_presence(catch_events, span, saw_empty_match, saw_non_empty_match);
                scan_call_site_arg_presence(finally_events, span, saw_empty_match, saw_non_empty_match);
            }
            _ => {}
        }
    }
}

fn span_contains(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn symbol_language(
    global: &GlobalIndex,
    file_to_language: &AHashMap<FileId, &'static str>,
    symbol: bonsai_common::SymbolId,
) -> Option<&'static str> {
    global
        .declaring_file(symbol)
        .and_then(|file| file_language(file_to_language, file))
}

fn class_symbols_by_name_for_files(
    global: &GlobalIndex,
    included_files: Option<&AHashSet<FileId>>,
) -> AHashMap<String, Vec<bonsai_common::SymbolId>> {
    let mut out: AHashMap<String, Vec<bonsai_common::SymbolId>> = AHashMap::new();
    for file in global.all_files() {
        if included_files.is_some_and(|files| !files.contains(&file)) {
            continue;
        }
        for decl in global.decls_in(file) {
            if decl_kind_is_type_receiver(decl.kind) {
                out.entry(decl.name.clone()).or_default().push(decl.symbol);
            }
        }
    }
    out
}

fn class_symbols_matching_import_target(
    global: &GlobalIndex,
    class_symbols_by_name: &AHashMap<String, Vec<bonsai_common::SymbolId>>,
    target: &str,
) -> Vec<bonsai_common::SymbolId> {
    let Some(member) = import_target_member(target) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for symbol in class_symbols_by_name.get(member).into_iter().flatten() {
        let Some(decl) = global.decl_of(*symbol) else {
            continue;
        };
        if declaration_matches_import_target(decl, target) && !out.contains(symbol) {
            out.push(*symbol);
        }
    }
    out
}

fn import_target_member(target: &str) -> Option<&str> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }
    Some(
        target
            .rsplit_once('.')
            .map_or(target, |(_, member)| member.trim()),
    )
}

fn declaration_matches_import_target(decl: &bonsai_lang_api::Decl, target: &str) -> bool {
    let target = target.trim();
    if target.is_empty() {
        return false;
    }
    let Some((module, member)) = target.rsplit_once('.') else {
        return decl.name == target;
    };
    if decl.name != member.trim() {
        return false;
    }
    bonsai_resolve::module_target_matches_decl_module_path(module.trim(), &decl.module_path)
        || decl.qualified_name.as_deref().is_some_and(|qualified| {
            let normalized = qualified.replace("::", ".").replace(['/', '\\'], ".");
            normalized == target || normalized.ends_with(&format!(".{target}"))
        })
}

fn class_symbols_by_name_scope_for_files(
    global: &GlobalIndex,
    symbol_to_scope: &AHashMap<bonsai_common::SymbolId, LocalScopeKey>,
    included_files: Option<&AHashSet<FileId>>,
) -> AHashMap<(String, LocalScopeKey), Vec<bonsai_common::SymbolId>> {
    let mut out: AHashMap<(String, LocalScopeKey), Vec<bonsai_common::SymbolId>> = AHashMap::new();
    for file in global.all_files() {
        if included_files.is_some_and(|files| !files.contains(&file)) {
            continue;
        }
        for decl in global.decls_in(file) {
            if !decl_kind_is_type_receiver(decl.kind) {
                continue;
            }
            let Some(scope) = symbol_to_scope.get(&decl.symbol) else {
                continue;
            };
            out.entry((decl.name.clone(), scope.clone()))
                .or_default()
                .push(decl.symbol);
        }
    }
    out
}

fn decl_kind_is_type_receiver(kind: bonsai_lang_api::DeclKind) -> bool {
    matches!(
        kind,
        bonsai_lang_api::DeclKind::Class
            | bonsai_lang_api::DeclKind::Struct
            | bonsai_lang_api::DeclKind::Trait
            | bonsai_lang_api::DeclKind::Interface
            | bonsai_lang_api::DeclKind::Enum
    )
}

fn class_constructors_by_parent_for_files(
    global: &GlobalIndex,
    included_files: Option<&AHashSet<FileId>>,
    included_funcs: Option<&AHashSet<FuncId>>,
) -> AHashMap<bonsai_common::SymbolId, Vec<FuncId>> {
    let mut out: AHashMap<bonsai_common::SymbolId, Vec<FuncId>> = AHashMap::new();
    for file in global.all_files() {
        if included_files.is_some_and(|files| !files.contains(&file)) {
            continue;
        }
        for decl in global.functions_in(file) {
            let func = FuncId::new(decl.symbol.raw());
            if included_funcs.is_some_and(|funcs| !funcs.contains(&func)) {
                continue;
            }
            let Some(parent) = decl.parent else {
                continue;
            };
            if is_constructor_decl(decl) {
                out.entry(parent).or_default().push(func);
            }
        }
    }
    out
}

fn class_methods_by_parent_for_files(
    global: &GlobalIndex,
    included_files: Option<&AHashSet<FileId>>,
    included_funcs: Option<&AHashSet<FuncId>>,
) -> AHashMap<bonsai_common::SymbolId, Vec<FuncId>> {
    let mut out: AHashMap<bonsai_common::SymbolId, Vec<FuncId>> = AHashMap::new();
    for file in global.all_files() {
        if included_files.is_some_and(|files| !files.contains(&file)) {
            continue;
        }
        for decl in global.functions_in(file) {
            let func = FuncId::new(decl.symbol.raw());
            if included_funcs.is_some_and(|funcs| !funcs.contains(&func)) {
                continue;
            }
            let Some(parent) = decl.parent else {
                continue;
            };
            if matches!(decl.kind, bonsai_lang_api::DeclKind::Method) {
                out.entry(parent).or_default().push(func);
            }
        }
    }
    out
}

fn is_constructor_decl(decl: &bonsai_lang_api::Decl) -> bool {
    matches!(decl.kind, bonsai_lang_api::DeclKind::Constructor)
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
    aliases_for_file: F,
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
{
    build_with_file_info(global, call_graph, aliases_for_file, |_| None)
}

/// Build with per-file aliases and language ids. Production
/// workspaces use this entry point so name-based callback and
/// constructor fallbacks cannot stitch unrelated languages together.
pub fn build_with_file_info<F, G>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    aliases_for_file: F,
    language_for_file: G,
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
    G: Fn(FileId) -> Option<&'static str>,
{
    build_with_file_info_and_paths(global, call_graph, aliases_for_file, language_for_file, |_| None)
}

/// Build with per-file aliases, language ids, and paths. Production
/// workspace callers use this so callback binding can stay scoped to
/// the same module/directory instead of falling back to global
/// same-name buckets on copied projects.
pub fn build_with_file_info_and_paths<F, G, P>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    aliases_for_file: F,
    language_for_file: G,
    path_for_file: P,
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
    G: Fn(FileId) -> Option<&'static str>,
    P: Fn(FileId) -> Option<String>,
{
    build_with_file_info_and_options_with_paths(
        global,
        call_graph,
        aliases_for_file,
        language_for_file,
        path_for_file,
        &TransferOptions::default(),
    )
}

/// Build with per-file aliases, language ids, and transfer options.
/// Security analysis uses this to thread rulepack-declared semantic
/// transfer shapes into the IDG without baking API names into the
/// graph core.
pub fn build_with_file_info_and_options<F, G>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    aliases_for_file: F,
    language_for_file: G,
    transfer_options: &TransferOptions,
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
    G: Fn(FileId) -> Option<&'static str>,
{
    build_with_file_info_and_options_with_paths(
        global,
        call_graph,
        aliases_for_file,
        language_for_file,
        |_| None,
        transfer_options,
    )
}

/// Build with per-file aliases, language ids, paths, and transfer
/// options. Security analysis uses this to thread rulepack-declared
/// semantic transfer shapes into the IDG without baking API names into
/// the graph core.
pub fn build_with_file_info_and_options_with_paths<F, G, P>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    aliases_for_file: F,
    language_for_file: G,
    path_for_file: P,
    transfer_options: &TransferOptions,
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
    G: Fn(FileId) -> Option<&'static str>,
    P: Fn(FileId) -> Option<String>,
{
    build_with_file_info_and_options_scoped(
        global,
        call_graph,
        aliases_for_file,
        language_for_file,
        path_for_file,
        transfer_options,
        None,
        None,
    )
}

/// Build with per-file aliases, language ids, transfer options, and
/// a caller-provided file scope. Security production scans use this
/// to keep excluded files out of the semantic graph before transfer
/// and stitching, while unscoped callers continue to build a full
/// workspace IDG.
pub fn build_with_file_info_and_options_for_files<F, G>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    aliases_for_file: F,
    language_for_file: G,
    transfer_options: &TransferOptions,
    included_files: &[FileId],
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
    G: Fn(FileId) -> Option<&'static str>,
{
    build_with_file_info_and_options_for_files_with_paths(
        global,
        call_graph,
        aliases_for_file,
        language_for_file,
        |_| None,
        transfer_options,
        included_files,
    )
}

/// Build with per-file aliases, language ids, paths, transfer options,
/// and a caller-provided file scope.
pub fn build_with_file_info_and_options_for_files_with_paths<F, G, P>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    aliases_for_file: F,
    language_for_file: G,
    path_for_file: P,
    transfer_options: &TransferOptions,
    included_files: &[FileId],
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
    G: Fn(FileId) -> Option<&'static str>,
    P: Fn(FileId) -> Option<String>,
{
    let included_files: AHashSet<FileId> = included_files.iter().copied().collect();
    build_with_file_info_and_options_scoped(
        global,
        call_graph,
        aliases_for_file,
        language_for_file,
        path_for_file,
        transfer_options,
        Some(&included_files),
        None,
    )
}

/// Build with per-file aliases, language ids, paths, transfer options,
/// and caller-provided file/function scopes.
#[allow(clippy::too_many_arguments)] // Public scoped IDG builder mirrors the release/security call site parameters.
pub fn build_with_file_info_and_options_for_files_and_funcs_with_paths<F, G, P>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    aliases_for_file: F,
    language_for_file: G,
    path_for_file: P,
    transfer_options: &TransferOptions,
    included_files: &[FileId],
    included_funcs: &[FuncId],
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
    G: Fn(FileId) -> Option<&'static str>,
    P: Fn(FileId) -> Option<String>,
{
    let included_files: AHashSet<FileId> = included_files.iter().copied().collect();
    let included_funcs: AHashSet<FuncId> = included_funcs.iter().copied().collect();
    build_with_file_info_and_options_scoped(
        global,
        call_graph,
        aliases_for_file,
        language_for_file,
        path_for_file,
        transfer_options,
        Some(&included_files),
        Some(&included_funcs),
    )
}

#[allow(clippy::too_many_arguments)] // Shared builder carries optional file/function scopes plus transfer hooks.
fn build_with_file_info_and_options_scoped<F, G, P>(
    global: &GlobalIndex,
    call_graph: &ResolvedCallGraph,
    mut aliases_for_file: F,
    language_for_file: G,
    path_for_file: P,
    transfer_options: &TransferOptions,
    included_files: Option<&AHashSet<FileId>>,
    included_funcs: Option<&AHashSet<FuncId>>,
) -> IdgWorkspace
where
    F: FnMut(FileId) -> AHashMap<String, String>,
    G: Fn(FileId) -> Option<&'static str>,
    P: Fn(FileId) -> Option<String>,
{
    let total_started = Instant::now();
    let phase_started = Instant::now();
    let maps = WorkspaceMaps::build_with_languages_for_files(
        global,
        language_for_file,
        &path_for_file,
        included_files,
        included_funcs,
    );
    idg_build_log(format_args!(
        "maps: {:.3}s funcs={} files={}",
        phase_started.elapsed().as_secs_f64(),
        maps.func_to_seg.len(),
        maps.file_to_language.len()
    ));
    let phase_started = Instant::now();
    let outputs =
        run_transfer_in_parallel_for_files(global, transfer_options, included_files, included_funcs);
    if idg_build_enabled() {
        let places: usize = outputs.iter().map(|out| out.places.len()).sum();
        let nodes: usize = outputs.iter().map(|out| out.nodes.len()).sum();
        let edges: usize = outputs.iter().map(|out| out.edges.len()).sum();
        let calls: usize = outputs.iter().map(|out| out.call_sites.len()).sum();
        idg_build_log(format_args!(
            "transfer: {:.3}s funcs={} places={} nodes={} edges={} call_sites={}",
            phase_started.elapsed().as_secs_f64(),
            outputs.len(),
            places,
            nodes,
            edges,
            calls
        ));
    }
    let phase_started = Instant::now();
    // Build `func_to_call_names`: every textual name a func can be
    // called as. Decl name plus every alias declared in any file
    // that imports the func by a renamed identifier. We invert the
    // per-file `{local_name → original_name}` map: when a file
    // imports `persist as persistEnvelope`, every persist FuncId
    // gains the alias `persistEnvelope` so the IDG resolver
    // accepts call sites that spell it that way.
    let mut func_to_call_names: AHashMap<FuncId, Vec<String>> = AHashMap::new();
    let mut class_symbols_by_import_alias_file: AHashMap<(FileId, String), Vec<bonsai_common::SymbolId>> =
        AHashMap::new();
    // Compiler-style declaration indexes make import-alias resolution a
    // narrow candidate lookup followed by exact module/qualified-name
    // validation. Rescanning every declaration for every alias is
    // quadratic on large workspaces.
    let mut funcs_by_decl_name: AHashMap<String, Vec<FuncId>> = AHashMap::new();
    for (func, name) in &maps.func_to_name {
        funcs_by_decl_name.entry(name.clone()).or_default().push(*func);
    }
    let class_symbols_by_name = class_symbols_by_name_for_files(global, included_files);
    let module_prefixes = module_prefixes_by_file(global);
    let module_default_exports = module_default_export_funcs_by_module(global, &module_prefixes);
    for file in global.all_files() {
        if included_files.is_some_and(|files| !files.contains(&file)) {
            continue;
        }
        let aliases = aliases_for_file(file);
        let caller_module = module_prefixes.get(&file).map(String::as_str);
        for (alias, original) in aliases {
            if let Some(member) = import_target_member(&original) {
                for func in funcs_by_decl_name.get(member).into_iter().flatten().copied() {
                    let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
                        continue;
                    };
                    if declaration_matches_import_target(decl, &original) {
                        add_func_call_alias(&mut func_to_call_names, func, &alias);
                    }
                }
            }
            if let Some(caller_module) = caller_module {
                for module_name in import_module_candidates(caller_module, &original) {
                    if let Some(funcs) = module_default_exports.get(&module_name) {
                        for func in funcs {
                            if !maps.func_to_seg.contains_key(func) {
                                continue;
                            }
                            add_func_call_alias(&mut func_to_call_names, *func, &alias);
                        }
                    }
                }
            }
            let symbols = class_symbols_matching_import_target(global, &class_symbols_by_name, &original);
            if !symbols.is_empty() {
                let candidates = class_symbols_by_import_alias_file
                    .entry((file, alias.clone()))
                    .or_default();
                for symbol in symbols {
                    if !candidates.contains(&symbol) {
                        candidates.push(symbol);
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
    let local_callable_bindings = bonsai_callgraph::collect_workspace_local_callable_bindings(global);
    for bindings in local_callable_bindings.values() {
        for (alias, func) in bindings {
            if !maps.func_to_seg.contains_key(func) {
                continue;
            }
            add_func_call_alias(&mut func_to_call_names, *func, alias);
        }
    }
    let alias_count: usize = func_to_call_names.values().map(Vec::len).sum();
    idg_build_log(format_args!(
        "call-name aliases: {:.3}s funcs={} aliases={}",
        phase_started.elapsed().as_secs_f64(),
        func_to_call_names.len(),
        alias_count
    ));
    let phase_started = Instant::now();
    let class_symbols_by_name_scope =
        class_symbols_by_name_scope_for_files(global, &maps.symbol_to_scope, included_files);
    let class_symbol_count: usize = class_symbols_by_name.values().map(Vec::len).sum();
    let class_constructors_by_parent =
        class_constructors_by_parent_for_files(global, included_files, included_funcs);
    let class_constructor_count: usize = class_constructors_by_parent.values().map(Vec::len).sum();
    let class_methods_by_parent = class_methods_by_parent_for_files(global, included_files, included_funcs);
    let class_method_count: usize = class_methods_by_parent.values().map(Vec::len).sum();
    idg_build_log(format_args!(
        "class index: {:.3}s names={} classes={} constructor_parents={} constructors={} method_parents={} methods={}",
        phase_started.elapsed().as_secs_f64(),
        class_symbols_by_name.len(),
        class_symbol_count,
        class_constructors_by_parent.len(),
        class_constructor_count,
        class_methods_by_parent.len(),
        class_method_count
    ));
    let phase_started = Instant::now();
    let included_funcs: AHashSet<FuncId> = maps.func_to_seg.keys().copied().collect();
    let call_edges_by_site = call_edges_by_site_for_funcs(call_graph, global, Some(&included_funcs));
    let call_edge_site_count: usize = call_edges_by_site.values().map(Vec::len).sum();
    idg_build_log(format_args!(
        "call-edge site index: {:.3}s sites={} edges={}",
        phase_started.elapsed().as_secs_f64(),
        call_edges_by_site.len(),
        call_edge_site_count
    ));
    let resolver = WorkspaceCalleeResolver {
        call_graph,
        func_to_name: &maps.func_to_name,
        global,
        func_to_call_names: &func_to_call_names,
        func_to_language: &maps.func_to_language,
        funcs_by_callback_name: &maps.funcs_by_callback_name,
        funcs_by_callback_name_module: &maps.funcs_by_callback_name_module,
        funcs_by_callback_name_directory: &maps.funcs_by_callback_name_directory,
        funcs_by_callback_name_file: &maps.funcs_by_callback_name_file,
        func_to_module: &maps.func_to_module,
        func_to_directory: &maps.func_to_directory,
        func_to_file: &maps.func_to_file,
        func_to_scope: &maps.func_to_scope,
        symbol_to_scope: &maps.symbol_to_scope,
        symbol_to_directory: &maps.symbol_to_directory,
        call_edges_by_site: &call_edges_by_site,
        file_to_language: &maps.file_to_language,
        class_symbols_by_name: &class_symbols_by_name,
        class_symbols_by_name_scope: &class_symbols_by_name_scope,
        class_symbols_by_import_alias_file: &class_symbols_by_import_alias_file,
        class_constructors_by_parent: &class_constructors_by_parent,
        class_methods_by_parent: &class_methods_by_parent,
        local_callable_bindings: &local_callable_bindings,
        callback_cache: RwLock::new(AHashMap::new()),
        ancestor_dispatch_cache: RwLock::new(AHashMap::new()),
    };
    let f2s = WorkspaceFuncToSegment {
        func_to_seg: &maps.func_to_seg,
    };
    let phase_started = Instant::now();
    let demand_languages: AHashSet<&str> = transfer_options
        .field_demand_languages
        .iter()
        .map(String::as_str)
        .collect();
    let demand_driven_funcs =
        (transfer_options.demand_driven_field_forwarding && !demand_languages.is_empty()).then(|| {
            maps.func_to_language
                .iter()
                .filter_map(|(func, language)| demand_languages.contains(language).then_some(*func))
                .collect::<AHashSet<_>>()
        });
    let field_demand_terminal_sites: AHashSet<(FuncId, bonsai_common::Span)> = transfer_options
        .field_demand_terminal_sites
        .iter()
        .copied()
        .collect();
    let mut ws = stitch_idg_with_selective_field_forwarding_mode(
        outputs,
        &resolver,
        &f2s,
        transfer_options.include_field_argument_forwarding,
        transfer_options.demand_driven_field_forwarding,
        demand_driven_funcs.as_ref(),
        (!field_demand_terminal_sites.is_empty()).then_some(&field_demand_terminal_sites),
    );
    stitch_declared_exception_hierarchy(&mut ws, &resolver);
    idg_build_log(format_args!(
        "stitch-idg: {:.3}s segments={} funcs={} intra_edges={} cross_edges={} field_links={}",
        phase_started.elapsed().as_secs_f64(),
        ws.segment_count(),
        ws.func_count(),
        ws.intra_edge_count(),
        ws.cross_file().len(),
        ws.field_flow().len()
    ));
    if transfer_options.include_diagnostic_field_flows {
        let phase_started = Instant::now();
        let before_edges = ws.total_edge_count();
        let before_field_links = ws.field_flow().len();
        stitch_receiver_field_flow(
            &mut ws,
            global,
            &maps.func_to_language,
            &maps.file_to_language,
            &maps.symbol_to_scope,
        );
        idg_build_log(format_args!(
            "receiver-field-flow: {:.3}s edge_delta={} field_link_delta={} total_edges={} field_links={}",
            phase_started.elapsed().as_secs_f64(),
            ws.total_edge_count().saturating_sub(before_edges),
            ws.field_flow().len().saturating_sub(before_field_links),
            ws.total_edge_count(),
            ws.field_flow().len()
        ));
    } else {
        idg_build_log(format_args!(
            "receiver-field-flow: skipped diagnostic-only phase total_edges={} field_links={}",
            ws.total_edge_count(),
            ws.field_flow().len()
        ));
    }
    if transfer_options.include_receiver_method_propagation {
        let phase_started = Instant::now();
        let before_edges = ws.total_edge_count();
        let before_field_links = ws.field_flow().len();
        stitch_receiver_method_propagation(
            &mut ws,
            global,
            call_graph,
            &resolver,
            &maps.func_to_language,
            &maps.file_to_language,
            &maps.func_to_scope,
            &maps.symbol_to_scope,
        );
        idg_build_log(format_args!(
            "receiver-method-propagation: {:.3}s edge_delta={} field_link_delta={} total_edges={} field_links={}",
            phase_started.elapsed().as_secs_f64(),
            ws.total_edge_count().saturating_sub(before_edges),
            ws.field_flow().len().saturating_sub(before_field_links),
            ws.total_edge_count(),
            ws.field_flow().len()
        ));
    } else {
        idg_build_log(format_args!(
            "receiver-method-propagation: skipped broad receiver heuristic total_edges={} field_links={}",
            ws.total_edge_count(),
            ws.field_flow().len()
        ));
    }
    idg_build_log(format_args!(
        "total: {:.3}s segments={} funcs={} total_edges={} field_links={}",
        total_started.elapsed().as_secs_f64(),
        ws.segment_count(),
        ws.func_count(),
        ws.total_edge_count(),
        ws.field_flow().len()
    ));
    ws
}

/// Complete typed `throw → catch` edges using declaration inheritance.
/// The per-function transfer sees exact type spellings but intentionally has
/// no global type-name inventory. Here the workspace's tree-sitter-derived
/// class declarations and `bases` facts can prove subtype assignability
/// without treating names such as `Exception` or `Error` as magic roots.
fn stitch_declared_exception_hierarchy(ws: &mut IdgWorkspace, resolver: &WorkspaceCalleeResolver<'_>) {
    #[derive(Clone)]
    struct ThrowNode {
        node: crate::node::NodeId,
        func: FuncId,
        ty: String,
        span: bonsai_common::Span,
    }
    #[derive(Clone)]
    struct CatchNode {
        node: crate::node::NodeId,
        func: FuncId,
        ty: String,
        try_span: bonsai_common::Span,
    }

    let segment_ids = ws.segments().map(|(id, _)| id).collect::<Vec<_>>();
    for segment_id in segment_ids {
        let Some(segment) = ws.segment(segment_id) else {
            continue;
        };
        // Index the exact evidence spans once. Looking them up separately for
        // every throw/catch node turns this phase into O(nodes * edges) on a
        // large function even though each relevant edge has one endpoint.
        let mut throw_spans = vec![None; segment.nodes.nodes.len()];
        let mut catch_try_spans = vec![None; segment.nodes.nodes.len()];
        for edge in &segment.edges {
            match edge.meta.kind {
                crate::edge::IdgEdgeKind::IntraThrow => {
                    if let Some(slot) = throw_spans.get_mut(edge.to.0 as usize) {
                        if slot.is_none() {
                            *slot = Some(edge.meta.via_span);
                        }
                    }
                }
                crate::edge::IdgEdgeKind::IntraAssign => {
                    if let Some(slot) = catch_try_spans.get_mut(edge.from.0 as usize) {
                        if slot.is_none() {
                            *slot = Some(edge.meta.via_span);
                        }
                    }
                }
                _ => {}
            }
        }
        let mut throws = Vec::new();
        let mut catches = Vec::new();
        for (index, node) in segment.nodes.nodes.iter().enumerate() {
            let local = crate::node::NodeId(index as u32);
            let Some(place) = segment.places.get(node.place) else {
                continue;
            };
            match place {
                crate::place::Place::Throw { ty } => {
                    let Some(span) = throw_spans[index] else {
                        continue;
                    };
                    let Some(name) = segment.strings.get(ty.0).map(str::to_string) else {
                        continue;
                    };
                    throws.push(ThrowNode {
                        node: local,
                        func: node.func,
                        ty: name,
                        span,
                    });
                }
                crate::place::Place::Catch { ty } => {
                    let Some(try_span) = catch_try_spans[index] else {
                        continue;
                    };
                    let Some(name) = segment.strings.get(ty.0).map(str::to_string) else {
                        continue;
                    };
                    catches.push(CatchNode {
                        node: local,
                        func: node.func,
                        ty: name,
                        try_span,
                    });
                }
                _ => {}
            }
        }
        let mut additions = Vec::new();
        for thrown in &throws {
            for caught in &catches {
                if thrown.func != caught.func
                    || thrown.span.file != caught.try_span.file
                    || thrown.span.start < caught.try_span.start
                    || thrown.span.end > caught.try_span.end
                {
                    continue;
                }
                let Some(precision) =
                    resolver.exception_type_assignability(thrown.func, &thrown.ty, &caught.ty)
                else {
                    continue;
                };
                let edge = crate::edge::IdgEdge {
                    from: thrown.node,
                    to: caught.node,
                    meta: crate::edge::EdgeMeta {
                        precision,
                        kind: crate::edge::IdgEdgeKind::IntraThrow,
                        call_kind: bonsai_callgraph::EdgeKind::Direct,
                        via_span: thrown.span,
                    },
                };
                if !segment.edges.contains(&edge) && !additions.contains(&edge) {
                    additions.push(edge);
                }
            }
        }
        if let Some(segment) = ws.segment_mut(segment_id) {
            segment.edges.extend(additions);
        }
    }
}

fn add_func_call_alias(func_to_call_names: &mut AHashMap<FuncId, Vec<String>>, func: FuncId, alias: &str) {
    if alias.is_empty() {
        return;
    }
    let entry = func_to_call_names.entry(func).or_default();
    if !entry.iter().any(|existing| existing == alias) {
        entry.push(alias.to_string());
    }
}

fn module_prefixes_by_file(global: &GlobalIndex) -> AHashMap<FileId, String> {
    let mut prefixes = AHashMap::new();
    for file in global.all_files() {
        if let Some(prefix) = global
            .decls_in(file)
            .iter()
            .find(|decl| decl.name == "__module__")
            .and_then(qname_module_prefix)
        {
            prefixes.insert(file, prefix.to_string());
            continue;
        }
        let mut best: Option<&str> = None;
        for decl in global.decls_in(file) {
            if decl.parent.is_some() {
                continue;
            }
            let Some(prefix) = qname_module_prefix(decl) else {
                continue;
            };
            let is_better = match best {
                Some(current) => prefix.split('.').count() < current.split('.').count(),
                None => true,
            };
            if is_better {
                best = Some(prefix);
            }
        }
        if let Some(prefix) = best {
            prefixes.insert(file, prefix.to_string());
        }
    }
    prefixes
}

fn qname_module_prefix(decl: &bonsai_lang_api::Decl) -> Option<&str> {
    let qname = decl.qualified_name.as_deref()?;
    let (prefix, tail) = qname.rsplit_once('.')?;
    if prefix.is_empty() || tail != decl.name {
        return None;
    }
    Some(prefix)
}

fn module_default_export_funcs_by_module(
    global: &GlobalIndex,
    module_prefixes: &AHashMap<FileId, String>,
) -> AHashMap<String, Vec<FuncId>> {
    let mut by_module: AHashMap<String, Vec<FuncId>> = AHashMap::new();
    for file in global.all_files() {
        let Some(module_prefix) = module_prefixes.get(&file) else {
            continue;
        };
        for decl in global.functions_in(file) {
            if matches!(decl.name.as_str(), "default" | "exports") {
                by_module
                    .entry(module_prefix.clone())
                    .or_default()
                    .push(FuncId::new(decl.symbol.raw()));
            }
        }
    }
    by_module
}

fn import_module_candidates(caller_module: &str, original: &str) -> Vec<String> {
    let target = original
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'))
        .trim();
    if target.is_empty() || target == "default" || !looks_like_module_path(target) {
        return Vec::new();
    }

    let mut out = Vec::new();
    if target.starts_with('.') {
        let mut parts: Vec<String> = caller_module
            .split('.')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect();
        parts.pop();
        for segment in target.split(['/', '\\']) {
            match segment {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                segment => parts.push(strip_known_source_extension(segment).to_string()),
            }
        }
        if !parts.is_empty() {
            out.push(parts.join("."));
        }
    } else {
        let mut parts = Vec::new();
        for segment in target.split(['/', '\\']) {
            if !segment.is_empty() {
                parts.push(strip_known_source_extension(segment));
            }
        }
        if !parts.is_empty() {
            out.push(parts.join("."));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn looks_like_module_path(value: &str) -> bool {
    value.starts_with('.') || value.contains('/') || value.contains('\\')
}

fn strip_known_source_extension(segment: &str) -> &str {
    for suffix in [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"] {
        if let Some(stripped) = segment.strip_suffix(suffix) {
            return stripped;
        }
    }
    segment
}

fn idg_build_enabled() -> bool {
    bonsai_diagnostics::debug::is_enabled("idg-build")
}

fn idg_build_log(args: std::fmt::Arguments<'_>) {
    if idg_build_enabled() {
        let message = bonsai_diagnostics::debug::render_message(&args.to_string());
        eprintln!("[idg-build] {message}");
    }
}

fn propagation_scope_files(
    global: &GlobalIndex,
    file_to_language: &AHashMap<FileId, &'static str>,
) -> Vec<FileId> {
    let mut files: Vec<FileId> = if file_to_language.is_empty() {
        global.all_files().collect()
    } else {
        file_to_language.keys().copied().collect()
    };
    files.sort_by_key(|file| file.raw());
    files
}

struct SegmentOffsets {
    by_segment: AHashMap<crate::SegmentId, u32>,
    ranges: Vec<(u32, u32, crate::SegmentId)>,
}

impl SegmentOffsets {
    fn new(ws: &IdgWorkspace) -> Self {
        let mut by_segment = AHashMap::new();
        let mut ranges = Vec::new();
        let mut offset = 0u32;
        for (seg_id, segment) in ws.segments() {
            let len = segment.nodes.len() as u32;
            by_segment.insert(seg_id, offset);
            ranges.push((offset, offset.saturating_add(len), seg_id));
            offset = offset.saturating_add(len);
        }
        Self { by_segment, ranges }
    }
}

/// Phase 3d: implicit-receiver propagation through method calls.
/// When a caller calls a method with a tainted receiver, the
/// closure needs to enter the callee and taint its reads of class
/// fields. The IDG transfer pass models the receiver-bridge as a
/// `Place::CallArg{site, idx=u32::MAX}` slot in the caller, but
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
    resolver: &WorkspaceCalleeResolver<'_>,
    func_to_language: &AHashMap<FuncId, &'static str>,
    file_to_language: &AHashMap<FileId, &'static str>,
    func_to_scope: &AHashMap<FuncId, LocalScopeKey>,
    symbol_to_scope: &AHashMap<bonsai_common::SymbolId, LocalScopeKey>,
) {
    use crate::edge::IdgEdgeKind;
    use bonsai_common::SymbolId;
    use bonsai_lang_api::DeclKind;
    let scope_files = propagation_scope_files(global, file_to_language);
    let offsets = SegmentOffsets::new(ws);
    // Group decls by parent so we know each class's known fields.
    // Reuse the field-flow scoping (parent-only buckets) so we
    // don't over-link free functions. Walk the inheritance chain
    // via `decl.bases` so a subclass method that reads a base
    // class's field still finds the field-write in the base
    // class's bucket. Mirror Phase 3c's traversal.
    let class_by_name: ahash::AHashMap<(Option<&'static str>, String, LocalScopeKey), SymbolId> = scope_files
        .iter()
        .copied()
        .flat_map(|file| {
            let language = file_language(file_to_language, file);
            global
                .decls_in(file)
                .iter()
                .filter(|decl| matches!(decl.kind, DeclKind::Class))
                .filter_map(move |decl| {
                    let scope = symbol_to_scope.get(&decl.symbol)?;
                    Some(((language, decl.name.clone(), scope.clone()), decl.symbol))
                })
        })
        .collect();
    let mut by_class: ahash::AHashMap<SymbolId, Vec<FuncId>> = ahash::AHashMap::default();
    let mut methods_by_class_and_name: ahash::AHashMap<(SymbolId, String), Vec<FuncId>> =
        ahash::AHashMap::default();
    for file in &scope_files {
        let file = *file;
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let Some(parent) = decl.parent else { continue };
            let func = FuncId::new(decl.symbol.raw());
            methods_by_class_and_name
                .entry((parent, decl.name.clone()))
                .or_default()
                .push(func);
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
                let class_language = symbol_language(global, file_to_language, class_sym);
                let Some(class_scope) = symbol_to_scope.get(&class_sym) else {
                    continue;
                };
                for base_name in &class_decl.bases {
                    let Some(&base_sym) =
                        class_by_name.get(&(class_language, base_name.clone(), class_scope.clone()))
                    else {
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
    let mut delegates_by_func: ahash::AHashMap<FuncId, bool> = ahash::AHashMap::default();
    let mut field_write_names_by_func: ahash::AHashMap<FuncId, ahash::AHashSet<String>> =
        ahash::AHashMap::default();
    let mut field_read_nodes_by_func: FieldReadNodesByFunc = ahash::AHashMap::default();
    let mut recv_nodes_by_func: RecvNodesByFunc = ahash::AHashMap::default();
    let mut recv_slots_by_call: RecvSlotsByCall = ahash::AHashMap::default();
    for class_sym in sorted_classes {
        let mut funcs = match by_class.get(&class_sym) {
            Some(v) => v.clone(),
            None => continue,
        };
        funcs.sort_by_key(|f| f.raw());
        funcs.dedup();
        // Discover the class's writable field set. Use the same
        // canonicalisation as Phase 3c so sigil'd / qualified
        // writes bucket onto the same key as bare-name reads.
        let mut field_names: ahash::AHashSet<String> = ahash::AHashSet::default();
        for func in &funcs {
            let names = field_write_names_by_func.entry(*func).or_insert_with(|| {
                let mut names: ahash::AHashSet<String> = ahash::AHashSet::default();
                collect_field_write_names(ws, global, *func, &mut names);
                // Also include the function's own decl name as a
                // potential field key — getters / property
                // accessors (`def cmd; @data[:cmd]; end`,
                // `get cmd() => this._data.cmd`) return values that
                // peers consume by name. Without this, a peer
                // method's `Read("cmd")` doesn't pair with the
                // getter's Return.
                if let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) {
                    let canonical = canonical_field_component(&decl.name);
                    if !canonical.is_empty() {
                        names.insert(canonical);
                    }
                }
                names
            });
            field_names.extend(names.iter().cloned());
        }
        if field_names.is_empty() {
            continue;
        }
        for callee in funcs {
            // Locate every `Place::Read{name, path: []}` ws_node in
            // `callee` whose canonical name is one of the class's
            // writable fields.
            let mut read_nodes = {
                let reads_by_name = field_read_nodes_by_func
                    .entry(callee)
                    .or_insert_with(|| collect_field_read_nodes_by_name(ws, &offsets, global, callee));
                field_read_nodes_matching(reads_by_name, &field_names)
            };
            // Also include every recv-slot CallArg in the callee's
            // body. This carries the receiver-tainted state through
            // intermediate methods that don't read class fields
            // directly (`AuditedRepository.run()` body is just
            // `return super.run()` — no field reads, but its super
            // recv-slot needs to be tainted so the next Phase 3d
            // pair `(run, super.run)` finds the recv-slot in the
            // closure).
            let recv_targets = recv_nodes_by_func
                .entry(callee)
                .or_insert_with(|| collect_recv_slot_nodes(ws, &offsets, global, callee))
                .clone();
            for n in &recv_targets {
                if !read_nodes.contains(n) {
                    read_nodes.push(*n);
                }
            }
            for n in receiver_accessor_return_nodes(ws, &offsets, global, callee, &field_names) {
                if !read_nodes.contains(&n) {
                    read_nodes.push(n);
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
            let delegates = *delegates_by_func
                .entry(callee)
                .or_insert_with(|| callee_body_delegates_to_ancestor(call_graph, resolver, callee));
            let mut super_chain_funcs: Vec<FuncId> = Vec::new();
            if read_nodes.is_empty() || delegates {
                let extras = collect_super_chain_read_nodes_and_funcs(
                    ws,
                    global,
                    callee,
                    &class_by_name,
                    &methods_by_class_and_name,
                    &field_names,
                    func_to_language,
                    file_to_language,
                    func_to_scope,
                    symbol_to_scope,
                    &offsets,
                    &mut field_read_nodes_by_func,
                    &mut recv_nodes_by_func,
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
            // idx=u32::MAX}` ws_node in the caller's segment and
            // emit edges into each field-Read of the callee.
            for edge in call_graph.callers_of(callee) {
                let caller = edge.from;
                if !funcs_share_language(func_to_language, caller, callee) {
                    continue;
                }
                let recv_slots = recv_slots_by_call
                    .entry((caller, edge.span))
                    .or_insert_with(|| recv_slots_for_call_span(ws, &offsets, global, caller, edge.span))
                    .clone();
                let mut emitted_link_for_call = false;
                for (recv_ws, callee_target) in recv_slots {
                    if let Some(target) = callee_target {
                        add_edge_between_ws_nodes(
                            ws,
                            &offsets,
                            recv_ws,
                            target,
                            IdgEdgeKind::IntraRead,
                            bonsai_common::Precision::Narrowed,
                        );
                    } else {
                        for read_ws in &read_nodes {
                            add_edge_between_ws_nodes(
                                ws,
                                &offsets,
                                recv_ws,
                                *read_ws,
                                IdgEdgeKind::IntraRead,
                                bonsai_common::Precision::Narrowed,
                            );
                        }
                    }
                    if !emitted_link_for_call {
                        let recv_span = ws_node_span(ws, &offsets, recv_ws)
                            .or_else(|| func_name_span(global, caller))
                            .unwrap_or_else(|| bonsai_common::Span::empty(bonsai_common::FileId::INVALID, 0));
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
                            precision: bonsai_common::Precision::Narrowed,
                        });
                        emitted_link_for_call = true;
                    }
                }
            }
        }
    }
}

/// Collect the canonical names of every `Place::Write{path-empty}`
/// or qualified `Place::Write{name=<declared receiver>, path=[field, ..]}`
/// in `func`'s segment, PLUS the canonical name of the func itself
/// (so peer-class getters / property accessors expose their decl
/// name as a field key — `def cmd` returning a tainted value
/// surfaces "cmd" as a field-readable name on the class).
fn collect_field_write_names(
    ws: &IdgWorkspace,
    global: &GlobalIndex,
    func: FuncId,
    out: &mut ahash::AHashSet<String>,
) {
    use crate::place::Place;
    let Some(seg_id) = ws.segment_for_func(func) else {
        return;
    };
    let Some(segment) = ws.segment(seg_id) else {
        return;
    };
    let receiver_names = global
        .decl_of(bonsai_common::SymbolId::new(func.raw()))
        .map(declared_receiver_names)
        .unwrap_or_default();
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        let canonical = match place {
            Place::Write { name, path, .. } if path.is_empty() => {
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                canonical_field_name(s, &receiver_names)
            }
            Place::Write { name, path, .. } if !path.is_empty() => {
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                if !receiver_name_matches(s, &receiver_names) {
                    continue;
                }
                let Some(projected) = canonical_projected_path(segment, path) else {
                    continue;
                };
                projected
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

fn field_read_head(
    segment: &crate::segment::IdgSegment,
    place: &crate::place::Place,
    receiver_names: &[String],
) -> Option<String> {
    let crate::place::Place::Read { name, path } = place else {
        return None;
    };
    let s = segment.strings.get(*name)?;
    if path.is_empty() {
        let canonical = canonical_field_name(s, receiver_names);
        let head = canonical.split('.').next().unwrap_or(&canonical);
        Some(head.to_string())
    } else if receiver_name_matches(s, receiver_names) {
        canonical_projected_path(segment, path)
    } else {
        None
    }
}

fn canonical_projected_path(
    segment: &crate::segment::IdgSegment,
    path: &smallvec::SmallVec<[bonsai_factstore::StrId; 4]>,
) -> Option<String> {
    let mut parts = Vec::new();
    for part in path {
        let canonical = canonical_field_component(segment.strings.get(*part)?);
        if !canonical.is_empty() {
            parts.push(canonical);
        }
    }
    (!parts.is_empty()).then(|| parts.join("."))
}

fn collect_field_read_nodes_by_name(
    ws: &IdgWorkspace,
    offsets: &SegmentOffsets,
    global: &GlobalIndex,
    func: FuncId,
) -> ahash::AHashMap<String, Vec<crate::WsNodeId>> {
    use crate::place::Place;
    let Some(seg_id) = ws.segment_for_func(func) else {
        return ahash::AHashMap::default();
    };
    let Some(segment) = ws.segment(seg_id) else {
        return ahash::AHashMap::default();
    };
    let receiver_names = global
        .decl_of(bonsai_common::SymbolId::new(func.raw()))
        .map(declared_receiver_names)
        .unwrap_or_default();
    let mut out: ahash::AHashMap<String, Vec<crate::WsNodeId>> = ahash::AHashMap::default();
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        let Some(head_field) = field_read_head(segment, place, &receiver_names) else {
            continue;
        };
        if head_field.is_empty() {
            continue;
        }
        let Place::Read { .. } = place else {
            continue;
        };
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(local) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        let Some(ws_node) = ws_node_for(offsets, seg_id, local) else {
            continue;
        };
        out.entry(head_field).or_default().push(ws_node);
    }
    for nodes in out.values_mut() {
        nodes.sort();
        nodes.dedup();
    }
    out
}

fn field_read_nodes_matching(
    reads_by_name: &ahash::AHashMap<String, Vec<crate::WsNodeId>>,
    field_names: &ahash::AHashSet<String>,
) -> Vec<crate::WsNodeId> {
    let mut out = Vec::new();
    for field in field_names {
        if let Some(nodes) = reads_by_name.get(field) {
            out.extend(nodes.iter().copied());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn receiver_accessor_return_nodes(
    ws: &IdgWorkspace,
    offsets: &SegmentOffsets,
    global: &GlobalIndex,
    func: FuncId,
    field_names: &ahash::AHashSet<String>,
) -> Vec<crate::WsNodeId> {
    let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
        return Vec::new();
    };
    let accessor_name = canonical_field_component(&decl.name);
    if accessor_name.is_empty() || !field_names.contains(&accessor_name) {
        return Vec::new();
    }
    if !function_returns_accessor_named(&decl.flow_events, &accessor_name) {
        return Vec::new();
    }
    collect_return_nodes(ws, offsets, func)
}

fn collect_return_nodes(ws: &IdgWorkspace, offsets: &SegmentOffsets, func: FuncId) -> Vec<crate::WsNodeId> {
    use crate::place::Place;
    let Some(seg_id) = ws.segment_for_func(func) else {
        return Vec::new();
    };
    let Some(segment) = ws.segment(seg_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        if !matches!(place, Place::Return | Place::Yield) {
            continue;
        }
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(local) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        let Some(ws_node) = ws_node_for(offsets, seg_id, local) else {
            continue;
        };
        out.push(ws_node);
    }
    out.sort();
    out.dedup();
    out
}

fn function_returns_accessor_named(events: &[bonsai_lang_api::FlowEvent], field_name: &str) -> bool {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Return { value_flow, .. } => {
                if value_flow.projection.as_ref().is_some_and(|projection| {
                    projection
                        .path
                        .last()
                        .is_some_and(|tail| canonical_field_component(tail) == field_name)
                }) {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if function_returns_accessor_named(then_events, field_name)
                    || function_returns_accessor_named(else_events, field_name)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if function_returns_accessor_named(body, field_name) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if function_returns_accessor_named(body, field_name)
                    || function_returns_accessor_named(catch_events, field_name)
                    || function_returns_accessor_named(finally_events, field_name)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// True when the resolved callgraph proves that `callee` dispatches into a
/// method owned by one of its declaration's ancestor classes. Receiver
/// spelling is intentionally irrelevant: language adapters/call resolution
/// already interpreted that syntax before the IDG sees it.
fn callee_body_delegates_to_ancestor(
    call_graph: &ResolvedCallGraph,
    resolver: &WorkspaceCalleeResolver<'_>,
    callee: FuncId,
) -> bool {
    let Some(decl) = resolver
        .global
        .decl_of(bonsai_common::SymbolId::new(callee.raw()))
    else {
        return false;
    };
    let receiver_names = declared_receiver_names(decl);
    call_graph.callees_of(callee).any(|edge| {
        resolver.is_ancestor_dispatch(callee, edge.to)
            && call_site_uses_declared_receiver(&decl.flow_events, edge.span, &receiver_names)
    })
}

fn call_site_uses_declared_receiver(
    events: &[FlowEvent],
    site: bonsai_common::Span,
    receiver_names: &[String],
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span, name, receiver, ..
            } if *span == site => {
                if receiver
                    .as_deref()
                    .is_some_and(|receiver| receiver_name_matches(receiver, receiver_names))
                {
                    return true;
                }
                let head_end = name.find(['.', '(', ':']).unwrap_or(name.len());
                if receiver_name_matches(&name[..head_end], receiver_names) {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if call_site_uses_declared_receiver(then_events, site, receiver_names)
                    || call_site_uses_declared_receiver(else_events, site, receiver_names)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if call_site_uses_declared_receiver(body, site, receiver_names) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if call_site_uses_declared_receiver(body, site, receiver_names)
                    || call_site_uses_declared_receiver(catch_events, site, receiver_names)
                    || call_site_uses_declared_receiver(finally_events, site, receiver_names)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Collect `read_nodes` from every ancestor class's method of the
/// same name as `callee`. The caller of `callee` may have only the
/// override in its callgraph adjacency, but the actual taint flow
/// reaches the parent body via `super`. Walks `decl.bases`
/// transitively.
#[allow(clippy::too_many_arguments)] // Super-chain collection needs workspace, language, cache, and receiver-node state.
fn collect_super_chain_read_nodes_and_funcs(
    ws: &IdgWorkspace,
    global: &GlobalIndex,
    callee: FuncId,
    class_by_name: &ahash::AHashMap<(Option<&'static str>, String, LocalScopeKey), bonsai_common::SymbolId>,
    methods_by_class_and_name: &ahash::AHashMap<(bonsai_common::SymbolId, String), Vec<FuncId>>,
    field_names: &ahash::AHashSet<String>,
    func_to_language: &AHashMap<FuncId, &'static str>,
    file_to_language: &AHashMap<FileId, &'static str>,
    _func_to_scope: &AHashMap<FuncId, LocalScopeKey>,
    symbol_to_scope: &AHashMap<bonsai_common::SymbolId, LocalScopeKey>,
    offsets: &SegmentOffsets,
    field_read_nodes_by_func: &mut FieldReadNodesByFunc,
    recv_nodes_by_func: &mut RecvNodesByFunc,
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
        let parent_language = symbol_language(global, file_to_language, parent_sym);
        let parent_scope = symbol_to_scope.get(&parent_sym);
        for base_name in &parent_decl.bases {
            let Some(parent_scope) = parent_scope else {
                continue;
            };
            if let Some(&base_sym) =
                class_by_name.get(&(parent_language, base_name.clone(), parent_scope.clone()))
            {
                if visited.insert(base_sym) {
                    frontier.push(base_sym);
                }
            }
        }
    }
    while let Some(class_sym) = frontier.pop() {
        // For every method in this class with the same name as
        // `callee`, fold in its read_nodes.
        if let Some(methods) = methods_by_class_and_name.get(&(class_sym, method_name.clone())) {
            for other in methods {
                let other = *other;
                if !funcs_share_language(func_to_language, callee, other) {
                    continue;
                }
                let mut nodes = {
                    let reads_by_name = field_read_nodes_by_func
                        .entry(other)
                        .or_insert_with(|| collect_field_read_nodes_by_name(ws, offsets, global, other));
                    field_read_nodes_matching(reads_by_name, field_names)
                };
                let recv = recv_nodes_by_func
                    .entry(other)
                    .or_insert_with(|| collect_recv_slot_nodes(ws, offsets, global, other))
                    .clone();
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
            let class_language = symbol_language(global, file_to_language, class_sym);
            let Some(class_scope) = symbol_to_scope.get(&class_sym) else {
                continue;
            };
            for base_name in &class_decl.bases {
                if let Some(&base_sym) =
                    class_by_name.get(&(class_language, base_name.clone(), class_scope.clone()))
                {
                    if visited.insert(base_sym) {
                        frontier.push(base_sym);
                    }
                }
            }
        }
    }
    out
}

fn collect_recv_slot_nodes(
    ws: &IdgWorkspace,
    offsets: &SegmentOffsets,
    global: &GlobalIndex,
    func: FuncId,
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
        let Place::CallArg { site, idx } = place else {
            continue;
        };
        if *idx != u32::MAX && !(*idx == 0 && call_site_has_no_explicit_args(global, func, site.0)) {
            continue;
        }
        let pid = crate::node::PlaceId(pid_idx as u32);
        let Some(local) = segment.nodes.lookup(func, pid) else {
            continue;
        };
        let Some(ws_node) = ws_node_for(offsets, seg_id, local) else {
            continue;
        };
        out.push(ws_node);
    }
    out.sort();
    out.dedup();
    out
}

/// Return every receiver-bridge `Place::CallArg{site, idx=u32::MAX}`
/// ws_node in `caller`'s segment for one already-resolved call
/// site. The second tuple element is `None` for the generic fan-out
/// case (caller-side receiver-bridge taints all of callee's field
/// reads). Future work could narrow this to a specific Read node
/// when the callee's parameter list pins the field reference
/// precisely.
fn recv_slots_for_call_span(
    ws: &IdgWorkspace,
    offsets: &SegmentOffsets,
    global: &GlobalIndex,
    caller: FuncId,
    span: bonsai_common::Span,
) -> Vec<(crate::WsNodeId, Option<crate::WsNodeId>)> {
    use crate::place::Place;
    let mut out: Vec<(crate::WsNodeId, Option<crate::WsNodeId>)> = Vec::new();
    let Some(seg_id) = ws.segment_for_func(caller) else {
        return out;
    };
    let Some(segment) = ws.segment(seg_id) else {
        return out;
    };
    // Emit from the receiver-bridge slot (`idx=u32::MAX`). Older
    // adapter shapes also route receiver tokens through `idx=0` for
    // argument-less calls, but for calls with explicit arguments
    // `idx=0` is the first real argument.
    let try_indices: &[u32] = if call_site_has_no_explicit_args(global, caller, span) {
        &[u32::MAX, 0u32]
    } else {
        &[u32::MAX]
    };
    for try_idx in try_indices {
        let place = Place::CallArg {
            site: crate::CallSiteId(span),
            idx: *try_idx,
        };
        let Some(pid) = segment.places.lookup(&place) else {
            continue;
        };
        let Some(local) = segment.nodes.lookup(caller, pid) else {
            continue;
        };
        let Some(ws_node) = ws_node_for(offsets, seg_id, local) else {
            continue;
        };
        out.push((ws_node, None));
    }
    out
}

/// Strip generic / qualified prefix off a class-like callee name.
/// Handles `AuditedRepository<T>` -> `AuditedRepository`,
/// `mod.Foo` -> `Foo`, `Foo::Bar` -> `Bar`. Empty input or
/// non-identifier residue returns empty.
fn bare_class_name(name: &str) -> &str {
    let trimmed = name.trim();
    let mut s = trimmed;
    if let Some(idx) = s.find('<') {
        s = &s[..idx];
    }
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

fn push_unique_class_name(out: &mut Vec<String>, value: String) {
    if !out.iter().any(|existing| existing == &value) {
        out.push(value);
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
fn stitch_receiver_field_flow(
    ws: &mut IdgWorkspace,
    global: &GlobalIndex,
    func_to_language: &AHashMap<FuncId, &'static str>,
    file_to_language: &AHashMap<FileId, &'static str>,
    symbol_to_scope: &AHashMap<bonsai_common::SymbolId, LocalScopeKey>,
) {
    use crate::edge::IdgEdgeKind;
    use bonsai_common::SymbolId;
    use bonsai_lang_api::DeclKind;
    let scope_files = propagation_scope_files(global, file_to_language);
    let offsets = SegmentOffsets::new(ws);
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
    let class_by_name: ahash::AHashMap<(Option<&'static str>, String, LocalScopeKey), SymbolId> = scope_files
        .iter()
        .copied()
        .flat_map(|file| {
            let language = file_language(file_to_language, file);
            global
                .decls_in(file)
                .iter()
                .filter(|decl| matches!(decl.kind, DeclKind::Class))
                .filter_map(move |decl| {
                    let scope = symbol_to_scope.get(&decl.symbol)?;
                    Some(((language, decl.name.clone(), scope.clone()), decl.symbol))
                })
        })
        .collect();
    for file in &scope_files {
        let file = *file;
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
                    let class_language = symbol_language(global, file_to_language, class_sym);
                    let Some(class_scope) = symbol_to_scope.get(&class_sym) else {
                        continue;
                    };
                    for base_name in &class_decl.bases {
                        let Some(&base_sym) =
                            class_by_name.get(&(class_language, base_name.clone(), class_scope.clone()))
                        else {
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
            collect_field_nodes(
                ws,
                &offsets,
                global,
                *func,
                &mut writes_by_field,
                &mut reads_by_field,
            );
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
            let canonical = canonical_field_component(&decl.name);
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
            let Some(ws_node) = ws_node_for(&offsets, seg_id, local) else {
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
                    if !funcs_share_language(func_to_language, *w_func, *r_func) {
                        continue;
                    }
                    add_edge_between_ws_nodes(
                        ws,
                        &offsets,
                        *w_ws,
                        *r_ws,
                        IdgEdgeKind::IntraAssign,
                        bonsai_common::Precision::Narrowed,
                    );
                    // Record the link so the query layer can lift
                    // it into a synthetic CrossCallEdge for the
                    // security-analysis lineage walk. Without this
                    // the IDG forward closure correctly reaches the
                    // reader's CallArg(sink) but the lineage can't
                    // attribute the chain to (writer, reader)
                    // because no cross-call edge with callee=reader
                    // ever appears in `call_records`. The synthetic
                    // edge fills that role with `arg_idx = u32::MAX`
                    // and `param_idx = u32::MAX` so it can't be
                    // confused with a real positional-arg edge.
                    let writer_span = ws_node_span(ws, &offsets, *w_ws)
                        .or_else(|| func_name_span(global, *w_func))
                        .unwrap_or_else(|| bonsai_common::Span::empty(bonsai_common::FileId::INVALID, 0));
                    ws.field_flow_mut().push(crate::workspace::FieldFlowLink {
                        writer: *w_func,
                        reader: *r_func,
                        writer_ws_node: w_ws.0,
                        reader_ws_node: r_ws.0,
                        via_span: writer_span,
                        precision: bonsai_common::Precision::Narrowed,
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
    offsets: &SegmentOffsets,
    global: &GlobalIndex,
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
    let receiver_names = global
        .decl_of(bonsai_common::SymbolId::new(func.raw()))
        .map(declared_receiver_names)
        .unwrap_or_default();
    for (pid_idx, place) in segment.places.places.iter().enumerate() {
        // Three place shapes contribute to field flow:
        //   * `Place::Write { name, path: [] }` where `name` is
        //     sigil'd (`@cmd`, `$cmd`) or qualified (`self.cmd`).
        //     Bare locals fall through.
        //   * `Place::Write { name = <declared receiver>, path = ["field", ..] }`
        //     — `this.cmd = X` style assignments. Canonical key is
        //     the full projected path, so `self._data.cmd` does not
        //     collapse into sibling `self._data.user`.
        //   * `Place::Read` accepts both path-empty sigil/bare names
        //     and projected receiver paths. Bare-tail reads only pair
        //     with sigil'd / qualified writes via the canonical key at
        //     edge-emit time.
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
                (true, canonical_field_name(s, &receiver_names))
            }
            Place::Write { name, path, .. } if !path.is_empty() => {
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                if !receiver_name_matches(s, &receiver_names) {
                    continue;
                }
                let Some(projected) = canonical_projected_path(segment, path) else {
                    continue;
                };
                (true, projected)
            }
            Place::Read { name, path } if path.is_empty() => {
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                (false, canonical_field_name(s, &receiver_names))
            }
            Place::Read { name, path } if !path.is_empty() => {
                let Some(s) = segment.strings.get(*name) else {
                    continue;
                };
                if !receiver_name_matches(s, &receiver_names) {
                    continue;
                }
                let Some(projected) = canonical_projected_path(segment, path) else {
                    continue;
                };
                (false, projected)
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
        let Some(ws_node) = ws_node_for(offsets, seg_id, local) else {
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
/// `WsNodeId` via the same unified address space as `IdgQueryService`.
fn ws_node_for(
    offsets: &SegmentOffsets,
    seg_id: crate::SegmentId,
    local: crate::node::NodeId,
) -> Option<crate::WsNodeId> {
    offsets
        .by_segment
        .get(&seg_id)
        .map(|base| crate::WsNodeId(base.saturating_add(local.0)))
}

/// Strip language-specific sigils and receiver prefixes off a
/// field name so peer methods spelling the same field differently
/// (Ruby `@cmd` vs Python `self.cmd` vs PHP `$this->cmd`) all
/// bucket into the same canonical key.
fn canonical_field_name(name: &str, receiver_names: &[String]) -> String {
    let normalized = name.trim().replace("->", ".");
    if let Some((root, field)) = normalized.split_once('.') {
        if receiver_name_matches(root, receiver_names) {
            return canonical_field_component(field);
        }
    }
    canonical_field_component(&normalized)
}

fn canonical_field_component(name: &str) -> String {
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
    offsets: &SegmentOffsets,
    from: crate::WsNodeId,
    to: crate::WsNodeId,
    kind: crate::edge::IdgEdgeKind,
    precision: bonsai_common::Precision,
) {
    let Some((from_seg, from_local)) = ws_node_to_local(ws, offsets, from) else {
        return;
    };
    let Some((to_seg, to_local)) = ws_node_to_local(ws, offsets, to) else {
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
fn ws_node_span(
    ws: &IdgWorkspace,
    offsets: &SegmentOffsets,
    ws_node: crate::WsNodeId,
) -> Option<bonsai_common::Span> {
    use crate::place::Place;
    let (seg_id, local) = ws_node_to_local(ws, offsets, ws_node)?;
    let segment = ws.segment(seg_id)?;
    let node = segment.nodes.get(local)?;
    let place = segment.places.places.get(node.place.0 as usize)?;
    match place {
        Place::Write { span, .. } => Some(*span),
        Place::CallArg { site, .. } | Place::CallRet { site } => Some(site.0),
        _ => None,
    }
}

fn func_name_span(global: &GlobalIndex, func: FuncId) -> Option<bonsai_common::Span> {
    global
        .decl_of(bonsai_common::SymbolId::new(func.raw()))
        .map(|decl| decl.name_span)
}

/// Reverse [`ws_node_for`] — given a workspace `WsNodeId`, find
/// the (segment, local) pair it lives in.
fn ws_node_to_local(
    ws: &IdgWorkspace,
    offsets: &SegmentOffsets,
    ws_node: crate::WsNodeId,
) -> Option<(crate::SegmentId, crate::node::NodeId)> {
    let idx = offsets.ranges.partition_point(|(_, end, _)| *end <= ws_node.0);
    let (start, end, seg_id) = *offsets.ranges.get(idx)?;
    if ws_node.0 >= end {
        return None;
    }
    let local = crate::node::NodeId(ws_node.0.saturating_sub(start));
    let segment = ws.segment(seg_id)?;
    (local.0 < segment.nodes.len() as u32).then_some((seg_id, local))
}

/// Run the transfer pass on every function in the workspace, in
/// parallel. Each function's transfer is independent (it only
/// reads its own `Decl`), so this is embarrassingly parallel via
/// rayon.
fn run_transfer_in_parallel_for_files(
    global: &GlobalIndex,
    transfer_options: &TransferOptions,
    included_files: Option<&AHashSet<FileId>>,
    included_funcs: Option<&AHashSet<FuncId>>,
) -> Vec<TransferOutput> {
    let aggregate_layouts = unambiguous_aggregate_layouts(global);
    // Collect every (FileId, decl-index) pair so rayon can split
    // them across threads. Each transfer call produces a
    // `TransferOutput` with its own embedded name pool — the
    // segment merge re-interns names into the segment-level pool,
    // so per-call name spaces don't conflict.
    let mut funcs: Vec<(FileId, &bonsai_lang_api::Decl)> = Vec::new();
    for file in global.all_files() {
        if included_files.is_some_and(|files| !files.contains(&file)) {
            continue;
        }
        for decl in global.functions_in(file) {
            let func = FuncId::new(decl.symbol.raw());
            if included_funcs.is_some_and(|funcs| !funcs.contains(&func)) {
                continue;
            }
            funcs.push((file, decl));
        }
    }
    funcs
        .into_par_iter()
        .map(|(_file, decl)| {
            if aggregate_layouts.is_empty() || !flow_events_contain_aggregate_assign(&decl.flow_events) {
                return transfer_function_for_with_options(decl, transfer_options);
            }
            let mut resolved = decl.clone();
            resolve_aggregate_assignments(
                &mut resolved.flow_events,
                &resolved.type_aliases,
                &aggregate_layouts,
            );
            transfer_function_for_with_options(&resolved, transfer_options)
        })
        .collect()
}

fn unambiguous_aggregate_layouts(global: &GlobalIndex) -> AHashMap<String, Vec<String>> {
    let mut candidates: AHashMap<String, Option<Vec<String>>> = AHashMap::new();
    for layout in global.aggregate_layouts() {
        let key = bonsai_lang_api::kit::canonical_simple_type_name(&layout.type_name);
        if key.is_empty() || layout.fields.is_empty() {
            continue;
        }
        candidates
            .entry(key)
            .and_modify(|known| {
                if known.as_ref().is_some_and(|fields| fields != &layout.fields) {
                    *known = None;
                }
            })
            .or_insert_with(|| Some(layout.fields.clone()));
    }
    let layouts: AHashMap<String, Vec<String>> = candidates
        .into_iter()
        .filter_map(|(name, fields)| fields.map(|fields| (name, fields)))
        .collect();
    idg_build_log(format_args!("aggregate layouts: {}", layouts.len()));
    layouts
}

fn flow_events_contain_aggregate_assign(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::AggregateAssign { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            flow_events_contain_aggregate_assign(then_events)
                || flow_events_contain_aggregate_assign(else_events)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            flow_events_contain_aggregate_assign(body)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            flow_events_contain_aggregate_assign(body)
                || flow_events_contain_aggregate_assign(catch_events)
                || flow_events_contain_aggregate_assign(finally_events)
        }
        _ => false,
    })
}

fn resolve_aggregate_assignments(
    events: &mut [FlowEvent],
    aliases: &[bonsai_lang_api::TypeAliasBinding],
    layouts: &AHashMap<String, Vec<String>>,
) {
    for event in events {
        match event {
            FlowEvent::AggregateAssign {
                target,
                type_name,
                value_flow,
                ..
            } => {
                if value_flow.tuple_items.is_empty() || !value_flow.aggregate_fields.is_empty() {
                    continue;
                }
                let declared_type = type_name.as_deref().or_else(|| {
                    aliases
                        .iter()
                        .find(|alias| alias.name == *target)
                        .map(|alias| alias.type_name.as_str())
                });
                let Some(declared_type) = declared_type else {
                    continue;
                };
                let key = bonsai_lang_api::kit::canonical_simple_type_name(declared_type);
                let Some(fields) = layouts.get(&key) else {
                    idg_build_log(format_args!(
                        "aggregate unresolved: target={target} type={key} items={}",
                        value_flow.tuple_items.len()
                    ));
                    continue;
                };
                if value_flow.tuple_items.len() > fields.len() {
                    continue;
                }
                value_flow.aggregate_fields = value_flow
                    .tuple_items
                    .drain(..)
                    .zip(fields.iter().cloned())
                    .map(|(value, name)| bonsai_lang_api::ExpressionField { name, value })
                    .collect();
                idg_build_log(format_args!(
                    "aggregate resolved: target={target} type={key} fields={}",
                    value_flow.aggregate_fields.len()
                ));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                resolve_aggregate_assignments(then_events, aliases, layouts);
                resolve_aggregate_assignments(else_events, aliases, layouts);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                resolve_aggregate_assignments(body, aliases, layouts)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                resolve_aggregate_assignments(body, aliases, layouts);
                resolve_aggregate_assignments(catch_events, aliases, layouts);
                resolve_aggregate_assignments(finally_events, aliases, layouts);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "workspace_adapter_tests.rs"]
mod tests;
