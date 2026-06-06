//! Name-level reachability along a resolved call chain.
//!
//! Every chain is a `&[FuncId]` produced by the resolver + call-graph
//! enumeration layer. Traversal never searches the workspace by name
//! (no BFS / DFS over strings); it follows the shape the resolver
//! already decided. For each hop we:
//!
//! 1. Look up the `Decl` via `GlobalIndex` (hop_func_id → symbol → decl).
//! 2. Emit the decl's name and its parameter names.
//! 3. Walk the decl's structured `FlowEvent` tree, emitting call
//!    names, short-tails, argument keyword + value text, and assign
//!    target / source names.
//! 4. For the first visit to each hop's file, emit file-scoped facts
//!    reached *through the resolver*: class names in the file, import
//!    module / alias / original name via the per-file import index (or
//!    the parser's generic extractor as a fallback — never a workspace
//!    scan).
//! 5. Emit string literals and refs whose span lies inside the hop's
//!    decl body.
//!
//! The resulting set is the vocabulary `inspect --from X --to Y`
//! already matches against today — this crate is the named home for
//! that logic.

use ahash::AHashSet;
use bonsai_common::{FileId, FuncId, Precision, Span, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_index::GlobalIndex;
use bonsai_lang_api::FlowEvent;

/// Alias for the token set the reachability pass produces. Using a
/// set (not a vec) on the return boundary lets consumers query
/// membership in O(1) and spares callers from de-duplicating
/// themselves.
pub type TokenSet = AHashSet<String>;

/// Browse-fact kinds the reachability pass classifies tokens into.
/// Mirrors the
/// set `bonsai-ninja`'s browse commands expose (`defs`, `calls`,
/// `imports`, `vars`, `strings`, `args`, `refs`, `classes`) so
/// consumers can narrow `--from` / `--to` matching to a specific
/// browse surface. `Read` is the subset of `refs` with
/// `RefKind::Read`; we split it out because security rules often
/// want "read of X" vs "call of X" vs "write to X" distinctions.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FactKind {
    Decl,
    Call,
    TaintedCall,
    Read,
    Write,
    Arg,
    StringLit,
    Import,
    Class,
}

/// Per-kind token breakdown along a resolved call chain. Each
/// variant maps to the corresponding [`FactKind`]; consumers
/// typically look up `.by_kind.get(&FactKind::Read)` to answer
/// "is this name tainted as a read?".
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct KindedTokens {
    pub by_kind: ahash::AHashMap<FactKind, TokenSet>,
}

/// Indexed semantic taint graph for one entry function. Built during
/// workspace index and queried by security/inspect-style commands
/// without replaying interprocedural taint.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EntryTaintGraph {
    /// Caller→callee edges discovered during interprocedural propagation,
    /// each tagged with the precision of the resolution.
    pub call_records: Vec<TaintedCallEdge>,
    /// Leaf call sites where one or more arguments arrived tainted.
    pub tainted_calls: Vec<crate::inter::TaintedCall>,
    #[serde(default = "default_graph_precision")]
    pub precision: Precision,
    #[serde(default)]
    pub saturated: bool,
    /// Total `(func, seed)` pairs analyzed building this graph.
    /// Used by callers to budget global work across many entry sources.
    #[serde(default)]
    pub pairs_analyzed: u32,
}

impl Default for EntryTaintGraph {
    fn default() -> Self {
        Self {
            call_records: Vec::new(),
            tainted_calls: Vec::new(),
            precision: Precision::Exact,
            saturated: false,
            pairs_analyzed: 0,
        }
    }
}

/// Serde default for [`EntryTaintGraph::precision`] / [`TaintedCallEdge::precision`]
/// when older payloads (without the field) are deserialised — we
/// stay maximally precise rather than guess `Approximate`.
fn default_graph_precision() -> Precision {
    Precision::Exact
}

/// One caller→callee edge in the per-entry semantic taint graph,
/// tagged with the precision of the resolution that produced it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TaintedCallEdge {
    /// Stable edge trace ID from the interprocedural taint run.
    #[serde(default)]
    pub trace_id: u64,
    /// Parent edge trace ID, when this propagation edge was reached
    /// from another edge.
    #[serde(default)]
    pub parent_trace_id: Option<u64>,
    pub caller: FuncId,
    pub callee: FuncId,
    pub call_span: Span,
    #[serde(default)]
    pub tainted_args: Vec<crate::inter::TaintedArg>,
    #[serde(default = "default_graph_precision")]
    pub precision: Precision,
}

impl KindedTokens {
    /// Union of every kind's token set — flat membership check
    /// without preserving which fact bucket each token came from.
    #[must_use]
    pub fn flattened(&self) -> TokenSet {
        let mut flat: TokenSet = TokenSet::default();
        for tokens in self.by_kind.values() {
            flat.extend(tokens.iter().cloned());
        }
        flat
    }

    /// Insert `value` into the bucket for `kind`. No-op for empty
    /// strings — every adapter eventually emits a few of those (e.g.
    /// missing `source_name`), and we don't want them polluting the
    /// fact set or the consumer's `--from` filter.
    fn insert(&mut self, kind: FactKind, value: &str) {
        if value.is_empty() {
            return;
        }
        self.by_kind.entry(kind).or_default().insert(value.to_string());
    }
}

/// Walk a resolved call chain and return every lexical token a
/// `--from` / `--to` filter could plausibly match, bucketed by
/// browse-fact kind so callers can narrow matching to a specific
/// [`FactKind`] (`--from-kind read X` matches only when X appears
/// as a read reference, not as a call site, import, or string).
///
/// `chain` is typically the `funcs` vec from a
/// [`bonsai_callgraph::ResolvedCallGraph`] chain — the resolver
/// already decided which FuncIds make up this path, and this
/// function only inspects those hops. No name-based workspace search.
///
/// This is the **reachability** pass only — it collects visible
/// tokens along the chain but doesn't run data-flow. For the
/// taint-aware variant that augments the token set with
/// interprocedural propagation facts, combine
/// [`name_reachable_through_chain_kinded`] with
/// [`taint_facts_for_entry`] via [`merge_into`].
#[must_use]
pub fn name_reachable_through_chain_kinded(chain: &[FuncId], db: &AnalyzerDb) -> KindedTokens {
    let mut kinded = KindedTokens::default();
    let mut seen_files: AHashSet<FileId> = AHashSet::default();
    let global = db.global_index();

    for &hop_func_id in chain {
        let hop_symbol = SymbolId::new(hop_func_id.raw());
        let Some(hop_decl) = global.decl_of(hop_symbol) else {
            continue;
        };
        let hop_facts = name_reachable_through_func_kinded(hop_func_id, db);
        merge_into(&mut kinded, &hop_facts);

        if let Some(hop_file) = global.declaring_file(hop_decl.symbol) {
            if seen_files.insert(hop_file) {
                let file_facts = name_reachable_through_file_kinded(hop_file, db);
                merge_into(&mut kinded, &file_facts);
            }
        }
    }
    kinded
}

/// Per-FuncId reachability facts: decl name, parameter names, flow-event
/// tokens, and span-restricted string literals + refs that lie
/// inside the function's body. Excludes file-scoped facts (classes
/// and imports) — those are independent of the FuncId and are
/// expensive to recompute, so they live in
/// [`name_reachable_through_file_kinded`] and are folded into the
/// chain by `name_reachable_through_chain_kinded` once per unique
/// file.
///
/// Splitting per-FuncId from per-FileId lets the inspect filter
/// pipeline cache at the right granularity: chains share many hops
/// (e.g. requests's 5k chains visit ~200 unique decls), so caching
/// at the chain level recomputes the same hop's tokens hundreds of
/// times. Caching per FuncId computes each hop's tokens exactly
/// once per inspect invocation.
#[must_use]
pub fn name_reachable_through_func_kinded(func: FuncId, db: &AnalyzerDb) -> KindedTokens {
    let mut kinded = KindedTokens::default();
    let global = db.global_index();
    let symbol = SymbolId::new(func.raw());
    let Some(decl) = global.decl_of(symbol) else {
        return kinded;
    };
    kinded.insert(FactKind::Decl, &decl.name);
    for param_name in &decl.params {
        kinded.insert(FactKind::Decl, param_name);
    }
    collect_flow_event_tokens_kinded(&decl.flow_events, &mut kinded);

    let Some(file) = global.declaring_file(decl.symbol) else {
        return kinded;
    };
    let Some(file_index) = global.file_index(file) else {
        return kinded;
    };
    for string_literal in &file_index.strings {
        if span_contains(decl.span, string_literal.span) {
            kinded.insert(FactKind::StringLit, &string_literal.text);
        }
    }
    for reference in &file_index.refs {
        if !span_contains(decl.span, reference.span) {
            continue;
        }
        let kind = match reference.kind {
            bonsai_lang_api::RefKind::Read => FactKind::Read,
            bonsai_lang_api::RefKind::Write => FactKind::Write,
            bonsai_lang_api::RefKind::Call => FactKind::Call,
            bonsai_lang_api::RefKind::Type
            | bonsai_lang_api::RefKind::Macro
            | bonsai_lang_api::RefKind::Import
            | bonsai_lang_api::RefKind::Decorator
            | bonsai_lang_api::RefKind::Other => continue,
        };
        kinded.insert(kind, &reference.name);
        let short = short_callee(&reference.name);
        if short != reference.name.as_str() {
            kinded.insert(kind, short);
        }
    }
    kinded
}

/// File-scoped reachability facts: class / struct / trait / interface /
/// enum names declared anywhere in the file, plus every import
/// spec's module / alias / original name. Cached per FileId so a
/// chain that visits a file via N different hops only pays for
/// these once.
#[must_use]
pub fn name_reachable_through_file_kinded(file: FileId, db: &AnalyzerDb) -> KindedTokens {
    let mut kinded = KindedTokens::default();
    let global = db.global_index();
    if let Some(file_index) = global.file_index(file) {
        for decl in &file_index.defs {
            if matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Class
                    | bonsai_lang_api::DeclKind::Struct
                    | bonsai_lang_api::DeclKind::Trait
                    | bonsai_lang_api::DeclKind::Interface
                    | bonsai_lang_api::DeclKind::Enum
            ) {
                kinded.insert(FactKind::Class, &decl.name);
            }
        }
    }
    let import_specs = db.imports_for(file);
    for import_spec in &import_specs {
        kinded.insert(FactKind::Import, &import_spec.module);
        if let Some(alias) = &import_spec.alias {
            kinded.insert(FactKind::Import, alias);
        }
        if let Some(original_name) = &import_spec.original_name {
            kinded.insert(FactKind::Import, original_name);
        }
    }
    kinded
}

/// Walk a decl's flow events and slot every callee text, arg value /
/// keyword, assign target, and assign RHS name into the appropriate
/// [`FactKind`] bucket. Call names land in [`FactKind::Call`], arg
/// values/keywords in [`FactKind::Arg`], assignment targets in
/// [`FactKind::Write`], and assignment RHS names in [`FactKind::Read`].
/// Recurses through Branch / Loop / Try / Defer / Using.
fn collect_flow_event_tokens_kinded(events: &[FlowEvent], tokens: &mut KindedTokens) {
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } => {
                tokens.insert(FactKind::Call, name);
                let short = short_callee(name);
                if short != name.as_str() {
                    tokens.insert(FactKind::Call, short);
                }
                for arg in args {
                    if let Some(keyword_name) = &arg.name {
                        tokens.insert(FactKind::Arg, keyword_name);
                    }
                    tokens.insert(FactKind::Arg, &arg.value_text);
                }
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                tokens.insert(FactKind::Write, target);
                if let Some(source) = source_name {
                    tokens.insert(FactKind::Read, source);
                }
                if let Some(call) = source_call {
                    tokens.insert(FactKind::Call, call);
                    let short = short_callee(call);
                    if short != call.as_str() {
                        tokens.insert(FactKind::Call, short);
                    }
                }
                for arg in source_call_args {
                    tokens.insert(FactKind::Arg, arg);
                }
                for source in source_names {
                    tokens.insert(FactKind::Read, source);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_flow_event_tokens_kinded(then_events, tokens);
                collect_flow_event_tokens_kinded(else_events, tokens);
            }
            FlowEvent::Loop { body, .. } => collect_flow_event_tokens_kinded(body, tokens),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_flow_event_tokens_kinded(body, tokens);
                collect_flow_event_tokens_kinded(catch_events, tokens);
                collect_flow_event_tokens_kinded(finally_events, tokens);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_flow_event_tokens_kinded(body, tokens);
            }
            _ => {}
        }
    }
}

/// Short tail (after the last separator in
/// `bonsai_common::QUALIFIED_NAME_SEPARATORS`) of a qualified callee
/// name. Matches the CLI's original short-callee semantics so
/// tokenization is identical before vs. after extraction.
fn short_callee(name: &str) -> &str {
    let mut tail = name;
    for sep in bonsai_common::QUALIFIED_NAME_SEPARATORS {
        if let Some(idx) = tail.rfind(sep) {
            tail = &tail[idx + sep.len()..];
        }
    }
    tail
}

/// `outer` span contains `inner` span when both are in the same file
/// and `inner`'s byte range is a subset.
fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

/// Compute just the interprocedural augmentation facts for one entry
/// function — callee names, tainted arg identifiers, tainted
/// param names. The per-entry piece is the expensive one; caching
/// it across chains that share an entry is where the perf win
/// comes from on workloads like Redis `--query system` where one
/// sink has hundreds of chains but only dozens of distinct entries.
///
/// Returns an empty [`KindedTokens`] when the entry has no params
/// to seed (adapter limitation) or when the global index doesn't
/// have a decl for the FuncId (stale id after invalidation).
#[must_use]
pub fn taint_facts_for_entry(entry_func: FuncId, db: &AnalyzerDb, _sanitizers: &TokenSet) -> KindedTokens {
    taint_facts_and_graph_for_entry(entry_func, db, &TokenSet::default()).0
}

/// Compute interprocedural taint facts and the indexed call graph for
/// `entry_func`. Two seeds are built and used:
///
/// * `fact_seed` — params + locally bound assignment targets, used to
///   produce the kinded facts the inspect filter pipeline matches against.
/// * `graph_seed` — a wider seed that also pulls in RHS / call-arg
///   tokens, used so the persisted call graph captures every edge a
///   downstream analysis might want, even when a name was never an
///   assignment target.
///
/// One-off entry point that provisions a fresh `InterTaintCaches`.
/// Workspace consumers should prefer
/// [`taint_facts_and_graph_for_entry_with_caches`] so the engine's
/// resolver memo / alias maps / function summaries survive across
/// the workspace's prewarm and per-source runs.
#[must_use]
pub fn taint_facts_and_graph_for_entry(
    entry_func: FuncId,
    db: &AnalyzerDb,
    sanitizers: &TokenSet,
) -> (KindedTokens, EntryTaintGraph) {
    let caches = crate::inter::InterTaintCaches::default();
    taint_facts_and_graph_for_entry_with_caches(entry_func, db, sanitizers, &caches)
}

/// Variant that threads a caller-provided `InterTaintCaches` so
/// workspace prewarm shares the resolver memo with subsequent
/// security-analysis / value-flow / inspect runs.
#[must_use]
pub fn taint_facts_and_graph_for_entry_with_caches(
    entry_func: FuncId,
    db: &AnalyzerDb,
    _sanitizers: &TokenSet,
    caches: &crate::inter::InterTaintCaches,
) -> (KindedTokens, EntryTaintGraph) {
    let mut facts = KindedTokens::default();
    let mut graph = EntryTaintGraph::default();
    let global = db.global_index();
    let entry_decl = global.decl_of(SymbolId::new(entry_func.raw()));
    // Initial seed = entry's formal parameter names. Empty params are
    // dropped — adapters occasionally emit them for unnamed positions.
    let mut seed: TokenSet = entry_decl
        .as_ref()
        .map(|decl| {
            decl.params
                .iter()
                .filter(|param| !param.is_empty())
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let mut graph_seed = seed.clone();
    // Augment seed with local assignment targets. Covers two cases:
    //   * Param-less entries (Flask / Django views, top-level
    //     scripts) — params alone would give an empty seed.
    //   * Entries receiving taint via a param-derived local (JS
    //     `let token = req.query.token`); Tree-sitter adapters
    //     don't always populate `source_name` on the Assign, so
    //     without this the local never picks up taint from the
    //     param and the chain dies at the first call site.
    if let Some(decl) = entry_decl.as_ref() {
        collect_assign_targets(&decl.flow_events, &mut seed, false);
        collect_assign_targets(&decl.flow_events, &mut graph_seed, true);
        collect_graph_seed_tokens(&decl.flow_events, &mut graph_seed);
    }

    // Structural facts: even with no param-seeded propagation we
    // populate the entry's own name and param list so filters that
    // target the entry (`--from handle_request`, `--from token`) have
    // a taint-anchored signal. We also walk the entry's flow events
    // to surface every call / assignment / arg token as a fact —
    // these are what the chain would touch if fully inlined, so a
    // needle like `request` (read from `request.args.get(...)`) or
    // `update_user` (called from the entry) still matches strictly
    // via taint facts without falling back to lexical body tokens.
    if let Some(decl) = entry_decl.as_ref() {
        facts.insert(FactKind::Decl, &decl.name);
        for param in &decl.params {
            if !param.is_empty() {
                facts.insert(FactKind::Decl, param);
            }
        }
        collect_flow_facts(&decl.flow_events, &mut facts);
    }

    if !graph_seed.is_empty() {
        let config = crate::inter::InterTaintConfig {
            sanitizers: TokenSet::default(),
            budget: 256,
            intra_worklist_cap: None,
            max_edge_precision: Some(Precision::Narrowed),
            ..Default::default()
        };
        let graph_result = crate::inter::interprocedural_taint_to_completion_with_caches(
            entry_func,
            &graph_seed,
            &config,
            db,
            caches,
        );
        graph.call_records = graph_result
            .call_records
            .iter()
            .map(|record| TaintedCallEdge {
                trace_id: record.trace_id,
                parent_trace_id: record.parent_trace_id,
                caller: record.caller,
                callee: record.callee,
                call_span: record.call_span,
                tainted_args: record.tainted_args.clone(),
                precision: record.edge_precision,
            })
            .collect();
        graph.tainted_calls.clone_from(&graph_result.tainted_calls);
        graph.precision = graph_result.precision;
        graph.saturated = graph_result.saturated;

        // Avoid re-running the inter pass when the two seeds coincide;
        // a separate fact-only run is only needed if the wider graph_seed
        // would dilute the per-fact view used by --from / --to filters.
        let fact_result;
        let result = if seed == graph_seed {
            &graph_result
        } else {
            fact_result = crate::inter::interprocedural_taint_to_completion_with_caches(
                entry_func, &seed, &config, db, caches,
            );
            &fact_result
        };
        for propagation in &result.call_records {
            if let Some(callee_decl) = global.decl_of(SymbolId::new(propagation.callee.raw())) {
                facts.insert(FactKind::Call, &callee_decl.name);
            }
            for tainted_arg in &propagation.tainted_args {
                facts.insert(FactKind::Arg, &tainted_arg.value_text);
                facts.insert(FactKind::Decl, &tainted_arg.param_name);
            }
        }
        for call in &result.tainted_calls {
            facts.insert(FactKind::TaintedCall, &call.name);
            let short = short_callee(&call.name);
            if short != call.name.as_str() {
                facts.insert(FactKind::TaintedCall, short);
            }
            for arg in &call.tainted_args {
                facts.insert(FactKind::Arg, &arg.value_text);
            }
            if let Some(receiver) = &call.tainted_receiver {
                facts.insert(FactKind::Arg, receiver);
            }
        }
    }
    (facts, graph)
}

/// Walk the entry's flow events and collect every Assign target into
/// `out`. Used as a fallback taint seed when the entry has no formal
/// params — each local that the entry binds is a candidate taint
/// carrier.
pub(crate) fn collect_assign_targets(
    events: &[bonsai_lang_api::FlowEvent],
    out: &mut TokenSet,
    include_source_calls: bool,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                if !target.is_empty() {
                    out.insert(target.clone());
                }
                if include_source_calls {
                    if let Some(call) = source_call {
                        out.insert(call.clone());
                        let short = short_callee(call);
                        if short != call.as_str() {
                            out.insert(short.to_string());
                        }
                    }
                    for source in source_names {
                        if !source.is_empty() {
                            out.insert(source.clone());
                            let short = short_callee(source);
                            if short != source.as_str() {
                                out.insert(short.to_string());
                            }
                        }
                    }
                }
                for arg in source_call_args {
                    let trimmed = arg.trim();
                    // Only bare-identifier args are candidate carriers —
                    // composite expressions get rejected to avoid noisy seeds.
                    if is_bare_identifier(trimmed) {
                        out.insert(trimmed.to_string());
                    }
                }
            }
            FlowEvent::Call { args, .. } => {
                // Call args that are bare identifiers are candidate
                // taint carriers too — catches source calls with
                // pointer/out-buffer arguments where the variable
                // isn't an `Assign` target but clearly carries data
                // from this call.
                for arg in args {
                    let trimmed = arg.value_text.trim();
                    if is_bare_identifier(trimmed) {
                        out.insert(trimmed.to_string());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assign_targets(then_events, out, include_source_calls);
                collect_assign_targets(else_events, out, include_source_calls);
            }
            FlowEvent::Loop { body, .. } => {
                collect_assign_targets(body, out, include_source_calls);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assign_targets(body, out, include_source_calls);
                collect_assign_targets(catch_events, out, include_source_calls);
                collect_assign_targets(finally_events, out, include_source_calls);
            }
            _ => {}
        }
    }
}

/// True when `text` is a bare identifier (letter/underscore start,
/// ascii-alphanumeric/underscore tail).
fn is_bare_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Walk an entry's flow events and collect every "source-like" token
/// — assignment RHS names, call argument values, return / throw /
/// yield expressions — into `out`. Used to widen the inter-pass
/// graph seed so the persisted call graph captures edges the
/// strict param/local seed alone would miss.
fn collect_graph_seed_tokens(events: &[bonsai_lang_api::FlowEvent], out: &mut TokenSet) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                if let Some(name) = source_name.as_deref() {
                    insert_graph_seed(out, name);
                }
                for name in source_names {
                    insert_graph_seed(out, name);
                }
                for arg in source_call_args {
                    insert_graph_seed(out, arg);
                }
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    // The `place` slot carries the abstract place-id string when
                    // the adapter resolved one — useful as a stable seed key.
                    if let Some(place) = arg.place.as_deref() {
                        insert_graph_seed(out, place);
                    }
                    insert_graph_seed(out, &arg.value_text);
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                // Prefer the full value_text when available; fall back to value_name
                // for adapters that only surface the bare identifier form.
                if let Some(value) = value_text.as_deref().or(value_name.as_deref()) {
                    insert_graph_seed(out, value);
                }
            }
            FlowEvent::Throw { value_name, .. } => {
                if let Some(value) = value_name.as_deref() {
                    insert_graph_seed(out, value);
                }
            }
            FlowEvent::Yield { value_text, .. } => {
                if let Some(value) = value_text.as_deref() {
                    insert_graph_seed(out, value);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_graph_seed_tokens(then_events, out);
                collect_graph_seed_tokens(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_graph_seed_tokens(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_graph_seed_tokens(body, out);
                collect_graph_seed_tokens(catch_events, out);
                collect_graph_seed_tokens(finally_events, out);
            }
            _ => {}
        }
    }
}

/// Insert `token` into the graph seed set, but only when it looks
/// like a real source-like reference (skips literals, keywords,
/// whitespace-bearing fragments). Trims first so adapter quirks
/// around padding don't produce duplicate entries.
fn insert_graph_seed(out: &mut TokenSet, token: &str) {
    let token = token.trim();
    if !source_like_seed_token(token) {
        return;
    }
    out.insert(token.to_string());
}

/// True when `token` is a plausible taint-seed name. Rejects string
/// literals, numbers, well-known keywords, and any token containing
/// whitespace; accepts bare identifiers, sigil-prefixed forms (`@x`,
/// `$this->x`), and dotted member accesses where every component is
/// itself a bare identifier.
fn source_like_seed_token(token: &str) -> bool {
    let token = token.trim();
    if token.is_empty()
        || token.starts_with('"')
        || token.starts_with('\'')
        || token.parse::<f64>().is_ok()
        || matches!(token, "true" | "false" | "null" | "nil" | "None")
        || token.chars().any(char::is_whitespace)
    {
        return false;
    }
    if is_bare_identifier(token) {
        return true;
    }
    // Ruby instance variables: `@field`.
    if let Some(field) = token.strip_prefix('@') {
        return is_bare_identifier(field);
    }
    // PHP / Hack `$this->field` and `this->field` aliases.
    if let Some(field) = token
        .strip_prefix("$this->")
        .or_else(|| token.strip_prefix("this->"))
    {
        return is_bare_identifier(field.trim_start_matches('$'));
    }
    // Dotted access: every segment must itself be a bare identifier
    // (after trimming the optional `$` PHP/Perl variable sigil).
    if token.contains('.') {
        return token
            .split('.')
            .all(|part| is_bare_identifier(part.trim_start_matches('$')));
    }
    false
}

/// Walk the entry's structural flow events and add every call,
/// assignment target, and argument value into the kinded-facts set.
/// Used so filters can match against tokens the chain physically
/// touches (e.g. `request` inside `token = request.args.get(...)`)
/// without resorting to lexical body-token matching. Recurses through
/// Branch / Loop / Try regions in the same shape as the inter-pass
/// walker.
fn collect_flow_facts(events: &[bonsai_lang_api::FlowEvent], facts: &mut KindedTokens) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } => {
                facts.insert(FactKind::Call, name);
                let short = short_callee(name);
                if short != name.as_str() {
                    facts.insert(FactKind::Call, short);
                }
                for arg in args {
                    if !arg.value_text.is_empty() {
                        facts.insert(FactKind::Arg, &arg.value_text);
                    }
                    if let Some(keyword) = &arg.name {
                        if !keyword.is_empty() {
                            facts.insert(FactKind::Arg, keyword);
                        }
                    }
                }
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                if !target.is_empty() {
                    facts.insert(FactKind::Write, target);
                }
                if let Some(source) = source_name {
                    if !source.is_empty() {
                        facts.insert(FactKind::Read, source);
                    }
                }
                if let Some(call) = source_call {
                    if !call.is_empty() {
                        facts.insert(FactKind::Call, call);
                        let short = short_callee(call);
                        if short != call.as_str() {
                            facts.insert(FactKind::Call, short);
                        }
                    }
                }
                for arg in source_call_args {
                    if !arg.is_empty() {
                        facts.insert(FactKind::Arg, arg);
                    }
                }
                for source in source_names {
                    if !source.is_empty() {
                        facts.insert(FactKind::Read, source);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_flow_facts(then_events, facts);
                collect_flow_facts(else_events, facts);
            }
            FlowEvent::Loop { body, .. } => collect_flow_facts(body, facts),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_flow_facts(body, facts);
                collect_flow_facts(catch_events, facts);
                collect_flow_facts(finally_events, facts);
            }
            _ => {}
        }
    }
}

/// Merge every token from `other` into `target`, preserving kind
/// buckets. Used to fold cached per-entry interprocedural facts
/// into a per-chain reachability token set without re-running the
/// interprocedural pass.
pub fn merge_into(target: &mut KindedTokens, other: &KindedTokens) {
    for (kind, tokens) in &other.by_kind {
        let bucket = target.by_kind.entry(*kind).or_default();
        for token in tokens {
            bucket.insert(token.clone());
        }
    }
}

fn source_seed_nodes_from_idg(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    let mut seed_nodes: Vec<bonsai_idg::WsNodeId> = Vec::new();
    let seed_names: Vec<String> = seeds.iter().cloned().collect();
    if let Some(anchor) = source_anchor {
        let anchor_nodes = idg.source_seed_nodes_at_span(source_func, anchor);
        let anchor_has_call_return = anchor_nodes.iter().any(|node| {
            idg.resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::CallRet)
        });
        if !anchor_has_call_return && !seed_names.is_empty() {
            let named_nodes = idg.read_or_write_nodes_for_names(source_func, &seed_names);
            if named_nodes.is_empty() {
                seed_nodes.extend(anchor_nodes);
            } else {
                seed_nodes.extend(named_nodes);
            }
        } else {
            seed_nodes.extend(anchor_nodes);
            if anchor_has_call_return && !seed_names.is_empty() {
                seed_nodes.extend(idg.read_or_write_nodes_for_names(source_func, &seed_names));
            }
        }
    }
    if !output_arg_names.is_empty() && source_anchor.is_none() {
        seed_nodes.extend(idg.read_or_write_nodes_for_names(source_func, output_arg_names));
    }
    if seed_nodes.is_empty() {
        if seed_names.is_empty() {
            seed_nodes.extend(idg.param_nodes_of(source_func));
        } else {
            let narrowed = idg.param_nodes_for_names(source_func, &seed_names, global);
            seed_nodes.extend(narrowed);
        }
        seed_nodes.extend(idg.read_or_write_nodes_for_names(source_func, &seed_names));
    }
    seed_nodes.sort();
    seed_nodes.dedup();
    seed_nodes
}

/// Semantic-only source-return reachability over the IDG.
///
/// Defaults to `Precision::Narrowed` so callers cannot accidentally
/// promote diagnostic over-approximate edges into public evidence.
#[must_use]
pub fn source_seed_reaches_return_from_idg(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> bool {
    source_seed_reaches_return_from_idg_with_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        Some(Precision::Narrowed),
        db,
        idg,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)] // Public IDG query surface carries seed, precision, db, and service context.
pub fn source_seed_reaches_return_from_idg_with_max_precision(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    max_precision: Option<Precision>,
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> bool {
    let global = db.global_index();
    let mut seed_nodes = source_seed_nodes_from_idg(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        global.as_ref(),
        idg,
    );
    if seed_nodes.is_empty() {
        return false;
    }
    if !receiver_state_propagations.is_empty() {
        apply_receiver_state_fixpoint(
            &mut seed_nodes,
            receiver_state_propagations,
            global.as_ref(),
            idg,
            max_precision,
            None,
        );
    }
    let Some(return_node) = idg.return_node_of(source_func) else {
        return false;
    };
    idg.forward_closure_with_max_precision(&seed_nodes, max_precision)
        .contains(&return_node)
}

/// IDG-driven [`EntryTaintGraph`] builder. Closes the per-source
/// interprocedural pass entirely on the workspace IDG —
/// SSA-narrowed forward closure plus cross-call lifting.
///
/// `source_anchor` is the rule match's source span: seeds are
/// IDG nodes anchored at that span (`CallRet`, `CallArg`,
/// span-distinct `Write`). `output_arg_names`, when non-empty,
/// names additional carriers for the source's side-effect outputs;
/// for example, a configured read-into-buffer source seeds
/// post-call reads/writes of that buffer. When neither are supplied,
/// the seed set falls back to entry params + every Read/Write of
/// `seeds`.
///
/// Semantic-only call-record graph over the IDG.
///
/// Use [`entry_taint_call_records_from_idg_with_max_precision`] with
/// `None` only for explicit diagnostics.
#[must_use]
pub fn entry_taint_call_records_from_idg(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> EntryTaintGraph {
    entry_taint_call_records_from_idg_with_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        Some(Precision::Narrowed),
        db,
        idg,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)] // Public IDG query surface carries seed, precision, db, and service context.
pub fn entry_taint_call_records_from_idg_with_max_precision(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    max_precision: Option<Precision>,
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> EntryTaintGraph {
    let global = db.global_index();
    let mut graph = EntryTaintGraph::default();

    let mut seed_nodes = source_seed_nodes_from_idg(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        global.as_ref(),
        idg,
    );
    if seed_nodes.is_empty() {
        return graph;
    }

    if bonsai_diagnostics::debug::is_enabled("idg-closure") {
        let n = global
            .decl_of(bonsai_common::SymbolId::new(source_func.raw()))
            .map(|d| d.name.clone())
            .unwrap_or_default();
        let xc_pre = idg.cross_call_edges_in_closure_with_max_precision(&seed_nodes, max_precision);
        let closure = idg.forward_closure_with_max_precision(&seed_nodes, max_precision);
        let seed_repr: Vec<String> = seed_nodes
            .iter()
            .map(|w| {
                idg.resolve_point(*w)
                    .map(|p| format!("ws#{}={:?}@{}..{}", w.0, p.kind, p.span.start, p.span.end))
                    .unwrap_or_else(|| format!("ws#{}", w.0))
            })
            .collect();
        let seed_names_repr: Vec<&str> = seeds.iter().map(|s| s.as_str()).collect();
        bonsai_diagnostics::debug_log!(
            "idg-closure",
            "src={}({}) seed_names={:?} anchor={:?} output_args={:?} seed_count={} seed_nodes={:?} closure_size={} xcalls={}",
            n,
            source_func.raw(),
            seed_names_repr,
            source_anchor.map(|s| (s.start, s.end)),
            output_arg_names,
            seed_nodes.len(),
            seed_repr,
            closure.len(),
            xc_pre.len()
        );
        if bonsai_diagnostics::debug::is_enabled("idg-closure-detail") {
            let detail: Vec<String> = closure
                .iter()
                .filter_map(|w| {
                    idg.resolve_point(*w).map(|p| {
                        format!(
                            "ws#{}={:?}:{}@{}..{}",
                            w.0, p.kind, p.name, p.span.start, p.span.end
                        )
                    })
                })
                .collect();
            bonsai_diagnostics::debug_log!("idg-closure-detail", "  closure_nodes: {:?}", detail);
        }
    }

    if !receiver_state_propagations.is_empty() {
        apply_receiver_state_fixpoint(
            &mut seed_nodes,
            receiver_state_propagations,
            global.as_ref(),
            idg,
            max_precision,
            None,
        );
    }
    let closure_nodes = idg.forward_closure_with_max_precision(&seed_nodes, max_precision);
    let cross_calls = {
        let mut edges =
            idg.cross_call_edges_in_reachable_nodes_with_max_precision(&closure_nodes, max_precision);
        let dist_map = distances_from_source(source_func, &edges);
        edges.sort_by_key(|ce| {
            (
                dist_map.get(&ce.caller).copied().unwrap_or(u32::MAX),
                ce.caller.raw(),
                ce.callee.raw(),
                ce.call_span.start,
                ce.arg_idx,
                ce.param_idx,
                ce.precision,
            )
        });
        edges.dedup();
        edges
    };
    let mut next_trace_id: u64 = 1;
    let mut first_inflow: ahash::AHashMap<FuncId, u64> = ahash::AHashMap::new();
    let mut call_records: Vec<TaintedCallEdge> = Vec::with_capacity(cross_calls.len());
    let mut worst = Precision::Exact;
    let mut call_summary_cache: ahash::AHashMap<
        FuncId,
        ahash::AHashMap<bonsai_common::Span, CallEventSummary>,
    > = ahash::AHashMap::default();
    for ce in &cross_calls {
        let trace_id = next_trace_id;
        next_trace_id = next_trace_id.saturating_add(1);
        let parent_trace_id = first_inflow.get(&ce.caller).copied();
        let is_synthetic_return = ce.arg_idx == u8::MAX;
        let synthetic_back_to_source = is_synthetic_return && ce.callee == source_func;
        if !synthetic_back_to_source {
            first_inflow.entry(ce.callee).or_insert(trace_id);
        }
        worst = worst.meet(ce.precision);

        let callee_decl = global.decl_of(bonsai_common::SymbolId::new(ce.callee.raw()));
        let call_summary =
            cached_call_event_summary(ce.caller, ce.call_span, global.as_ref(), &mut call_summary_cache);
        let tainted_args = tainted_args_for_cross_call_edge(ce, callee_decl, call_summary);
        call_records.push(TaintedCallEdge {
            trace_id,
            parent_trace_id,
            caller: ce.caller,
            callee: ce.callee,
            call_span: ce.call_span,
            tainted_args,
            precision: ce.precision,
        });
    }

    graph.call_records = call_records;
    graph.precision = worst;
    graph.saturated = false;
    graph.pairs_analyzed = u32::try_from(cross_calls.len()).unwrap_or(u32::MAX);
    graph
}

/// Semantic-only taint graph over the IDG.
///
/// Use [`entry_taint_graph_from_idg_with_max_precision`] with `None`
/// only for explicit diagnostics.
#[must_use]
pub fn entry_taint_graph_from_idg(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> EntryTaintGraph {
    entry_taint_graph_from_idg_with_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        &[],
        &[],
        Some(Precision::Narrowed),
        db,
        idg,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)] // Public IDG query surface carries seed, precision, db, and service context.
pub fn entry_taint_graph_from_idg_with_max_precision(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    call_result_passthroughs: &[crate::inter::CallResultPassthrough],
    output_arg_flows: &[crate::inter::OutputArgFlow],
    max_precision: Option<Precision>,
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> EntryTaintGraph {
    entry_taint_graph_from_idg_with_target_funcs_and_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        call_result_passthroughs,
        output_arg_flows,
        None,
        max_precision,
        db,
        idg,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)] // Public IDG query surface carries seed, targets, precision, db, and service context.
pub fn entry_taint_graph_from_idg_with_target_funcs_and_max_precision(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    call_result_passthroughs: &[crate::inter::CallResultPassthrough],
    output_arg_flows: &[crate::inter::OutputArgFlow],
    target_funcs: Option<&AHashSet<FuncId>>,
    max_precision: Option<Precision>,
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> EntryTaintGraph {
    entry_taint_graph_from_idg_with_target_filters_and_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        call_result_passthroughs,
        output_arg_flows,
        target_funcs,
        None,
        max_precision,
        db,
        idg,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)] // Public IDG query surface carries seed, targets, precision, db, and service context.
pub fn entry_taint_graph_from_idg_with_target_filters_and_max_precision(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    call_result_passthroughs: &[crate::inter::CallResultPassthrough],
    output_arg_flows: &[crate::inter::OutputArgFlow],
    target_funcs: Option<&AHashSet<FuncId>>,
    lineage_funcs: Option<&AHashSet<FuncId>>,
    max_precision: Option<Precision>,
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> EntryTaintGraph {
    entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        call_result_passthroughs,
        output_arg_flows,
        None,
        target_funcs,
        lineage_funcs,
        max_precision,
        db,
        idg,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)] // Public IDG query surface carries seed, node targets, function targets, precision, db, and service context.
pub fn entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    call_result_passthroughs: &[crate::inter::CallResultPassthrough],
    output_arg_flows: &[crate::inter::OutputArgFlow],
    target_nodes: Option<&[bonsai_idg::WsNodeId]>,
    target_funcs: Option<&AHashSet<FuncId>>,
    lineage_funcs: Option<&AHashSet<FuncId>>,
    max_precision: Option<Precision>,
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> EntryTaintGraph {
    let global = db.global_index();
    let mut graph = EntryTaintGraph::default();

    // Compose the seed set. Source rules may declare output
    // arguments; those configured carrier names seed post-call
    // reads/writes when the span-anchored seed is not enough.
    let mut seed_nodes = source_seed_nodes_from_idg(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        global.as_ref(),
        idg,
    );
    if seed_nodes.is_empty() {
        return graph;
    }

    if bonsai_diagnostics::debug::is_enabled("idg-closure") {
        let n = global
            .decl_of(bonsai_common::SymbolId::new(source_func.raw()))
            .map(|d| d.name.clone())
            .unwrap_or_default();
        let xc_pre = idg.cross_call_edges_in_closure_with_max_precision(&seed_nodes, max_precision);
        let closure = idg.forward_closure_with_max_precision(&seed_nodes, max_precision);
        let seed_repr: Vec<String> = seed_nodes
            .iter()
            .map(|w| {
                idg.resolve_point(*w)
                    .map(|p| format!("ws#{}={:?}@{}..{}", w.0, p.kind, p.span.start, p.span.end))
                    .unwrap_or_else(|| format!("ws#{}", w.0))
            })
            .collect();
        let seed_names_repr: Vec<&str> = seeds.iter().map(|s| s.as_str()).collect();
        bonsai_diagnostics::debug_log!(
            "idg-closure",
            "src={}({}) seed_names={:?} anchor={:?} output_args={:?} seed_count={} seed_nodes={:?} closure_size={} xcalls={}",
            n,
            source_func.raw(),
            seed_names_repr,
            source_anchor.map(|s| (s.start, s.end)),
            output_arg_names,
            seed_nodes.len(),
            seed_repr,
            closure.len(),
            xc_pre.len()
        );
        if bonsai_diagnostics::debug::is_enabled("idg-closure-detail") {
            let detail: Vec<String> = closure
                .iter()
                .filter_map(|w| {
                    idg.resolve_point(*w).map(|p| {
                        format!(
                            "ws#{}={:?}:{}@{}..{}",
                            w.0, p.kind, p.name, p.span.start, p.span.end
                        )
                    })
                })
                .collect();
            bonsai_diagnostics::debug_log!("idg-closure-detail", "  closure_nodes: {:?}", detail);
        }
    }

    apply_configured_transfer_fixpoint(
        &mut seed_nodes,
        receiver_state_propagations,
        call_result_passthroughs,
        output_arg_flows,
        global.as_ref(),
        idg,
        max_precision,
        None,
    );
    let closure_nodes = if let Some(target_nodes) = target_nodes.filter(|nodes| !nodes.is_empty()) {
        idg.forward_target_nodes_cut_with_max_precision(&seed_nodes, target_nodes, max_precision)
    } else if let Some(targets) = target_funcs {
        idg.forward_target_func_cut_with_max_precision(&seed_nodes, targets, max_precision)
    } else {
        idg.forward_closure_with_max_precision(&seed_nodes, max_precision)
    };
    if closure_nodes.is_empty() {
        return graph;
    }
    let closure_set: ahash::AHashSet<bonsai_idg::WsNodeId> = closure_nodes.iter().copied().collect();

    // Cross-call edges in closure → call_records. Sort
    // topologically (caller-before-callee) so trace_id assignment
    // matches the engine's worklist order — `first_inflow[caller]`
    // must already be populated when a record with that caller is
    // processed, otherwise lineage chains reconstructed from
    // parent_trace_id come out reversed.
    let cross_calls = {
        let mut edges = idg.cross_call_edges_in_reachable_nodes_filtered_with_max_precision(
            &closure_nodes,
            max_precision,
            lineage_funcs,
        );
        // Topological sort: walk from source_func outward, ordering
        // edges by their distance from source_func. Edges whose
        // caller hasn't been visited yet come later. This is
        // breadth-first by caller.
        let dist_map = distances_from_source(source_func, &edges);
        edges.sort_by_key(|ce| {
            (
                dist_map.get(&ce.caller).copied().unwrap_or(u32::MAX),
                ce.caller.raw(),
                ce.call_span.start,
                ce.arg_idx,
            )
        });
        edges
    };
    let mut next_trace_id: u64 = 1;
    let mut first_inflow: ahash::AHashMap<FuncId, u64> = ahash::AHashMap::new();
    let mut call_records: Vec<TaintedCallEdge> = Vec::with_capacity(cross_calls.len());
    let mut worst = Precision::Exact;
    let mut call_summary_cache: ahash::AHashMap<
        FuncId,
        ahash::AHashMap<bonsai_common::Span, CallEventSummary>,
    > = ahash::AHashMap::default();
    for ce in &cross_calls {
        let trace_id = next_trace_id;
        next_trace_id = next_trace_id.saturating_add(1);
        let parent_trace_id = first_inflow.get(&ce.caller).copied();
        // Synthetic `Return → CallRet` edges (sentinel
        // `arg_idx = u8::MAX`) flip the natural call orientation:
        // `caller = the returning function`, `callee = the
        // function that holds the call site`. Registering
        // `first_inflow[callee]` for those edges effectively
        // teaches the sink-attribution walker "you can reach
        // `callee` by following the call's return", which is
        // load-bearing for the cross-function-source case
        // (`source mid()`, sink in `top` that uses mid's return).
        // BUT, when the synthetic edge points back at the
        // source func itself (`source = handle`, handle calls
        // transform which returns to handle), it overwrites a
        // legitimate "source is its own entry — no inflow" state
        // with a trace_id for the return hop, and downstream
        // sinks in `handle` chain through that synthetic edge as
        // if `handle` had a caller. Gate the registration: the
        // synthetic edge only seeds `first_inflow[callee]` when
        // `callee` isn't already the source function. The
        // cross-function-source case still works (the source's
        // OWN first_inflow remains None, the *other* function's
        // first_inflow gets set), while the intra-function case
        // (g1_c_return pattern) avoids the cycle entirely.
        let is_synthetic_return = ce.arg_idx == u8::MAX;
        let synthetic_back_to_source = is_synthetic_return && ce.callee == source_func;
        if !synthetic_back_to_source {
            first_inflow.entry(ce.callee).or_insert(trace_id);
        }
        worst = worst.meet(ce.precision);

        let callee_decl = global.decl_of(bonsai_common::SymbolId::new(ce.callee.raw()));
        let call_summary =
            cached_call_event_summary(ce.caller, ce.call_span, global.as_ref(), &mut call_summary_cache);
        let tainted_args = tainted_args_for_cross_call_edge(ce, callee_decl, call_summary);
        call_records.push(TaintedCallEdge {
            trace_id,
            parent_trace_id,
            caller: ce.caller,
            callee: ce.callee,
            call_span: ce.call_span,
            tainted_args,
            precision: ce.precision,
        });
    }

    // Tainted call sites in closure → tainted_calls.
    let tainted_args_by_site =
        idg.tainted_call_args_in_reachable_nodes_for_funcs(&closure_nodes, target_funcs);
    let mut by_site: ahash::AHashMap<(FuncId, bonsai_common::Span), Vec<u8>> = ahash::AHashMap::new();
    for (caller, call_span, arg_idx) in &tainted_args_by_site {
        if target_funcs.is_some_and(|targets| !targets.contains(caller)) {
            continue;
        }
        by_site.entry((*caller, *call_span)).or_default().push(*arg_idx);
    }

    let mut tainted_calls: Vec<crate::inter::TaintedCall> = Vec::new();
    let compiled_call_result_passthroughs = compile_call_result_passthroughs(call_result_passthroughs);
    let mut passthrough_callee_cache = CalleeNameCache::default();
    let mut tainted_names_by_caller: ahash::AHashMap<FuncId, ahash::AHashSet<String>> =
        ahash::AHashMap::new();
    let mut function_summary_cache: ahash::AHashMap<FuncId, crate::inter::FunctionSummary> =
        ahash::AHashMap::default();
    let mut sorted_sites: Vec<((FuncId, bonsai_common::Span), Vec<u8>)> = by_site.into_iter().collect();
    // Tie-break on span.end too — two call sites in the same caller
    // can share a span.start when one is nested inside the other
    // (`Command::new(...).arg(...)` reaches the matcher as multiple
    // CallEvents with overlapping spans). Without the secondary sort
    // key the stable-sort preserves AHashMap insertion order for
    // ties, which is randomised per process and produces different
    // `tainted_calls` orderings across runs — that propagates into
    // the `F:` / `S:` ids since lineage `parent_trace_id` chains
    // off whichever call_records[0] sorts first.
    sorted_sites.sort_by_key(|((f, s), _)| (f.raw(), s.start, s.end));
    for ((caller, call_span), arg_indices) in sorted_sites {
        let Some(call_summary) =
            cached_call_event_summary(caller, call_span, global.as_ref(), &mut call_summary_cache).cloned()
        else {
            continue;
        };
        let mut tainted_args: Vec<crate::inter::TaintedArgAtCall> = arg_indices
            .iter()
            .filter_map(|idx| {
                if tainted_arg_is_clean_nested_call_return(
                    caller,
                    *idx,
                    &call_summary,
                    &cross_calls,
                    db,
                    global.as_ref(),
                    &mut call_summary_cache,
                    &mut function_summary_cache,
                    &compiled_call_result_passthroughs,
                    &mut passthrough_callee_cache,
                ) {
                    return None;
                }
                call_summary.args_value_text.get(*idx as usize).map(|value_text| {
                    crate::inter::TaintedArgAtCall {
                        index: *idx as usize,
                        value_text: value_text.clone(),
                    }
                })
            })
            .collect();
        tainted_args.sort_by_key(|a| a.index);
        tainted_args.dedup_by_key(|a| a.index);
        let parent_trace_id = first_inflow.get(&caller).copied();
        let tainted_receiver = call_summary.receiver.as_ref().and_then(|recv| {
            let names = tainted_names_by_caller
                .entry(caller)
                .or_insert_with(|| tainted_local_names_in_caller(caller, global.as_ref(), idg, &closure_set));
            for token in tokenise_identifiers_outside_strings(recv) {
                if names.contains(&token) {
                    return Some(recv.clone());
                }
            }
            None
        });
        if tainted_args.is_empty() && tainted_receiver.is_none() {
            continue;
        }
        tainted_calls.push(crate::inter::TaintedCall {
            parent_trace_id,
            caller,
            name: call_summary.name.clone(),
            call_span,
            tainted_args,
            tainted_receiver,
            kind: crate::inter::TaintedCallKind::Call,
        });
    }

    // Emit synthetic `TaintedCallKind::Return` rows for every
    // function in the closure whose `Place::Return` node lies in
    // the seed's forward closure. This mirrors the engine's
    // return-propagation step: a tainted value reaches the
    // function's return slot, so a `MatchKind::Return` sink rule
    // can fire on its return statement(s). Without this, the
    // matcher's return-rule scan completes but `build_findings_
    // chain_aware` never sees a TaintedCall for that return — so
    // even when the closure correctly tracks taint into the
    // return value, no finding emerges. Each return event
    // surfaced by the caller's flow_events with span overlapping
    // the function's body becomes its own row, attributed to
    // the lineage `parent_trace_id` for the function.
    let mut return_tainted_calls: Vec<crate::inter::TaintedCall> = Vec::new();
    {
        let return_funcs: Vec<FuncId> = idg.funcs_with_return_nodes_in_reachable_nodes(&closure_nodes);
        for func in return_funcs {
            if target_funcs.is_some_and(|targets| !targets.contains(&func)) {
                continue;
            }
            let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
                continue;
            };
            let mut return_spans: Vec<bonsai_common::Span> = Vec::new();
            collect_return_spans(&decl.flow_events, &mut return_spans);
            return_spans.sort_by_key(|s| (s.start, s.end));
            return_spans.dedup();
            let parent_trace_id = first_inflow.get(&func).copied();
            for return_span in return_spans {
                return_tainted_calls.push(crate::inter::TaintedCall {
                    parent_trace_id,
                    caller: func,
                    name: "return".to_string(),
                    call_span: return_span,
                    tainted_args: Vec::new(),
                    tainted_receiver: None,
                    kind: crate::inter::TaintedCallKind::Return,
                });
            }
        }
    }
    tainted_calls.extend(return_tainted_calls);

    // Emit synthetic `TaintedCallKind::Write` rows for every Assign
    // event in any closure-reachable function whose RHS reads a name
    // marked tainted. A `MatchKind::Write` sink rule (e.g.
    // `swift.cmdi.arguments_write`) can only fire when
    // `build_findings_chain_aware` finds a TaintedCall row at the
    // assignment span. The receiver-only `proc.launch()` call has
    // no positional taint to expose, so attribution must come from
    // the assignment.
    let mut write_tainted_calls: Vec<crate::inter::TaintedCall> = Vec::new();
    {
        let mut funcs_in_closure: ahash::AHashSet<FuncId> = ahash::AHashSet::default();
        funcs_in_closure.insert(source_func);
        for record in &call_records {
            funcs_in_closure.insert(record.caller);
            funcs_in_closure.insert(record.callee);
        }
        let mut sorted_funcs: Vec<FuncId> = funcs_in_closure.into_iter().collect();
        sorted_funcs.sort_by_key(|f| f.raw());
        for func in sorted_funcs {
            if target_funcs.is_some_and(|targets| !targets.contains(&func)) {
                continue;
            }
            let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
                continue;
            };
            let names = {
                tainted_names_by_caller
                    .entry(func)
                    .or_insert_with(|| {
                        tainted_local_names_in_caller(func, global.as_ref(), idg, &closure_set)
                    })
                    .clone()
            };
            if names.is_empty() {
                continue;
            }
            let parent_trace_id = first_inflow.get(&func).copied();
            collect_tainted_writes(
                &decl.flow_events,
                func,
                &names,
                parent_trace_id,
                &mut write_tainted_calls,
            );
        }
    }
    tainted_calls.extend(write_tainted_calls);
    // Sort key: (caller, evidence_rank, span_start, span_end).
    // `evidence_rank` puts the kind that carries concrete
    // `tainted_args` BEFORE the synthetic kinds that don't, so when
    // multiple tainted-calls overlap a sink span (e.g. a `Return`
    // synthetic at the surrounding `return os.system(x)` statement
    // and the inner `Call` to `os.system`), the dedup pass at the
    // security-analysis layer picks the Call as the lineage anchor
    // and surfaces `arg[0] x` instead of "tainted value".
    fn evidence_rank(c: &crate::inter::TaintedCall) -> u8 {
        match c.kind {
            crate::inter::TaintedCallKind::Call => 0,
            crate::inter::TaintedCallKind::Write => 1,
            crate::inter::TaintedCallKind::Return => 2,
        }
    }
    tainted_calls.sort_by(|a, b| {
        (
            a.caller.raw(),
            evidence_rank(a),
            a.call_span.start,
            a.call_span.end,
        )
            .cmp(&(
                b.caller.raw(),
                evidence_rank(b),
                b.call_span.start,
                b.call_span.end,
            ))
    });
    graph.call_records = call_records;
    graph.tainted_calls = tainted_calls;
    graph.precision = worst;
    graph.saturated = false;
    graph.pairs_analyzed = u32::try_from(cross_calls.len()).unwrap_or(u32::MAX);
    if bonsai_diagnostics::debug::is_enabled("taint-graph") {
        let n = global
            .decl_of(bonsai_common::SymbolId::new(source_func.raw()))
            .map(|d| d.name.clone())
            .unwrap_or_default();
        bonsai_diagnostics::debug_log!(
            "taint-graph",
            "src={}({}) call_records={} tainted_calls={} precision={:?}",
            n,
            source_func.raw(),
            graph.call_records.len(),
            graph.tainted_calls.len(),
            graph.precision
        );
        for tc in &graph.tainted_calls {
            bonsai_diagnostics::debug_log!(
                "taint-graph",
                "  tainted_call caller={}({}) name={:?} span={}..{} tainted_args={:?} tainted_receiver={:?}",
                global
                    .decl_of(bonsai_common::SymbolId::new(tc.caller.raw()))
                    .map(|d| d.name.clone())
                    .unwrap_or_default(),
                tc.caller.raw(),
                tc.name,
                tc.call_span.start,
                tc.call_span.end,
                tc.tainted_args
                    .iter()
                    .map(|a| (a.index, a.value_text.clone()))
                    .collect::<Vec<_>>(),
                tc.tainted_receiver
            );
        }
        for cr in &graph.call_records {
            bonsai_diagnostics::debug_log!(
                "taint-graph",
                "  call_record trace={} parent={:?} caller={}({}) callee={}({}) span={}..{} arg={} param_name={:?}",
                cr.trace_id,
                cr.parent_trace_id,
                global
                    .decl_of(bonsai_common::SymbolId::new(cr.caller.raw()))
                    .map(|d| d.name.clone())
                    .unwrap_or_default(),
                cr.caller.raw(),
                global
                    .decl_of(bonsai_common::SymbolId::new(cr.callee.raw()))
                    .map(|d| d.name.clone())
                    .unwrap_or_default(),
                cr.callee.raw(),
                cr.call_span.start,
                cr.call_span.end,
                cr.tainted_args
                    .first()
                    .map(|a| a.index)
                    .unwrap_or(usize::MAX),
                cr.tainted_args
                    .first()
                    .map(|a| a.param_name.clone())
                    .unwrap_or_default(),
            );
        }
    }
    graph
}

/// Expand an IDG seed set with semantic transfer shapes before
/// computing the final closure. This is shared by security findings
/// and user-facing dump commands so both surfaces explain taint
/// through the same configured receiver-state, call-result, and
/// output-argument transfers. Constructor field propagation is handled
/// by the IDG itself; this layer must not promote one tainted
/// constructor argument to the entire constructed object root.
#[allow(clippy::too_many_arguments)] // Shared transfer surface carries seed, transfer tables, IDG, precision, and scope.
pub fn apply_configured_transfer_fixpoint(
    seed_nodes: &mut Vec<bonsai_idg::WsNodeId>,
    receiver_state_propagations: &[crate::inter::ReceiverStatePropagation],
    call_result_passthroughs: &[crate::inter::CallResultPassthrough],
    output_arg_flows: &[crate::inter::OutputArgFlow],
    global: &bonsai_index::GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    max_precision: Option<Precision>,
    func_filter: Option<&AHashSet<FuncId>>,
) {
    if !receiver_state_propagations.is_empty() {
        apply_receiver_state_fixpoint(
            seed_nodes,
            receiver_state_propagations,
            global,
            idg,
            max_precision,
            func_filter,
        );
    }
    loop {
        let mut grew = false;
        if !call_result_passthroughs.is_empty() {
            grew |= apply_call_result_passthrough_fixpoint(
                seed_nodes,
                call_result_passthroughs,
                global,
                idg,
                max_precision,
                func_filter,
            );
        }
        if !output_arg_flows.is_empty() {
            grew |= apply_output_arg_flow_fixpoint(
                seed_nodes,
                output_arg_flows,
                global,
                idg,
                max_precision,
                func_filter,
            );
        }
        if !grew {
            break;
        }
    }
}

/// Walk a function's flow events and collect every `Return`
/// event's source span. Recurses through structural events
/// (Branch / Loop / Try / Defer / Using) so nested returns are
/// found.
/// Walk `events`, find every Assign whose RHS reads a name in
/// `tainted_names`, and emit a TaintedCallKind::Write row attributed
/// to `func` at the assignment's span. Recurses through control-flow
/// containers so nested writes (inside if / try / loop) still
/// surface for the matcher's `MatchKind::Write` sink scan.
fn collect_tainted_writes(
    events: &[bonsai_lang_api::FlowEvent],
    func: FuncId,
    tainted_names: &ahash::AHashSet<String>,
    parent_trace_id: Option<u64>,
    out: &mut Vec<crate::inter::TaintedCall>,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                source_call_args,
                source_call,
                span,
                ..
            } => {
                if target.is_empty() {
                    continue;
                }
                let mut tainted_args: Vec<crate::inter::TaintedArgAtCall> = Vec::new();
                let push_if_tainted = |value: &str, args: &mut Vec<crate::inter::TaintedArgAtCall>| {
                    if value.is_empty() {
                        return;
                    }
                    // Token-level membership (mirrors the receiver path
                    // at the tainted-call site): a tainted local only
                    // taints this Write when it appears as a whole
                    // identifier in the RHS, not as a substring. A short
                    // tainted name like `id` must not match inside
                    // `uuid` / `valid` / `hidden`, which would fabricate
                    // a Write row attributed to an assignment that never
                    // read the tainted value.
                    if !tokenise_identifiers_outside_strings(value)
                        .iter()
                        .any(|t| tainted_names.contains(t))
                    {
                        return;
                    }
                    if args.iter().any(|a| a.value_text == value) {
                        return;
                    }
                    let index = args.len();
                    args.push(crate::inter::TaintedArgAtCall {
                        index,
                        value_text: value.to_string(),
                    });
                };
                if let Some(name) = source_name {
                    push_if_tainted(name, &mut tainted_args);
                }
                for n in source_names {
                    push_if_tainted(n, &mut tainted_args);
                }
                // For `target = callee(args...)`, the arguments are inputs to the
                // callee, not direct inputs to the target write. Configured
                // passthroughs and resolved return summaries add the legitimate
                // `CallRet -> target` flow; treating args as direct write evidence
                // makes arbitrary split/map helpers look like value passthroughs.
                if source_call.is_none() {
                    for n in source_call_args {
                        push_if_tainted(n, &mut tainted_args);
                    }
                }
                if let Some(call_name) = source_call {
                    push_if_tainted(call_name, &mut tainted_args);
                }
                if tainted_args.is_empty() {
                    continue;
                }
                out.push(crate::inter::TaintedCall {
                    parent_trace_id,
                    caller: func,
                    name: target.clone(),
                    call_span: *span,
                    tainted_args,
                    tainted_receiver: None,
                    kind: crate::inter::TaintedCallKind::Write,
                });
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_tainted_writes(then_events, func, tainted_names, parent_trace_id, out);
                collect_tainted_writes(else_events, func, tainted_names, parent_trace_id, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_tainted_writes(body, func, tainted_names, parent_trace_id, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_tainted_writes(body, func, tainted_names, parent_trace_id, out);
                collect_tainted_writes(catch_events, func, tainted_names, parent_trace_id, out);
                collect_tainted_writes(finally_events, func, tainted_names, parent_trace_id, out);
            }
            _ => {}
        }
    }
}

fn collect_return_spans(events: &[bonsai_lang_api::FlowEvent], out: &mut Vec<bonsai_common::Span>) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Return { span, .. } => out.push(*span),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_return_spans(then_events, out);
                collect_return_spans(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_return_spans(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_return_spans(body, out);
                collect_return_spans(catch_events, out);
                collect_return_spans(finally_events, out);
            }
            _ => {}
        }
    }
}

/// Walk every call-arg site reached by the current closure and
/// extend `seed_nodes` with the receiver's post-call writers when
/// the call matches a configured `ReceiverStatePropagation`
/// (`taint_semantics.taint_receiver_from_args`). Iterates to a
/// fixpoint — each round may introduce new tainted call-args
/// (because the new receiver seeds extend the closure), which in
/// turn may match further propagations. Bounds the loop with a
/// (call_span, receiver_name) seen-set so chained propagations
/// converge in a small constant number of rounds for any rulepack.
fn apply_receiver_state_fixpoint(
    seed_nodes: &mut Vec<bonsai_idg::WsNodeId>,
    propagations: &[crate::inter::ReceiverStatePropagation],
    global: &bonsai_index::GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    max_precision: Option<Precision>,
    func_filter: Option<&AHashSet<FuncId>>,
) {
    let mut applied: ahash::AHashSet<(FuncId, bonsai_common::Span, String)> = ahash::AHashSet::default();
    bonsai_diagnostics::debug_log!(
        "recv-state",
        "fixpoint start: {} propagation rule(s)",
        propagations.len()
    );
    let mut iter = 0usize;
    loop {
        iter += 1;
        let closure = idg.forward_closure_with_max_precision(seed_nodes, max_precision);
        let tainted = idg.tainted_call_args_in_reachable_nodes_for_funcs(&closure, func_filter);
        let mut grew = false;
        // Per-caller, look up flow events once and walk them to find
        // the call event matching each tainted (caller, call_span).
        // Sort by (caller, span) so the iteration order is stable
        // across runs — receiver-state-driven seeds added to
        // `seed_nodes` need a deterministic ordering or the
        // downstream chain enumeration produces different `S:` ids
        // between back-to-back invocations of the same workspace.
        let mut by_caller: ahash::AHashMap<FuncId, Vec<bonsai_common::Span>> = ahash::AHashMap::default();
        for (caller, call_span, _arg_idx) in &tainted {
            by_caller.entry(*caller).or_default().push(*call_span);
        }
        let mut sorted_callers: Vec<(FuncId, Vec<bonsai_common::Span>)> = by_caller.into_iter().collect();
        sorted_callers.sort_by_key(|(f, _)| f.raw());
        for (caller, mut spans) in sorted_callers {
            spans.sort();
            spans.dedup();
            let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(caller.raw())) else {
                continue;
            };
            walk_call_events_for_propagation(
                &decl.flow_events,
                caller,
                &spans,
                propagations,
                idg,
                seed_nodes,
                &mut applied,
                &mut grew,
            );
        }
        bonsai_diagnostics::debug_log!(
            "recv-state",
            "iter={} grew={} seeds={} applied={}",
            iter,
            grew,
            seed_nodes.len(),
            applied.len()
        );
        if !grew {
            break;
        }
        seed_nodes.sort();
        seed_nodes.dedup();
    }
}

/// Apply rulepack-declared call-result passthroughs. For a configured
/// representation-transform call, if a selected `CallArg` or
/// method-receiver slot is in the current closure, seed the sibling
/// `CallRet` at the same site. The regular IDG closure then carries
/// that return into the assignment target and onward. The engine owns
/// the mechanism; the rulepack owns the API names and argument/receiver
/// semantics.
fn apply_call_result_passthrough_fixpoint(
    seed_nodes: &mut Vec<bonsai_idg::WsNodeId>,
    passthroughs: &[crate::inter::CallResultPassthrough],
    global: &bonsai_index::GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    max_precision: Option<Precision>,
    func_filter: Option<&AHashSet<FuncId>>,
) -> bool {
    let passthroughs = compile_call_result_passthroughs(passthroughs);
    let mut passthroughs_by_arg: ahash::AHashMap<u8, Vec<usize>> = ahash::AHashMap::default();
    let mut receiver_passthroughs: Vec<usize> = Vec::new();
    for (idx, configured) in passthroughs.iter().enumerate() {
        if configured.passthrough.input_receiver {
            receiver_passthroughs.push(idx);
        }
        for &arg_idx in &configured.passthrough.input_arg_indices {
            if let Ok(arg_idx) = u8::try_from(arg_idx) {
                passthroughs_by_arg.entry(arg_idx).or_default().push(idx);
            }
        }
    }
    let mut seeded: ahash::AHashSet<bonsai_idg::WsNodeId> = seed_nodes.iter().copied().collect();
    let mut applied: ahash::AHashSet<(FuncId, bonsai_common::Span, u8, String)> = ahash::AHashSet::default();
    let mut callee_name_cache = CalleeNameCache::default();
    let mut any_grew = false;
    loop {
        let closure = idg.forward_closure_with_max_precision(seed_nodes, max_precision);
        let tainted_args = idg.tainted_call_args_in_reachable_nodes_for_funcs(&closure, func_filter);
        let descendant_inputs = DescendantClosureIndex::from_closure(&closure, idg, func_filter);
        let mut call_summary_cache: ahash::AHashMap<
            FuncId,
            ahash::AHashMap<bonsai_common::Span, CallEventSummary>,
        > = ahash::AHashMap::default();
        let mut grew = false;
        for (caller, call_span, arg_idx) in tainted_args {
            let Some(summary) = cached_call_event_summary(caller, call_span, global, &mut call_summary_cache)
            else {
                continue;
            };
            let candidate_indices = if arg_idx == u8::MAX {
                receiver_passthroughs.as_slice()
            } else {
                passthroughs_by_arg.get(&arg_idx).map_or(&[][..], Vec::as_slice)
            };
            for &configured_idx in candidate_indices {
                let configured = &passthroughs[configured_idx];
                let passthrough = configured.passthrough;
                if !configured.callee.matches(&summary.name, &mut callee_name_cache) {
                    continue;
                }
                let key = (caller, call_span, arg_idx, passthrough.callee.clone());
                if !applied.insert(key) {
                    continue;
                }
                let Some(ret_node) = idg.call_ret_node_at_site(caller, call_span) else {
                    continue;
                };
                if seeded.insert(ret_node) {
                    seed_nodes.push(ret_node);
                    grew = true;
                    any_grew = true;
                }
            }
        }
        for (caller, descendant_bases) in descendant_inputs.bases_by_func() {
            let Some(summaries) =
                cached_call_event_summaries_for_func(*caller, global, &mut call_summary_cache)
            else {
                continue;
            };
            for (call_span, summary) in summaries {
                for configured in &passthroughs {
                    let passthrough = configured.passthrough;
                    if !configured.callee.matches(&summary.name, &mut callee_name_cache) {
                        continue;
                    }
                    if passthrough.input_receiver
                        && call_receiver_has_descendant_input(summary, descendant_bases)
                    {
                        let key = (*caller, *call_span, u8::MAX, passthrough.callee.clone());
                        if applied.insert(key) {
                            if let Some(ret_node) = idg.call_ret_node_at_site(*caller, *call_span) {
                                if seeded.insert(ret_node) {
                                    seed_nodes.push(ret_node);
                                    grew = true;
                                    any_grew = true;
                                }
                            }
                        }
                    }
                    for &arg_idx in &passthrough.input_arg_indices {
                        let Ok(arg_idx_u8) = u8::try_from(arg_idx) else {
                            continue;
                        };
                        if !call_arg_has_descendant_input(summary, arg_idx, descendant_bases) {
                            continue;
                        }
                        let key = (*caller, *call_span, arg_idx_u8, passthrough.callee.clone());
                        if !applied.insert(key) {
                            continue;
                        }
                        let Some(ret_node) = idg.call_ret_node_at_site(*caller, *call_span) else {
                            continue;
                        };
                        if seeded.insert(ret_node) {
                            seed_nodes.push(ret_node);
                            grew = true;
                            any_grew = true;
                        }
                    }
                }
            }
        }
        if !grew {
            break;
        }
        seed_nodes.sort();
        seed_nodes.dedup();
    }
    any_grew
}

#[derive(Default)]
struct DescendantClosureIndex {
    bases_by_func: ahash::AHashMap<FuncId, ahash::AHashSet<String>>,
}

impl DescendantClosureIndex {
    fn from_closure(
        closure: &[bonsai_idg::WsNodeId],
        idg: &bonsai_idg::IdgQueryService,
        func_filter: Option<&AHashSet<FuncId>>,
    ) -> Self {
        let mut out = Self::default();
        for node in closure {
            let Some(point) = idg.resolve_point(*node) else {
                continue;
            };
            if func_filter.is_some_and(|funcs| !funcs.contains(&point.func)) {
                continue;
            }
            if !matches!(
                point.kind,
                bonsai_idg::PointKind::Read | bonsai_idg::PointKind::Write
            ) {
                continue;
            }
            for base in descendant_storage_bases(&point.name) {
                out.bases_by_func.entry(point.func).or_default().insert(base);
            }
        }
        out
    }

    fn bases_by_func(&self) -> impl Iterator<Item = (&FuncId, &ahash::AHashSet<String>)> {
        self.bases_by_func.iter()
    }
}

fn call_receiver_has_descendant_input(
    summary: &CallEventSummary,
    descendant_bases: &ahash::AHashSet<String>,
) -> bool {
    summary
        .receiver
        .as_deref()
        .is_some_and(|receiver| input_text_has_descendant_base(receiver, descendant_bases))
}

fn call_arg_has_descendant_input(
    summary: &CallEventSummary,
    arg_idx: usize,
    descendant_bases: &ahash::AHashSet<String>,
) -> bool {
    summary
        .args_place
        .get(arg_idx)
        .and_then(|place| place.as_deref())
        .is_some_and(|place| input_text_has_descendant_base(place, descendant_bases))
        || summary
            .args_value_text
            .get(arg_idx)
            .is_some_and(|text| input_text_has_descendant_base(text, descendant_bases))
}

fn input_text_has_descendant_base(text: &str, descendant_bases: &ahash::AHashSet<String>) -> bool {
    input_storage_bases(text)
        .into_iter()
        .any(|base| descendant_bases.contains(&base))
}

fn input_storage_bases(text: &str) -> Vec<String> {
    let mut out = ahash::AHashSet::default();
    let trimmed = text.trim();
    if let Some(base) = storage_base_candidate(trimmed) {
        out.insert(base);
    }
    for token in identifier_tokens_outside_strings(trimmed) {
        if let Some(base) = storage_base_candidate(&token) {
            out.insert(base);
        }
    }
    let mut out: Vec<String> = out.into_iter().collect();
    out.sort();
    out
}

fn storage_base_candidate(text: &str) -> Option<String> {
    let normalized = normalize_storage_text(text);
    if normalized.is_empty() {
        return None;
    }
    let base = normalized.split('.').next().unwrap_or("").trim();
    if is_bare_identifier(base) && !is_non_value_identifier(base) {
        Some(base.to_string())
    } else {
        None
    }
}

fn descendant_storage_bases(name: &str) -> Vec<String> {
    let normalized = normalize_storage_text(name);
    let parts: Vec<&str> = normalized.split('.').filter(|part| !part.is_empty()).collect();
    if parts.len() < 2 || !is_bare_identifier(parts[0]) {
        return Vec::new();
    }
    (1..parts.len()).map(|idx| parts[..idx].join(".")).collect()
}

fn normalize_storage_text(text: &str) -> String {
    let trimmed = text
        .trim()
        .trim_start_matches(['&', '*'])
        .trim_start_matches("mut ")
        .trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in trimmed.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            } else if ch.is_ascii_alphanumeric() || ch == '_' {
                out.push(ch);
            }
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '[' | '(' => out.push('.'),
            ']' | ')' => {}
            ':' if out.ends_with(':') => {}
            '-' | '>' => out.push('.'),
            ch if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '$' || ch == '@' => {
                out.push(ch);
            }
            _ => out.push('.'),
        }
    }
    out.split('.')
        .map(|part| part.trim().trim_start_matches(['$', '@', '%']))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn identifier_tokens_outside_strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
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
            push_identifier_token(&mut current, &mut out);
            quote = Some(ch);
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
            current.push(ch);
        } else {
            push_identifier_token(&mut current, &mut out);
        }
    }
    push_identifier_token(&mut current, &mut out);
    out
}

fn push_identifier_token(current: &mut String, out: &mut Vec<String>) {
    if current.is_empty() {
        return;
    }
    let token = std::mem::take(current);
    let base = token.split('.').next().unwrap_or("").trim();
    if is_bare_identifier(base) && !is_non_value_identifier(base) {
        out.push(token);
    }
}

fn is_non_value_identifier(token: &str) -> bool {
    matches!(
        token,
        "as" | "await"
            | "case"
            | "else"
            | "false"
            | "False"
            | "for"
            | "from"
            | "if"
            | "in"
            | "lambda"
            | "map"
            | "None"
            | "null"
            | "or"
            | "return"
            | "true"
            | "True"
            | "yield"
    )
}

/// Apply rulepack-declared output-argument transfers. If a configured
/// value argument is tainted at a call site, seed post-call consumers of
/// the configured output argument. The rulepack owns callee names and
/// argument indices; the IDG only supplies call-site shape and closure.
fn apply_output_arg_flow_fixpoint(
    seed_nodes: &mut Vec<bonsai_idg::WsNodeId>,
    flows: &[crate::inter::OutputArgFlow],
    global: &bonsai_index::GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    max_precision: Option<Precision>,
    func_filter: Option<&AHashSet<FuncId>>,
) -> bool {
    let flows: Vec<CompiledOutputArgFlow<'_>> = flows
        .iter()
        .map(|flow| CompiledOutputArgFlow {
            flow,
            callee: ConfiguredCalleeMatcher::new(&flow.callee),
        })
        .collect();
    let mut flows_by_arg: ahash::AHashMap<u8, Vec<usize>> = ahash::AHashMap::default();
    let mut flows_by_start_arg: Vec<usize> = Vec::new();
    for (idx, configured) in flows.iter().enumerate() {
        let start_arg = configured.flow.value_start_arg_index;
        if start_arg.is_some() {
            flows_by_start_arg.push(idx);
        }
        for &arg_idx in &configured.flow.value_arg_indices {
            if start_arg.is_some_and(|start| arg_idx >= start) {
                continue;
            }
            if let Ok(arg_idx) = u8::try_from(arg_idx) {
                flows_by_arg.entry(arg_idx).or_default().push(idx);
            }
        }
    }
    let mut seeded: ahash::AHashSet<bonsai_idg::WsNodeId> = seed_nodes.iter().copied().collect();
    let mut applied: ahash::AHashSet<(FuncId, bonsai_common::Span, usize, String)> =
        ahash::AHashSet::default();
    let mut callee_name_cache = CalleeNameCache::default();
    let mut iter = 0usize;
    let mut any_grew = false;
    loop {
        iter += 1;
        let closure = idg.forward_closure_with_max_precision(seed_nodes, max_precision);
        let tainted_args = idg.tainted_call_args_in_reachable_nodes_for_funcs(&closure, func_filter);
        let mut call_summary_cache: ahash::AHashMap<
            FuncId,
            ahash::AHashMap<bonsai_common::Span, CallEventSummary>,
        > = ahash::AHashMap::default();
        let mut grew = false;
        for (caller, call_span, arg_idx) in tainted_args {
            let Some(summary) = cached_call_event_summary(caller, call_span, global, &mut call_summary_cache)
            else {
                continue;
            };
            for &configured_idx in flows_by_arg.get(&arg_idx).map_or(&[][..], Vec::as_slice) {
                let configured = &flows[configured_idx];
                let flow = configured.flow;
                if (arg_idx as usize) == flow.output_arg_index {
                    continue;
                }
                if !configured.callee.matches(&summary.name, &mut callee_name_cache) {
                    continue;
                }
                let Some(output) = summary.output_arg_target(flow.output_arg_index) else {
                    continue;
                };
                let key = (caller, call_span, flow.output_arg_index, flow.callee.clone());
                if !applied.insert(key) {
                    continue;
                }
                for node in idg.nodes_for_name_after_span(caller, &output, call_span) {
                    if seeded.insert(node) {
                        seed_nodes.push(node);
                        grew = true;
                        any_grew = true;
                    }
                }
            }
            for &configured_idx in &flows_by_start_arg {
                let configured = &flows[configured_idx];
                let flow = configured.flow;
                if (arg_idx as usize) == flow.output_arg_index {
                    continue;
                }
                if flow
                    .value_start_arg_index
                    .is_none_or(|start| (arg_idx as usize) < start)
                    || !configured.callee.matches(&summary.name, &mut callee_name_cache)
                {
                    continue;
                }
                let Some(output) = summary.output_arg_target(flow.output_arg_index) else {
                    continue;
                };
                let key = (caller, call_span, flow.output_arg_index, flow.callee.clone());
                if !applied.insert(key) {
                    continue;
                }
                for node in idg.nodes_for_name_after_span(caller, &output, call_span) {
                    if seeded.insert(node) {
                        seed_nodes.push(node);
                        grew = true;
                        any_grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
        seed_nodes.sort();
        seed_nodes.dedup();
        bonsai_diagnostics::debug_log!(
            "output-arg-flow",
            "iter={} seeds={} applied={}",
            iter,
            seed_nodes.len(),
            applied.len()
        );
    }
    any_grew
}

#[cfg(test)]
fn call_result_passthrough_matches(call_name: &str, configured: &str) -> bool {
    ConfiguredCalleeMatcher::new(configured).matches(call_name, &mut CalleeNameCache::default())
}

struct CompiledCallResultPassthrough<'a> {
    passthrough: &'a crate::inter::CallResultPassthrough,
    callee: ConfiguredCalleeMatcher,
}

fn compile_call_result_passthroughs(
    passthroughs: &[crate::inter::CallResultPassthrough],
) -> Vec<CompiledCallResultPassthrough<'_>> {
    passthroughs
        .iter()
        .map(|passthrough| CompiledCallResultPassthrough {
            passthrough,
            callee: ConfiguredCalleeMatcher::new(&passthrough.callee),
        })
        .collect()
}

struct CompiledOutputArgFlow<'a> {
    flow: &'a crate::inter::OutputArgFlow,
    callee: ConfiguredCalleeMatcher,
}

enum ConfiguredCalleeMatcher {
    Regex {
        regex: Option<regex::Regex>,
        terminal: Option<String>,
    },
    Name {
        normalised: String,
        terminal: Option<String>,
    },
}

#[derive(Default)]
struct CalleeNameCache {
    trimmed: ahash::AHashMap<String, String>,
    normalised: ahash::AHashMap<String, String>,
}

impl CalleeNameCache {
    fn trimmed(&mut self, value: &str) -> &str {
        self.trimmed
            .entry(value.to_string())
            .or_insert_with(|| value.trim().trim_end_matches("()").to_string())
            .as_str()
    }

    fn normalised(&mut self, value: &str) -> &str {
        self.normalised
            .entry(value.to_string())
            .or_insert_with(|| normalise_passthrough_callee(value))
            .as_str()
    }
}

impl ConfiguredCalleeMatcher {
    fn new(configured: &str) -> Self {
        if let Some(regex) = configured.trim().strip_prefix("regex:") {
            return Self::Regex {
                regex: regex::Regex::new(regex).ok(),
                terminal: regex_terminal_literal(regex),
            };
        }
        let normalised = normalise_passthrough_callee(configured);
        Self::Name {
            terminal: callee_terminal_literal(&normalised),
            normalised,
        }
    }

    fn matches(&self, call_name: &str, cache: &mut CalleeNameCache) -> bool {
        match self {
            Self::Regex {
                regex: Some(regex),
                terminal,
            } => {
                if !callee_terminal_prefilter_matches(call_name, terminal.as_deref()) {
                    return false;
                }
                passthrough_compiled_regex_matches(regex, call_name, cache)
            }
            Self::Regex { regex: None, .. } => false,
            Self::Name {
                normalised: configured,
                terminal,
            } => {
                if !callee_terminal_prefilter_matches(call_name, terminal.as_deref()) {
                    return false;
                }
                let call = cache.normalised(call_name);
                if call.is_empty() || configured.is_empty() {
                    return false;
                }
                call == *configured
                    || call
                        .strip_suffix(configured)
                        .is_some_and(|prefix| prefix.ends_with('.'))
                    || configured
                        .strip_suffix(&call)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

fn callee_terminal_prefilter_matches(call_name: &str, terminal: Option<&str>) -> bool {
    terminal.is_none_or(|needle| needle.is_empty() || call_name.contains(needle))
}

fn callee_terminal_literal(normalised: &str) -> Option<String> {
    normalised
        .rsplit('.')
        .find(|part| !part.is_empty())
        .map(str::to_string)
}

fn regex_terminal_literal(pattern: &str) -> Option<String> {
    if has_unescaped_regex_alternation(pattern) {
        return None;
    }
    let mut current = String::new();
    let mut last = None;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                current.push(ch);
            } else if !current.is_empty() {
                last = Some(std::mem::take(&mut current));
            }
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            last = Some(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        last = Some(current);
    }
    last
}

fn has_unescaped_regex_alternation(pattern: &str) -> bool {
    let mut escaped = false;
    let mut in_class = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '|' if !in_class => return true,
            _ => {}
        }
    }
    false
}

fn normalise_passthrough_callee(value: &str) -> String {
    value
        .trim()
        .trim_end_matches("()")
        .replace("::", ".")
        .replace("->", ".")
        .replace(':', ".")
}

fn passthrough_compiled_regex_matches(
    regex: &regex::Regex,
    call_name: &str,
    cache: &mut CalleeNameCache,
) -> bool {
    let trimmed = cache.trimmed(call_name);
    if trimmed.is_empty() {
        return false;
    }
    if regex.is_match(trimmed) {
        return true;
    }
    regex.is_match(cache.normalised(call_name))
}

/// Recursive walker that finds Call events whose span is in
/// `target_spans`, checks the configured receiver-state
/// propagations, and seeds the receiver's post-call writers when
/// matched. Returns `grew=true` whenever it introduced a new seed.
#[allow(clippy::too_many_arguments)] // Recursive event walk threads shared seed/provenance state explicitly.
fn walk_call_events_for_propagation(
    events: &[bonsai_lang_api::FlowEvent],
    caller: FuncId,
    target_spans: &[bonsai_common::Span],
    propagations: &[crate::inter::ReceiverStatePropagation],
    idg: &bonsai_idg::IdgQueryService,
    seed_nodes: &mut Vec<bonsai_idg::WsNodeId>,
    applied: &mut ahash::AHashSet<(FuncId, bonsai_common::Span, String)>,
    grew: &mut bool,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                ..
            } => {
                if !target_spans.contains(span) {
                    continue;
                }
                if !receiver_state_matches(propagations, name, receiver_types) {
                    continue;
                }
                let Some(receiver_name) = receiver.as_deref().map(str::trim).filter(|r| !r.is_empty()) else {
                    continue;
                };
                let key = (caller, *span, receiver_name.to_string());
                if !applied.insert(key) {
                    continue;
                }
                // Seed downstream consumer ws_nodes (CallArg /
                // CallRet anchored after the rule-matched call)
                // that bridge_read from this receiver name. The
                // next closure round walks forward through them
                // and treats each as a tainted-arg for further
                // rule chaining.
                let mut added = idg.name_consumer_nodes_after_span(caller, receiver_name, *span);
                // Also seed every Read/Write ws_node for this
                // receiver name. The matcher's `receiver_is_tainted`
                // check (and the post-pass's `tainted_names_in_caller`
                // helper that feeds it) probes whether ANY Read/Write
                // node for the receiver carrier landed in the
                // forward closure — without these seeds, the
                // receiver-state propagation never registers as
                // "receiver tainted" for downstream sink rules even
                // though the consumer-bridges above do reach further
                // call sites.
                added.extend(idg.read_or_write_nodes_for_names(caller, &[receiver_name.to_string()]));
                if added.is_empty() {
                    continue;
                }
                seed_nodes.extend(added);
                *grew = true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_call_events_for_propagation(
                    then_events,
                    caller,
                    target_spans,
                    propagations,
                    idg,
                    seed_nodes,
                    applied,
                    grew,
                );
                walk_call_events_for_propagation(
                    else_events,
                    caller,
                    target_spans,
                    propagations,
                    idg,
                    seed_nodes,
                    applied,
                    grew,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_call_events_for_propagation(
                    body,
                    caller,
                    target_spans,
                    propagations,
                    idg,
                    seed_nodes,
                    applied,
                    grew,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_call_events_for_propagation(
                    body,
                    caller,
                    target_spans,
                    propagations,
                    idg,
                    seed_nodes,
                    applied,
                    grew,
                );
                walk_call_events_for_propagation(
                    catch_events,
                    caller,
                    target_spans,
                    propagations,
                    idg,
                    seed_nodes,
                    applied,
                    grew,
                );
                walk_call_events_for_propagation(
                    finally_events,
                    caller,
                    target_spans,
                    propagations,
                    idg,
                    seed_nodes,
                    applied,
                    grew,
                );
            }
            _ => {}
        }
    }
}

/// True when `name` (the call event's textual callee) plus
/// `receiver_types` (the adapter's narrowed static types) matches
/// any configured `ReceiverStatePropagation`. Mirrors the engine's
/// `configured_receiver_state_propagation_matches` so both paths
/// agree on which calls participate in receiver inheritance.
fn receiver_state_matches(
    configured: &[crate::inter::ReceiverStatePropagation],
    observed: &str,
    receiver_types: &[String],
) -> bool {
    let observed_trim = observed.trim();
    if observed_trim.is_empty() {
        return false;
    }
    let observed_tail = short_member_tail(observed_trim);
    configured.iter().any(|shape| {
        let method_trim = shape.method.trim();
        if method_trim.is_empty() {
            return false;
        }
        let method_match = method_trim == observed_trim
            || method_trim == observed_tail
            || short_member_tail(method_trim) == observed_tail;
        if !method_match {
            return false;
        }
        let Some(expected) = shape.receiver_type.as_deref() else {
            return true;
        };
        let expected_tail = short_member_tail(expected);
        receiver_types.iter().any(|actual| {
            let actual = actual.trim().trim_start_matches(['&', '*', '?', '!']);
            actual == expected || short_member_tail(actual) == expected_tail
        })
    })
}

/// Last `.` / `::` / `:` qualified segment, mirroring
/// `bonsai_callgraph::short_callee` semantics without the
/// dependency cycle: the qualified-prefix-stripped tail of an
/// identifier-like text. Empty input returns empty.
fn short_member_tail(name: &str) -> &str {
    let mut tail = name.trim();
    for sep in ["::", "->", "."] {
        if let Some((_, rest)) = tail.rsplit_once(sep) {
            tail = rest;
        }
    }
    if let Some((_, rest)) = tail.rsplit_once(':') {
        tail = rest;
    }
    tail
}

/// Compute BFS distances from `source_func` over the cross-call edge
/// graph. Callers absent from the returned map are unreachable and
/// sort to the end of the topological order.
fn distances_from_source(
    source_func: FuncId,
    edges: &[bonsai_idg::CrossCallEdge],
) -> ahash::AHashMap<FuncId, u32> {
    let mut adj: ahash::AHashMap<FuncId, Vec<FuncId>> = ahash::AHashMap::default();
    for ce in edges {
        adj.entry(ce.caller).or_default().push(ce.callee);
    }

    let mut distances: ahash::AHashMap<FuncId, u32> = ahash::AHashMap::default();
    distances.insert(source_func, 0);
    let mut frontier: Vec<FuncId> = vec![source_func];
    let mut depth: u32 = 0;
    while !frontier.is_empty() {
        depth += 1;
        let mut next: Vec<FuncId> = Vec::new();
        for f in &frontier {
            for &c in adj.get(f).map(Vec::as_slice).unwrap_or(&[]) {
                if !distances.contains_key(&c) {
                    distances.insert(c, depth);
                    next.push(c);
                }
            }
        }
        frontier = next;
    }
    distances
}

/// Walk `events` and collect every bare-identifier name reachable
/// through Assign / Call / Return events. Used by
/// [`entry_taint_graph_from_idg`] to enumerate candidate names for
/// the receiver-tainted check.
fn collect_caller_local_names(events: &[bonsai_lang_api::FlowEvent], params: &[String]) -> Vec<String> {
    let mut out: ahash::AHashSet<String> = params.iter().filter(|p| !p.is_empty()).cloned().collect();
    walk_collect_names(events, &mut out);
    out.into_iter().collect()
}

fn tainted_local_names_in_caller(
    caller: FuncId,
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    closure_set: &ahash::AHashSet<bonsai_idg::WsNodeId>,
) -> ahash::AHashSet<String> {
    let Some(caller_decl) = global.decl_of(bonsai_common::SymbolId::new(caller.raw())) else {
        return ahash::AHashSet::default();
    };
    let candidate_names = collect_caller_local_names(&caller_decl.flow_events, &caller_decl.params);
    idg.read_or_write_names_in_reachable_nodes(caller, &candidate_names, closure_set)
}

fn walk_collect_names(events: &[bonsai_lang_api::FlowEvent], out: &mut ahash::AHashSet<String>) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                if !target.is_empty() {
                    out.insert(target.clone());
                }
                if let Some(name) = source_name {
                    if !name.is_empty() {
                        out.insert(name.clone());
                    }
                }
                for n in source_names {
                    if !n.is_empty() {
                        out.insert(n.clone());
                    }
                }
                for n in source_call_args {
                    if !n.is_empty() {
                        out.insert(n.clone());
                    }
                }
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    if let Some(p) = arg.place.as_deref() {
                        if !p.is_empty() {
                            out.insert(p.to_string());
                        }
                    }
                    for n in &arg.source_names {
                        if !n.is_empty() {
                            out.insert(n.clone());
                        }
                    }
                }
            }
            FlowEvent::Return { value_name, .. } => {
                if let Some(n) = value_name {
                    if !n.is_empty() {
                        out.insert(n.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_collect_names(then_events, out);
                walk_collect_names(else_events, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_collect_names(body, out);
                walk_collect_names(catch_events, out);
                walk_collect_names(finally_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_collect_names(body, out);
            }
            _ => {}
        }
    }
}

fn tokenise_identifiers_outside_strings(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        if matches!(c, '\'' | '"' | '`') {
            push_id_token(&mut tokens, &mut current);
            quote = Some(c);
            continue;
        }
        if c == '_' || c.is_ascii_alphanumeric() {
            current.push(c);
        } else {
            push_id_token(&mut tokens, &mut current);
        }
    }
    push_id_token(&mut tokens, &mut current);
    tokens
}

fn push_id_token(tokens: &mut Vec<String>, current: &mut String) {
    if current
        .chars()
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_')
    {
        tokens.push(std::mem::take(current));
    } else {
        current.clear();
    }
}

#[derive(Clone, Debug)]
struct CallEventSummary {
    name: String,
    args_value_text: Vec<String>,
    args_span: Vec<bonsai_common::Span>,
    args_place: Vec<Option<String>>,
    receiver: Option<String>,
}

impl CallEventSummary {
    fn output_arg_target(&self, index: usize) -> Option<String> {
        self.args_place
            .get(index)
            .and_then(|place| place.as_deref())
            .map(str::trim)
            .filter(|place| !place.is_empty())
            .map(str::to_string)
            .or_else(|| {
                let text = self.args_value_text.get(index)?.trim();
                is_bare_identifier(text).then(|| text.to_string())
            })
    }
}

fn tainted_args_for_cross_call_edge(
    edge: &bonsai_idg::CrossCallEdge,
    callee_decl: Option<&bonsai_lang_api::Decl>,
    call_summary: Option<&CallEventSummary>,
) -> Vec<crate::inter::TaintedArg> {
    if edge.arg_idx == u8::MAX {
        return call_summary
            .and_then(|summary| summary.receiver.as_ref())
            .map(String::as_str)
            .map(str::trim)
            .filter(|receiver| !receiver.is_empty())
            .map(|receiver| {
                vec![crate::inter::TaintedArg {
                    index: usize::MAX,
                    value_text: receiver.to_string(),
                    param_name: "receiver".to_string(),
                }]
            })
            .unwrap_or_default();
    }
    let value_text = call_summary
        .and_then(|summary| summary.args_value_text.get(edge.arg_idx as usize).cloned())
        .unwrap_or_default();
    let param_name = if edge.param_idx == u8::MAX {
        String::new()
    } else {
        callee_decl
            .and_then(|decl| decl.params.get(edge.param_idx as usize).cloned())
            .unwrap_or_default()
    };
    vec![crate::inter::TaintedArg {
        index: edge.arg_idx as usize,
        value_text,
        param_name,
    }]
}

// Caller, arg, the two summaries, db/global, and two reuse caches — each is
// load-bearing; a wrapper struct would only relocate the argument list.
#[allow(clippy::too_many_arguments)]
fn tainted_arg_is_clean_nested_call_return(
    caller: FuncId,
    arg_idx: u8,
    call_summary: &CallEventSummary,
    cross_calls: &[bonsai_idg::CrossCallEdge],
    db: &AnalyzerDb,
    global: &GlobalIndex,
    call_summary_cache: &mut ahash::AHashMap<FuncId, ahash::AHashMap<bonsai_common::Span, CallEventSummary>>,
    function_summary_cache: &mut ahash::AHashMap<FuncId, crate::inter::FunctionSummary>,
    call_result_passthroughs: &[CompiledCallResultPassthrough<'_>],
    callee_name_cache: &mut CalleeNameCache,
) -> bool {
    let idx = usize::from(arg_idx);
    let Some(value_text) = call_summary.args_value_text.get(idx).map(String::as_str) else {
        return false;
    };
    let Some(arg_span) = call_summary.args_span.get(idx).copied() else {
        return false;
    };
    let Some((callee_text, nested_args)) = crate::inter::direct_call_expression_parts(value_text) else {
        return false;
    };
    if nested_call_return_matches_configured_passthrough(
        &callee_text,
        nested_args.len(),
        call_result_passthroughs,
        callee_name_cache,
    ) {
        return false;
    }

    let mut tainted_params_by_callee: ahash::AHashMap<FuncId, ahash::AHashSet<usize>> =
        ahash::AHashMap::default();
    for edge in cross_calls {
        if edge.caller != caller || edge.arg_idx == u8::MAX || edge.param_idx == u8::MAX {
            continue;
        }
        if !span_contains_or_equals(arg_span, edge.call_span) {
            continue;
        }
        let Some(nested_summary) =
            cached_call_event_summary(edge.caller, edge.call_span, global, call_summary_cache).cloned()
        else {
            continue;
        };
        if !call_names_match_direct_callee(&nested_summary.name, &callee_text) {
            continue;
        }
        tainted_params_by_callee
            .entry(edge.callee)
            .or_default()
            .insert(usize::from(edge.param_idx));
    }

    if tainted_params_by_callee.is_empty() {
        return !nested_args.is_empty();
    }

    for (callee, tainted_params) in tainted_params_by_callee {
        let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(callee.raw())) else {
            return false;
        };
        if decl.flow_events.is_empty() {
            return false;
        }
        let summary = function_summary_cache
            .entry(callee)
            .or_insert_with(|| crate::inter::function_summary(db, callee));
        if function_summary_returns_any_tainted_param(summary, &tainted_params) {
            return false;
        }
    }

    true
}

fn nested_call_return_matches_configured_passthrough(
    callee_text: &str,
    nested_arg_count: usize,
    passthroughs: &[CompiledCallResultPassthrough<'_>],
    callee_name_cache: &mut CalleeNameCache,
) -> bool {
    passthroughs.iter().any(|configured| {
        configured.callee.matches(callee_text, callee_name_cache)
            && (configured.passthrough.input_receiver
                || configured
                    .passthrough
                    .input_arg_indices
                    .iter()
                    .any(|idx| *idx < nested_arg_count))
    })
}

fn function_summary_returns_any_tainted_param(
    summary: &crate::inter::FunctionSummary,
    tainted_params: &ahash::AHashSet<usize>,
) -> bool {
    summary
        .returns_taint_of
        .iter()
        .any(|idx| tainted_params.contains(idx))
        || summary
            .returns_descendant_taint_of
            .iter()
            .any(|idx| tainted_params.contains(idx))
        || summary
            .returns_container_taint_of
            .iter()
            .any(|idx| tainted_params.contains(idx))
        || summary
            .returns_field_taint_of
            .iter()
            .any(|returned| tainted_params.contains(&returned.param))
        || summary
            .returns_element_taint_of
            .iter()
            .any(|returned| tainted_params.contains(&returned.param))
        || summary
            .returns_access_paths
            .iter()
            .any(|returned| tainted_params.contains(&returned.param))
}

fn span_contains_or_equals(outer: bonsai_common::Span, inner: bonsai_common::Span) -> bool {
    inner.start >= outer.start && inner.end <= outer.end
}

fn call_names_match_direct_callee(event_name: &str, callee_text: &str) -> bool {
    let event_name = event_name.trim();
    let callee_text = callee_text.trim();
    if event_name == callee_text {
        return true;
    }
    let event_tail = call_name_tail(event_name);
    let callee_tail = call_name_tail(callee_text);
    event_tail == callee_tail || event_name == callee_tail || event_tail == callee_text
}

fn call_name_tail(name: &str) -> &str {
    let mut tail = name.trim();
    if let Some(idx) = tail.rfind("->") {
        tail = &tail[idx + 2..];
    }
    if let Some((_, rest)) = tail.rsplit_once(['.', ':', '\\']) {
        tail = rest;
    }
    if let Some(idx) = tail.find('/') {
        if tail[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            tail = &tail[..idx];
        }
    }
    tail
}

fn cached_call_event_summary<'a>(
    func: FuncId,
    target_span: bonsai_common::Span,
    global: &GlobalIndex,
    cache: &'a mut ahash::AHashMap<FuncId, ahash::AHashMap<bonsai_common::Span, CallEventSummary>>,
) -> Option<&'a CallEventSummary> {
    cached_call_event_summaries_for_func(func, global, cache)
        .and_then(|summaries| summaries.get(&target_span))
}

fn cached_call_event_summaries_for_func<'a>(
    func: FuncId,
    global: &GlobalIndex,
    cache: &'a mut ahash::AHashMap<FuncId, ahash::AHashMap<bonsai_common::Span, CallEventSummary>>,
) -> Option<&'a ahash::AHashMap<bonsai_common::Span, CallEventSummary>> {
    if !cache.contains_key(&func) {
        let mut summaries: ahash::AHashMap<bonsai_common::Span, CallEventSummary> =
            ahash::AHashMap::default();
        if let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) {
            collect_call_event_summaries(&decl.flow_events, &mut summaries);
        }
        cache.insert(func, summaries);
    }
    cache.get(&func)
}

fn collect_call_event_summaries(
    events: &[bonsai_lang_api::FlowEvent],
    out: &mut ahash::AHashMap<bonsai_common::Span, CallEventSummary>,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                args,
                receiver,
                ..
            } => {
                out.insert(
                    *span,
                    CallEventSummary {
                        name: name.clone(),
                        args_value_text: args.iter().map(|arg| arg.value_text.clone()).collect(),
                        args_span: args.iter().map(|arg| arg.span).collect(),
                        args_place: args.iter().map(|arg| arg.place.clone()).collect(),
                        receiver: receiver.clone(),
                    },
                );
            }
            FlowEvent::Assign {
                span,
                source_call: Some(name),
                source_call_args,
                ..
            } => {
                out.entry(*span).or_insert_with(|| CallEventSummary {
                    name: name.clone(),
                    args_value_text: source_call_args.clone(),
                    args_span: source_call_args.iter().map(|_| *span).collect(),
                    args_place: source_call_args
                        .iter()
                        .map(|arg| is_bare_identifier(arg.trim()).then(|| arg.trim().to_string()))
                        .collect(),
                    receiver: None,
                });
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_call_event_summaries(then_events, out);
                collect_call_event_summaries(else_events, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_call_event_summaries(body, out);
                collect_call_event_summaries(catch_events, out);
                collect_call_event_summaries(finally_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_call_event_summaries(body, out);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "reachable_tests.rs"]
mod tests;
