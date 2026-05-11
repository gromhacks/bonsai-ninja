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
                entry_func,
                &seed,
                &config,
                db,
                &caches,
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
                // taint carriers too — catches pointer-out patterns
                // (`sscanf(qs, fmt, token, action)` in C) where the
                // variable isn't an `Assign` target but clearly
                // carries data from this call.
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

/// IDG-driven [`EntryTaintGraph`] builder. Closes the per-source
/// interprocedural pass entirely on the workspace IDG —
/// SSA-narrowed forward closure plus cross-call lifting.
///
/// `source_anchor` is the rule match's source span: seeds are
/// IDG nodes anchored at that span (`CallRet`, `CallArg`,
/// span-distinct `Write`). `output_arg_names`, when non-empty,
/// names additional carriers for the source's side-effect outputs
/// (e.g. `fgets(buf, ...)` with `output_arg_names=["buf"]` seeds
/// post-call reads/writes of `buf`). When neither are supplied,
/// the seed set falls back to entry params + every Read/Write of
/// `seeds`.
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
    let global = db.global_index();
    let mut graph = EntryTaintGraph::default();

    // Compose the seed set. The IDG transfer pass already models
    // the source's side-effect Write (when the callee is a
    // known side-effecting function — see
    // `side_effect_output_args_for` in transfer.rs); the
    // span-anchored seed captures it. `output_arg_names` is kept
    // as a hint but only consulted when the span-anchored seed
    // turns up empty — otherwise it would over-include post-call
    // clean overwrites of the same carrier name.
    let mut seed_nodes: Vec<bonsai_idg::WsNodeId> = Vec::new();
    if let Some(anchor) = source_anchor {
        seed_nodes.extend(idg.source_seed_nodes_at_span(source_func, anchor));
        if seed_nodes.is_empty() {
            for arg_name in output_arg_names {
                if arg_name.is_empty() {
                    continue;
                }
                seed_nodes.extend(idg.nodes_for_name_after_span(source_func, arg_name, anchor));
            }
        }
    }
    if seed_nodes.is_empty() {
        let seed_names: Vec<String> = seeds.iter().cloned().collect();
        // Narrow param-seeding to the param names the source rule
        // actually matched. Without this filter, sibling params get
        // pulled into the closure (e.g. `def handle(user, safe)`
        // would taint `safe` too just because `user` matched the
        // rule), surfacing unrelated downstream sinks as findings.
        // Falls back to every param only when the seed name set is
        // empty — in that case we have no signal narrower than "any
        // entry" and broadest-seed semantics is the engine's
        // historical default.
        if !seed_names.is_empty() {
            let narrowed = idg.param_nodes_for_names(source_func, &seed_names, global.as_ref());
            if !narrowed.is_empty() {
                seed_nodes.extend(narrowed);
            } else {
                seed_nodes.extend(idg.param_nodes_of(source_func));
            }
        } else {
            seed_nodes.extend(idg.param_nodes_of(source_func));
        }
        seed_nodes.extend(idg.read_or_write_nodes_for_names(source_func, &seed_names));
    }
    seed_nodes.sort();
    seed_nodes.dedup();
    if seed_nodes.is_empty() {
        return graph;
    }

    if bonsai_diagnostics::debug::is_enabled("idg-closure") {
        let n = global
            .decl_of(bonsai_common::SymbolId::new(source_func.raw()))
            .map(|d| d.name.clone())
            .unwrap_or_default();
        let xc_pre = idg.cross_call_edges_in_closure(&seed_nodes);
        let closure = idg.forward_closure(&seed_nodes);
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
                        format!("ws#{}={:?}@{}..{}", w.0, p.kind, p.span.start, p.span.end)
                    })
                })
                .collect();
            bonsai_diagnostics::debug_log!(
                "idg-closure-detail",
                "  closure_nodes: {:?}",
                detail
            );
        }
    }

    // Receiver-state-propagation post-pass. The engine applied
    // `taint_semantics.taint_receiver_from_args` rules during its
    // worklist; the IDG mirrors this via a closure-augmenting
    // post-pass driven by the rulepack-extracted propagation list.
    // For each tainted CallArg whose call matches a configured
    // (method, receiver_type) propagation, we walk every CallArg /
    // CallRet / CallArg-receiver-bridge node anchored at downstream
    // call sites that consume the receiver name (positional arg,
    // explicit receiver, or implicit-receiver bridge) and seed
    // those into the closure. The next-iteration closure then
    // includes them, which surfaces them as tainted-call args for
    // any further propagation rules to chain off. Iterate to a
    // fixpoint — the (caller, span, receiver_name) seen-set bounds
    // it to a small constant number of rounds.
    if !receiver_state_propagations.is_empty() {
        apply_receiver_state_fixpoint(
            &mut seed_nodes,
            receiver_state_propagations,
            global.as_ref(),
            idg,
        );
    }

    // Cross-call edges in closure → call_records. Sort
    // topologically (caller-before-callee) so trace_id assignment
    // matches the engine's worklist order — `first_inflow[caller]`
    // must already be populated when a record with that caller is
    // processed, otherwise lineage chains reconstructed from
    // parent_trace_id come out reversed.
    let cross_calls = {
        let mut edges = idg.cross_call_edges_in_closure(&seed_nodes);
        // Topological sort: walk from source_func outward, ordering
        // edges by their distance from source_func. Edges whose
        // caller hasn't been visited yet come later. This is
        // breadth-first by caller.
        let distances: Vec<(FuncId, u32)> = edges
            .iter()
            .map(|ce| ce.caller)
            .collect::<ahash::AHashSet<_>>()
            .into_iter()
            .map(|f| (f, distance_from(f, source_func, &edges)))
            .collect();
        let dist_map: ahash::AHashMap<FuncId, u32> = distances.into_iter().collect();
        edges.sort_by_key(|ce| (
            dist_map.get(&ce.caller).copied().unwrap_or(u32::MAX),
            ce.caller.raw(),
            ce.call_span.start,
            ce.arg_idx,
        ));
        edges
    };
    let mut next_trace_id: u64 = 1;
    let mut first_inflow: ahash::AHashMap<FuncId, u64> = ahash::AHashMap::new();
    let mut call_records: Vec<TaintedCallEdge> = Vec::with_capacity(cross_calls.len());
    let mut worst = Precision::Exact;
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

        let caller_decl = global.decl_of(bonsai_common::SymbolId::new(ce.caller.raw()));
        let callee_decl = global.decl_of(bonsai_common::SymbolId::new(ce.callee.raw()));
        let value_text = caller_decl
            .and_then(|d| {
                find_call_arg_value_text(&d.flow_events, ce.call_span, ce.arg_idx as usize)
            })
            .unwrap_or_default();
        let param_name = callee_decl
            .and_then(|d| d.params.get(ce.param_idx as usize).cloned())
            .unwrap_or_default();
        call_records.push(TaintedCallEdge {
            trace_id,
            parent_trace_id,
            caller: ce.caller,
            callee: ce.callee,
            call_span: ce.call_span,
            tainted_args: vec![crate::inter::TaintedArg {
                index: ce.arg_idx as usize,
                value_text,
                param_name,
            }],
            precision: ce.precision,
        });
    }

    // Tainted call sites in closure → tainted_calls.
    let tainted_args_by_site = idg.tainted_call_args_in_closure(&seed_nodes);
    let mut by_site: ahash::AHashMap<(FuncId, bonsai_common::Span), Vec<u8>> =
        ahash::AHashMap::new();
    for (caller, call_span, arg_idx) in &tainted_args_by_site {
        by_site
            .entry((*caller, *call_span))
            .or_default()
            .push(*arg_idx);
    }

    // Closure set for receiver-tainted check.
    let closure_set: ahash::AHashSet<bonsai_idg::WsNodeId> =
        idg.forward_closure(&seed_nodes).into_iter().collect();
    let tainted_names_in_caller = |caller: FuncId| -> ahash::AHashSet<String> {
        let mut out: ahash::AHashSet<String> = ahash::AHashSet::default();
        let Some(caller_decl) = global.decl_of(bonsai_common::SymbolId::new(caller.raw())) else {
            return out;
        };
        let candidate_names =
            collect_caller_local_names(&caller_decl.flow_events, &caller_decl.params);
        for name in candidate_names {
            let nodes = idg.read_or_write_nodes_for_names(caller, &[name.clone()]);
            if nodes.iter().any(|n| closure_set.contains(n)) {
                out.insert(name);
            }
        }
        out
    };

    let mut tainted_calls: Vec<crate::inter::TaintedCall> = Vec::new();
    let mut sorted_sites: Vec<((FuncId, bonsai_common::Span), Vec<u8>)> =
        by_site.into_iter().collect();
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
        let caller_decl = match global.decl_of(bonsai_common::SymbolId::new(caller.raw())) {
            Some(d) => d,
            None => continue,
        };
        let Some(call_event) = find_call_event(&caller_decl.flow_events, call_span) else {
            continue;
        };
        let bonsai_lang_api::FlowEvent::Call {
            name, args, receiver, ..
        } = call_event
        else {
            continue;
        };
        let mut tainted_args: Vec<crate::inter::TaintedArgAtCall> = arg_indices
            .iter()
            .filter_map(|idx| {
                args.get(*idx as usize).map(|arg| crate::inter::TaintedArgAtCall {
                    index: *idx as usize,
                    value_text: arg.value_text.clone(),
                })
            })
            .collect();
        tainted_args.sort_by_key(|a| a.index);
        tainted_args.dedup_by_key(|a| a.index);
        let parent_trace_id = first_inflow.get(&caller).copied();
        let tainted_receiver = receiver.as_ref().and_then(|recv| {
            let names = tainted_names_in_caller(caller);
            for token in tokenise_identifiers_outside_strings(recv) {
                if names.contains(&token) {
                    return Some(recv.clone());
                }
            }
            None
        });
        tainted_calls.push(crate::inter::TaintedCall {
            parent_trace_id,
            caller,
            name: name.clone(),
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
        let return_funcs: Vec<FuncId> = funcs_with_returnable_taint(&closure_set, idg);
        for func in return_funcs {
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
            let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
                continue;
            };
            let names = {
                let mut out: ahash::AHashSet<String> = ahash::AHashSet::default();
                let candidate_names = collect_caller_local_names(&decl.flow_events, &decl.params);
                for name in candidate_names {
                    let nodes = idg.read_or_write_nodes_for_names(func, &[name.clone()]);
                    if nodes.iter().any(|n| closure_set.contains(n)) {
                        out.insert(name);
                    }
                }
                out
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

/// Find every FuncId whose `Place::Return` ws_node lies in
/// `closure_set`. The IDG service exposes a per-func Return node
/// lookup, so we iterate every func in the workspace and probe.
/// Used by the return-sink emission pass to know which functions
/// reach a tainted return.
fn funcs_with_returnable_taint(
    closure_set: &ahash::AHashSet<bonsai_idg::WsNodeId>,
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<FuncId> {
    let mut out: Vec<FuncId> = Vec::new();
    for func in idg.all_funcs() {
        let Some(return_ws) = idg.return_node_of(func) else {
            continue;
        };
        if closure_set.contains(&return_ws) {
            out.push(func);
        }
    }
    out.sort_by_key(|f| f.raw());
    out.dedup();
    out
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
                    if !tainted_names.iter().any(|n| value.contains(n.as_str())) {
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
                for n in source_call_args {
                    push_if_tainted(n, &mut tainted_args);
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
            FlowEvent::Loop { body, .. }
            | FlowEvent::Defer { body, .. }
            | FlowEvent::Using { body, .. } => {
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

fn collect_return_spans(
    events: &[bonsai_lang_api::FlowEvent],
    out: &mut Vec<bonsai_common::Span>,
) {
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
            FlowEvent::Loop { body, .. }
            | FlowEvent::Defer { body, .. }
            | FlowEvent::Using { body, .. } => {
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
) {
    let mut applied: ahash::AHashSet<(FuncId, bonsai_common::Span, String)> =
        ahash::AHashSet::default();
    bonsai_diagnostics::debug_log!(
        "recv-state",
        "fixpoint start: {} propagation rule(s)",
        propagations.len()
    );
    let mut iter = 0usize;
    loop {
        iter += 1;
        let tainted = idg.tainted_call_args_in_closure(seed_nodes);
        let mut grew = false;
        // Per-caller, look up flow events once and walk them to find
        // the call event matching each tainted (caller, call_span).
        // Sort by (caller, span) so the iteration order is stable
        // across runs — receiver-state-driven seeds added to
        // `seed_nodes` need a deterministic ordering or the
        // downstream chain enumeration produces different `S:` ids
        // between back-to-back invocations of the same workspace.
        let mut by_caller: ahash::AHashMap<FuncId, Vec<bonsai_common::Span>> =
            ahash::AHashMap::default();
        for (caller, call_span, _arg_idx) in &tainted {
            by_caller.entry(*caller).or_default().push(*call_span);
        }
        let mut sorted_callers: Vec<(FuncId, Vec<bonsai_common::Span>)> =
            by_caller.into_iter().collect();
        sorted_callers.sort_by_key(|(f, _)| f.raw());
        for (caller, mut spans) in sorted_callers {
            spans.sort();
            spans.dedup();
            let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(caller.raw()))
            else {
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

/// Recursive walker that finds Call events whose span is in
/// `target_spans`, checks the configured receiver-state
/// propagations, and seeds the receiver's post-call writers when
/// matched. Returns `grew=true` whenever it introduced a new seed.
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
                let Some(receiver_name) = receiver
                    .as_deref()
                    .map(str::trim)
                    .filter(|r| !r.is_empty())
                else {
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
                let mut added = idg.name_consumer_nodes_after_span(
                    caller,
                    receiver_name,
                    *span,
                );
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
                added.extend(
                    idg.read_or_write_nodes_for_names(
                        caller,
                        &[receiver_name.to_string()],
                    ),
                );
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
            FlowEvent::Loop { body, .. }
            | FlowEvent::Defer { body, .. }
            | FlowEvent::Using { body, .. } => {
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
            let actual = actual.trim().trim_start_matches(|c: char| {
                matches!(c, '&' | '*' | '?' | '!')
            });
            actual == expected
                || short_member_tail(actual) == expected_tail
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

/// Compute the BFS distance from `source_func` to `target` over
/// the cross-call edge graph. Returns `u32::MAX` for unreachable
/// targets (those edges sort to the end of the topological order).
fn distance_from(
    target: FuncId,
    source_func: FuncId,
    edges: &[bonsai_idg::CrossCallEdge],
) -> u32 {
    if target == source_func {
        return 0;
    }
    // Build caller → callees adjacency from `edges`.
    let mut adj: ahash::AHashMap<FuncId, Vec<FuncId>> = ahash::AHashMap::default();
    for ce in edges {
        adj.entry(ce.caller).or_default().push(ce.callee);
    }
    // BFS from source_func until we find `target`.
    let mut visited: ahash::AHashSet<FuncId> = ahash::AHashSet::default();
    let mut frontier: Vec<FuncId> = vec![source_func];
    let mut depth: u32 = 0;
    while !frontier.is_empty() {
        depth += 1;
        let mut next: Vec<FuncId> = Vec::new();
        for f in &frontier {
            for &c in adj.get(f).map(Vec::as_slice).unwrap_or(&[]) {
                if c == target {
                    return depth;
                }
                if visited.insert(c) {
                    next.push(c);
                }
            }
        }
        frontier = next;
    }
    u32::MAX
}

/// Walk `events` and collect every bare-identifier name reachable
/// through Assign / Call / Return events. Used by
/// [`entry_taint_graph_from_idg`] to enumerate candidate names for
/// the receiver-tainted check.
fn collect_caller_local_names(
    events: &[bonsai_lang_api::FlowEvent],
    params: &[String],
) -> Vec<String> {
    let mut out: ahash::AHashSet<String> = params.iter().filter(|p| !p.is_empty()).cloned().collect();
    walk_collect_names(events, &mut out);
    out.into_iter().collect()
}

fn walk_collect_names(
    events: &[bonsai_lang_api::FlowEvent],
    out: &mut ahash::AHashSet<String>,
) {
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
            FlowEvent::Loop { body, .. }
            | FlowEvent::Defer { body, .. }
            | FlowEvent::Using { body, .. } => {
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

fn find_call_event<'a>(
    events: &'a [bonsai_lang_api::FlowEvent],
    target_span: bonsai_common::Span,
) -> Option<&'a bonsai_lang_api::FlowEvent> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { span, .. } if *span == target_span => return Some(event),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(v) = find_call_event(then_events, target_span) {
                    return Some(v);
                }
                if let Some(v) = find_call_event(else_events, target_span) {
                    return Some(v);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(v) = find_call_event(body, target_span) {
                    return Some(v);
                }
                if let Some(v) = find_call_event(catch_events, target_span) {
                    return Some(v);
                }
                if let Some(v) = find_call_event(finally_events, target_span) {
                    return Some(v);
                }
            }
            FlowEvent::Loop { body, .. }
            | FlowEvent::Defer { body, .. }
            | FlowEvent::Using { body, .. } => {
                if let Some(v) = find_call_event(body, target_span) {
                    return Some(v);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_call_arg_value_text(
    events: &[bonsai_lang_api::FlowEvent],
    target_span: bonsai_common::Span,
    arg_idx: usize,
) -> Option<String> {
    use bonsai_lang_api::FlowEvent;
    let event = find_call_event(events, target_span)?;
    if let FlowEvent::Call { args, .. } = event {
        args.get(arg_idx).map(|a| a.value_text.clone())
    } else {
        None
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::{FileId, Span};

    fn span() -> Span {
        Span {
            file: FileId::new(0),
            start: 0,
            end: 1,
        }
    }

    #[test]
    fn reachable_assignment_rhs_metadata_is_surfaced() {
        let events = vec![FlowEvent::Assign {
            span: span(),
            target: "cmd".to_string(),
            source_name: Some("legacy_input".to_string()),
            source_call: Some("pkg.transform".to_string()),
            source_call_args: vec!["user_input".to_string()],
            source_names: vec!["request.args".to_string(), "fallback".to_string()],
                        declares_new_binding: false,
                        value_kind: None,
                    }];

        let mut kinded = KindedTokens::default();
        collect_flow_event_tokens_kinded(&events, &mut kinded);
        assert!(kinded.by_kind[&FactKind::Write].contains("cmd"));
        for expected in ["legacy_input", "request.args", "fallback"] {
            assert!(
                kinded.by_kind[&FactKind::Read].contains(expected),
                "missing read token {expected}"
            );
        }
        for expected in ["pkg.transform", "transform"] {
            assert!(
                kinded.by_kind[&FactKind::Call].contains(expected),
                "missing call token {expected}"
            );
        }
        assert!(kinded.by_kind[&FactKind::Arg].contains("user_input"));
    }

    #[test]
    fn taint_entry_flow_facts_include_short_call_tail() {
        let events = vec![FlowEvent::Call {
            span: span(),
            name: "pkg.execute".to_string(),
            receiver: Some("pkg".to_string()),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: Vec::new(),
            receiver_types: Vec::new(),
        }];

        let mut facts = KindedTokens::default();
        collect_flow_facts(&events, &mut facts);
        assert!(facts.by_kind[&FactKind::Call].contains("pkg.execute"));
        assert!(facts.by_kind[&FactKind::Call].contains("execute"));
    }
}
