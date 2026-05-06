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
#[must_use]
pub fn taint_facts_and_graph_for_entry(
    entry_func: FuncId,
    db: &AnalyzerDb,
    _sanitizers: &TokenSet,
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
        let mut caches = crate::inter::InterTaintCaches::default();
        let graph_result = crate::inter::interprocedural_taint_to_completion_with_caches(
            entry_func,
            &graph_seed,
            &config,
            db,
            &mut caches,
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
                &mut caches,
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
