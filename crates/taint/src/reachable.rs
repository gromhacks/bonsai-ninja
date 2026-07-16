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

use crate::text::normalise_qualified_text;
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

pub(crate) const SYNTHETIC_RECEIVER_PARAM_NAME: &str = "receiver";

/// The semantic contract used to translate source facts into IDG seed nodes.
///
/// Both policies consume indexed AST/flow facts. `RuleMatch` is span-anchored
/// and field-sensitive for security rules; `LegacyTokenApi` preserves the
/// historical public token API's sigil, call-result, and first-write behavior.
/// Keeping the policy explicit lets every consumer share one seed composer
/// without silently mixing the two contracts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum IdgSeedPolicy {
    RuleMatch,
    LegacyTokenApi,
}

/// Input to [`compose_idg_seed_nodes`].
#[derive(Copy, Clone, Debug)]
pub struct IdgSeedRequest<'a> {
    func: FuncId,
    names: &'a TokenSet,
    anchor: Option<Span>,
    output_arg_names: &'a [String],
    policy: IdgSeedPolicy,
}

impl<'a> IdgSeedRequest<'a> {
    #[must_use]
    pub fn rule_match(
        func: FuncId,
        names: &'a TokenSet,
        anchor: Option<Span>,
        output_arg_names: &'a [String],
    ) -> Self {
        Self {
            func,
            names,
            anchor,
            output_arg_names,
            policy: IdgSeedPolicy::RuleMatch,
        }
    }

    #[must_use]
    pub fn legacy_tokens(func: FuncId, names: &'a TokenSet) -> Self {
        Self {
            func,
            names,
            anchor: None,
            output_arg_names: &[],
            policy: IdgSeedPolicy::LegacyTokenApi,
        }
    }
}

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
    /// Compatibility metric for the number of resolved cross-call relations
    /// represented by this graph. It never limits semantic work.
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
    /// Resolver sub-kind retained from the IDG cross-call edge.
    #[serde(default = "default_call_edge_kind")]
    pub edge_kind: bonsai_callgraph::EdgeKind,
}

fn default_call_edge_kind() -> bonsai_callgraph::EdgeKind {
    bonsai_callgraph::EdgeKind::Direct
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

/// Default entry seed for fact-oriented and diagnostic taint queries:
/// formal params plus locally bound assignment targets and bare call
/// arguments. This is the shared seed shape for `dump-taint` and the
/// fact side of `inspect`/dataflow.
#[must_use]
pub fn default_entry_taint_seed(decl: Option<&bonsai_lang_api::Decl>) -> TokenSet {
    let mut seed: TokenSet = decl
        .map(|decl| {
            decl.params
                .iter()
                .filter(|param| !param.is_empty())
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(decl) = decl {
        collect_assign_targets(&decl.flow_events, &mut seed, false);
    }
    seed
}

/// Default entry seed for graph materialization: the fact seed plus
/// RHS value operands, return/yield values, and other graph-visible
/// tokens. Callable target/module components are deliberately not
/// promoted to value carriers; receiver/callable taint must arrive
/// through real params, assignment targets, arguments, or explicit
/// source evidence.
#[must_use]
pub fn default_entry_graph_seed(decl: Option<&bonsai_lang_api::Decl>) -> TokenSet {
    let mut seed: TokenSet = decl
        .map(|decl| {
            decl.params
                .iter()
                .filter(|param| !param.is_empty())
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(decl) = decl {
        collect_assign_targets(&decl.flow_events, &mut seed, false);
        collect_graph_seed_tokens(&decl.flow_events, &mut seed);
    }
    seed
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
    let seed = default_entry_taint_seed(entry_decl);
    let graph_seed = default_entry_graph_seed(entry_decl);

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
        // A cold cached-dataflow query must not publish a warmed workspace
        // service, but it still uses the one canonical IDG engine. The
        // semantic-fingerprint cache shares this compiler graph across entry
        // misses without changing `AnalyzerDb::idg_service()` lifecycle.
        let idg = crate::idg_build::compiler_idg_service_without_default_seed(db);
        caches.mark_used();
        let config = crate::inter::InterTaintConfig {
            sanitizers: TokenSet::default(),
            max_edge_precision: Some(Precision::Narrowed),
            ..Default::default()
        };
        let graph_result = crate::inter::idg_backed_interprocedural_taint_with_service(
            entry_func,
            &graph_seed,
            &config,
            db,
            idg.as_ref(),
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
                edge_kind: record.edge_kind,
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
            fact_result = crate::inter::idg_backed_interprocedural_taint_with_service(
                entry_func,
                &seed,
                &config,
                db,
                idg.as_ref(),
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

/// Build the rulepack-free inspect taint graph for one entry, cut to
/// the functions that contain the user's query/filter hits. This uses
/// the same broad entry seed shape as [`taint_facts_and_graph_for_entry`]
/// but asks the IDG for a target cut instead of materialising every
/// downstream terminal propagation reachable from the entry.
#[must_use]
pub fn inspect_entry_taint_graph_from_idg_with_target_funcs(
    entry_func: FuncId,
    target_funcs: Option<&AHashSet<FuncId>>,
    db: &AnalyzerDb,
    idg: &bonsai_idg::IdgQueryService,
) -> EntryTaintGraph {
    let global = db.global_index();
    let entry_decl = global.decl_of(SymbolId::new(entry_func.raw()));
    let graph_seed = default_entry_graph_seed(entry_decl);
    if graph_seed.is_empty() {
        return EntryTaintGraph::default();
    }
    entry_taint_graph_from_idg_with_target_funcs_and_max_precision(
        entry_func,
        &graph_seed,
        None,
        &[],
        &[],
        &[],
        &[],
        target_funcs,
        Some(Precision::Narrowed),
        db,
        idg,
    )
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
                let _ = source_call_args;
            }
            FlowEvent::Call { args, .. } => {
                // Candidate carriers come from adapter/tree-sitter facts,
                // never by reparsing the rendering string.
                for arg in args {
                    if let Some(place) = arg.place.as_deref().filter(|place| !place.is_empty()) {
                        out.insert(place.to_string());
                    }
                    for source in &arg.source_names {
                        if !source.is_empty() {
                            out.insert(source.clone());
                        }
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
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
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
                source_call,
                source_names,
                source_call_args,
                ..
            } => {
                if let Some(name) = source_name.as_deref() {
                    if !source_name_is_call_target_component(name, source_call.as_deref()) {
                        insert_graph_seed(out, name);
                    }
                }
                for name in source_names {
                    if source_name_is_call_target_component(name, source_call.as_deref()) {
                        continue;
                    }
                    insert_graph_seed(out, name);
                }
                let _ = source_call_args;
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    // The `place` slot carries the abstract place-id string when
                    // the adapter resolved one — useful as a stable seed key.
                    if let Some(place) = arg.place.as_deref() {
                        insert_graph_seed(out, place);
                    }
                    for source in &arg.source_names {
                        insert_graph_seed(out, source);
                    }
                }
            }
            FlowEvent::Return {
                value_name,
                value_flow,
                ..
            } => {
                if let Some(value) = value_name.as_deref() {
                    insert_graph_seed(out, value);
                }
                collect_expression_flow_seed_tokens(value_flow, out);
            }
            FlowEvent::Throw { value_name, .. } => {
                if let Some(value) = value_name.as_deref() {
                    insert_graph_seed(out, value);
                }
            }
            FlowEvent::Yield { value_flow, .. } => {
                collect_expression_flow_seed_tokens(value_flow, out);
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

fn collect_expression_flow_seed_tokens(flow: &bonsai_lang_api::ExpressionFlow, out: &mut TokenSet) {
    if let Some(place) = flow.place.as_deref() {
        insert_graph_seed(out, place);
    }
    for source in &flow.source_names {
        insert_graph_seed(out, source);
    }
    for field in &flow.aggregate_fields {
        collect_expression_flow_seed_tokens(&field.value, out);
    }
    for item in &flow.tuple_items {
        collect_expression_flow_seed_tokens(item, out);
    }
    for spread in &flow.spreads {
        collect_expression_flow_seed_tokens(spread, out);
    }
}

fn source_name_is_call_target_component(source_name: &str, source_call: Option<&str>) -> bool {
    let source_name = normalise_qualified_text(source_name);
    let source_name = source_name.trim();
    let Some(source_call) = source_call.map(normalise_qualified_text) else {
        return false;
    };
    let source_call = source_call.trim();
    if source_name.is_empty() || source_call.is_empty() {
        return false;
    }
    if source_name == source_call || source_name == short_callee(source_call) {
        return true;
    }
    for sep in bonsai_common::QUALIFIED_NAME_SEPARATORS {
        if source_call
            .strip_prefix(source_name)
            .is_some_and(|rest| rest.starts_with(sep))
        {
            return true;
        }
    }
    source_call
        .split(['.', ':'])
        .flat_map(|part| part.split("->"))
        .any(|component| component == source_name)
}

/// Insert an adapter/tree-sitter-derived carrier into the graph seed set.
/// Literal classification belongs to the adapter (`AssignValueKind`), not a
/// cross-language spelling inventory in the engine.
fn insert_graph_seed(out: &mut TokenSet, token: &str) {
    let token = token.trim();
    if token.is_empty() {
        return;
    }
    out.insert(token.to_string());
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

/// Canonical source-fact to IDG-node composer used by taint, security, and
/// compatibility APIs. Policy selects semantics; graph-node lookup and
/// deterministic normalization live in this one implementation.
#[must_use]
pub fn compose_idg_seed_nodes(
    request: IdgSeedRequest<'_>,
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    match request.policy {
        IdgSeedPolicy::RuleMatch => rule_match_seed_nodes(
            request.func,
            request.names,
            request.anchor,
            request.output_arg_names,
            global,
            idg,
        ),
        IdgSeedPolicy::LegacyTokenApi => legacy_token_seed_nodes(request.func, request.names, global, idg),
    }
}

fn rule_match_seed_nodes(
    source_func: FuncId,
    seeds: &TokenSet,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    let mut seed_nodes: Vec<bonsai_idg::WsNodeId> = Vec::new();
    // Bare container seeds (`args`) also address their projections
    // (`args.q`) — same expansion the security scheduler applies, so
    // the graph built here propagates exactly what the scheduling cut
    // proved reachable.
    let seed_names = field_sensitive_rule_seed_names(seeds);
    if let Some(anchor) = source_anchor {
        let anchor_nodes = idg.source_seed_nodes_at_span(source_func, anchor);
        let anchor_has_call_return = anchor_nodes.iter().any(|node| {
            idg.resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::CallRet)
        });
        if !anchor_has_call_return && !seed_names.is_empty() {
            // Keep the source rule anchored to the exact AST fact. A matcher
            // may report both a projected value and its structural carrier
            // (`envelope.user`, `envelope`); globally looking up the carrier
            // would seed every sibling field in the literal. Prefer anchor
            // nodes whose rendered storage name matches the most-specific
            // seed pattern, and only use global name lookup when the anchor
            // exposes no name-bearing node at all.
            let anchored_named_nodes = anchor_nodes
                .iter()
                .copied()
                .filter(|node| {
                    idg.resolve_point(*node)
                        .is_some_and(|point| rule_seed_name_matches(&seed_names, &point.name))
                })
                .collect::<Vec<_>>();
            if !anchored_named_nodes.is_empty() {
                seed_nodes.extend(anchored_named_nodes);
            } else {
                let mut named_nodes = idg.read_or_write_nodes_for_names(source_func, &seed_names);
                // A read-kind source whose matched name is a parameter
                // taints from the parameter binding too — parity with the
                // security scheduler's seed builder.
                named_nodes.extend(idg.param_nodes_for_names(source_func, &seed_names, global));
                if named_nodes.is_empty() {
                    seed_nodes.extend(anchor_nodes);
                } else {
                    seed_nodes.extend(named_nodes);
                }
            }
        } else {
            seed_nodes.extend(anchor_nodes);
        }
    }
    if !output_arg_names.is_empty() && source_anchor.is_none() {
        let output_seed_names = bonsai_idg::expand_bare_seed_names_with_descendants(output_arg_names.iter());
        seed_nodes.extend(idg.read_or_write_nodes_for_names(source_func, &output_seed_names));
    } else if !output_arg_names.is_empty() {
        seed_nodes.extend(output_arg_read_seed_nodes(source_func, output_arg_names, idg));
    }
    if seed_nodes.is_empty() {
        if seed_names.is_empty() {
            if source_anchor.is_none() {
                seed_nodes.extend(idg.param_nodes_of(source_func));
            }
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

/// Rule matchers often surface both a projected value and its carrier token
/// from the same AST expression (`obj.field`, `obj`). The carrier is syntax,
/// not an independent whole-object source. Drop that bare base when a more
/// specific projection is present, then apply descendant expansion only to
/// the remaining genuinely bare values.
fn field_sensitive_rule_seed_names(seeds: &TokenSet) -> Vec<String> {
    let mut raw = seeds
        .iter()
        .map(|seed| seed.trim())
        .filter(|seed| !seed.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    raw.sort();
    raw.dedup();
    let projected_bases = raw
        .iter()
        .filter_map(|seed| {
            let seed = seed.strip_suffix(".*").unwrap_or(seed);
            seed.split_once('.').map(|(base, _)| base.to_string())
        })
        .collect::<AHashSet<_>>();
    raw.retain(|seed| {
        if let Some(wildcard_base) = seed.strip_suffix(".*") {
            // `envelope.*` is the same structural carrier as `envelope` and
            // must not widen an exact `envelope.user` source. A wildcard on
            // an already-projected place (`msg.sender.*`) remains meaningful.
            wildcard_base.contains('.') || !projected_bases.contains(wildcard_base)
        } else {
            seed.contains('.') || !projected_bases.contains(seed)
        }
    });
    bonsai_idg::expand_bare_seed_names_with_descendants(raw.iter())
}

fn rule_seed_name_matches(seed_names: &[String], point_name: &str) -> bool {
    let point_name = point_name.trim();
    !point_name.is_empty()
        && seed_names.iter().any(|pattern| {
            let pattern = pattern.trim();
            if let Some(base) = pattern.strip_suffix(".*") {
                point_name == base
                    || point_name
                        .strip_prefix(base)
                        .is_some_and(|tail| tail.starts_with('.') || tail.starts_with('['))
            } else {
                point_name == pattern
            }
        })
}

/// Seed-node composer for the LEGACY token-name taint API
/// (`interprocedural_taint` / `call_site_receives_taint`), which seeds by
/// bare identifier tokens with the compatibility API's matching semantics:
///
/// 1. **Sigil tolerance** — a seed `args` must also address the sigil'd
///    bindings Perl/PHP produce (`$args`, `@args`, `%args`). The IDG's
///    string-pool lookup is exact, so the variants are expanded here.
/// 2. **Call-name seeds** — a seed like `ReadLine` names a SOURCE CALL,
///    not a variable. It seeds the `CallRet` node of every call in the
///    entry function whose (qualified-tail) name matches, so
///    `var raw = Console.ReadLine()` taints `raw` through the
///    `CallRet → Write` edge, and the CallRet lands in
///    `source_call_spans` so `sink(source(x))` isn't pruned as clean.
///
/// This is the compatibility-policy branch of the canonical seed composer;
/// security selects the rule-match policy instead.
fn legacy_token_seed_nodes(
    entry_func: FuncId,
    seeds: &TokenSet,
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    let mut names: Vec<String> = Vec::new();
    for seed in seeds.iter() {
        let seed = seed.trim();
        if seed.is_empty() {
            continue;
        }
        names.push(seed.to_string());
        let already_sigiled = seed
            .chars()
            .next()
            .is_some_and(|first| bonsai_common::IDENTIFIER_SIGILS.contains(&first));
        if !already_sigiled {
            names.extend(
                bonsai_common::IDENTIFIER_SIGILS
                    .iter()
                    .map(|sigil| format!("{sigil}{seed}")),
            );
        }
    }
    // The legacy API's token contract distinguishes scalar value taint
    // (`args`) from descendant-container taint (`args.*`).  Do not use the
    // security seed expansion here: promoting every bare token to `.*`
    // makes passing a tainted object also taint unrelated fields in the
    // callee.  Sigil variants are still included above.
    let expanded = names;
    // Seed the PARAMETER binding nodes for the seed names — the entry
    // value whose forward closure is exactly "what the tainted entry
    // value reaches." Deliberately NOT `read_or_write_nodes_for_names`:
    // seeding every write named `cmd` would seed a post-`cmd = "const"`
    // clean-overwrite write (defeating SSA), and seeding every read would
    // taint the sink's own `sink(cmd)` read directly. The param node's
    // closure naturally excludes an independent later overwrite.
    let param_nodes = idg.param_nodes_for_names(entry_func, &expanded, global);
    let resolved_param_names: AHashSet<String> = param_nodes
        .iter()
        .filter_map(|node| idg.resolve_point(*node))
        .filter(|point| point.kind == bonsai_idg::PointKind::Param && !point.name.is_empty())
        .map(|point| point.name)
        .collect();
    let mut nodes = param_nodes;
    // Explicit wildcard seeds (`args.*`) address unshadowed projected
    // READS. Seed reads only: projected writes may be later clean
    // overwrites and must never be resurrected as sources.
    nodes.extend(legacy_descendant_read_seed_nodes(entry_func, &expanded, idg));
    if let Some(decl) = global.decl_of(SymbolId::new(entry_func.raw())) {
        // Locals that are the entry-most definition of a seed name (e.g.
        // Perl `my ($args) = @_;` when the adapter models the param as a
        // local write rather than a `Place::Param`) still need seeding.
        // Seed the FIRST write of every requested name that did not resolve
        // to a formal parameter. This is deliberately per-name rather than
        // an all-or-nothing fallback: seed-free consumers request params and
        // independent local origins together. A matching parameter must not
        // seed a later same-name overwrite, while an unrelated local still
        // needs its entry-most definition.
        let local_seed_names: Vec<String> = expanded
            .iter()
            .filter(|name| !resolved_param_names.contains(name.as_str()))
            .cloned()
            .collect();
        nodes.extend(first_write_nodes_for_names(
            entry_func,
            &local_seed_names,
            &decl.flow_events,
            idg,
        ));
        // Source-call-name seeds (`ReadLine`) taint the call's return.
        let mut call_spans: Vec<Span> = Vec::new();
        collect_seed_matching_call_spans(&decl.flow_events, seeds, &mut call_spans);
        for span in call_spans {
            nodes.extend(idg.call_ret_node_at_site(entry_func, span));
        }
        // Legacy callers sometimes describe an output-buffer source with a
        // pair of tokens (`fgets` + `buf`) instead of declarative
        // `SourceOutputArgs`. When both the call name and one of its
        // addressable arguments are explicitly seeded, start the closure at
        // that argument's read nodes as well. The two-token requirement keeps
        // an ordinary source-call seed (`request.args.get`) from incorrectly
        // treating string/default inputs as output carriers.
        let mut source_output_names = Vec::new();
        collect_seed_matching_output_arg_names(&decl.flow_events, seeds, &mut source_output_names);
        nodes.extend(output_arg_read_seed_nodes(entry_func, &source_output_names, idg));
    }
    nodes.sort();
    nodes.dedup();
    nodes
}

fn legacy_descendant_read_seed_nodes(
    entry_func: FuncId,
    expanded_names: &[String],
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    let descendant_names = expanded_names
        .iter()
        .filter(|name| name.trim().ends_with(".*"))
        .cloned()
        .collect::<Vec<_>>();
    if descendant_names.is_empty() {
        return Vec::new();
    }
    idg.read_or_write_nodes_for_names(entry_func, &descendant_names)
        .into_iter()
        .filter(|node| {
            idg.resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::Read)
        })
        .collect()
}

/// Seed nodes for the FIRST write of each seed name in `func`, in source
/// order. Used when a seed name has no `Place::Param` node (adapters that
/// model a parameter as an initial local write). Only the earliest write
/// of a name is seeded — later writes are reassignments a token seed must
/// not resurrect, preserving clean-overwrite semantics.
fn first_write_nodes_for_names(
    func: FuncId,
    seed_names: &[String],
    events: &[FlowEvent],
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    let mut first_write_span: ahash::AHashMap<String, Span> = ahash::AHashMap::default();
    collect_first_write_spans(events, seed_names, &mut first_write_span);
    let mut nodes = Vec::new();
    for span in first_write_span.values() {
        nodes.extend(idg.write_node_at_span(func, *span));
    }
    nodes
}

fn collect_first_write_spans(
    events: &[FlowEvent],
    seed_names: &[String],
    out: &mut ahash::AHashMap<String, Span>,
) {
    for event in events {
        match event {
            FlowEvent::Assign { target, span, .. } => {
                let target = target.trim();
                if seed_names.iter().any(|name| name == target) && !out.contains_key(target) {
                    out.insert(target.to_string(), *span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_first_write_spans(then_events, seed_names, out);
                collect_first_write_spans(else_events, seed_names, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_first_write_spans(body, seed_names, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_first_write_spans(body, seed_names, out);
                collect_first_write_spans(catch_events, seed_names, out);
                collect_first_write_spans(finally_events, seed_names, out);
            }
            _ => {}
        }
    }
}

/// Recursively collect the spans of calls whose name matches one of the
/// seed tokens, using the legacy engine's qualified-tail match:
/// `ReadLine` matches `Console.ReadLine`, `question` matches
/// `rl.question`, `get` matches `maps:get`.
fn collect_seed_matching_call_spans(events: &[FlowEvent], seeds: &TokenSet, out: &mut Vec<Span>) {
    let name_matches = |name: &str| -> bool {
        seeds.iter().any(|seed| {
            let seed = seed.trim();
            !seed.is_empty()
                && (name == seed
                    || (name.ends_with(seed) && name[..name.len() - seed.len()].ends_with(['.', ':', '>'])))
        })
    };
    for event in events {
        match event {
            FlowEvent::Call { span, name, .. } => {
                if name_matches(name) {
                    out.push(*span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_seed_matching_call_spans(then_events, seeds, out);
                collect_seed_matching_call_spans(else_events, seeds, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_seed_matching_call_spans(body, seeds, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_seed_matching_call_spans(body, seeds, out);
                collect_seed_matching_call_spans(catch_events, seeds, out);
                collect_seed_matching_call_spans(finally_events, seeds, out);
            }
            _ => {}
        }
    }
}

fn collect_seed_matching_output_arg_names(events: &[FlowEvent], seeds: &TokenSet, out: &mut Vec<String>) {
    let name_matches = |name: &str| -> bool {
        seeds.iter().any(|seed| {
            let seed = seed.trim();
            !seed.is_empty()
                && (name == seed
                    || (name.ends_with(seed) && name[..name.len() - seed.len()].ends_with(['.', ':', '>'])))
        })
    };
    let value_matches = |value: &str| -> bool {
        let value = normalise_qualified_text(value);
        let value = value.trim().trim_start_matches(['$', '@', '%', '&', '*']).trim();
        !value.is_empty()
            && seeds.iter().any(|seed| {
                let seed = normalise_qualified_text(seed);
                let seed = seed.trim().trim_start_matches(['$', '@', '%', '&', '*']).trim();
                !seed.ends_with(".*") && seed == value
            })
    };
    for event in events {
        match event {
            FlowEvent::Call { name, args, .. } if name_matches(name) => {
                for arg in args {
                    let Some(candidate) = arg.place.as_deref().map(str::trim) else {
                        continue;
                    };
                    if !candidate.is_empty()
                        && !candidate.starts_with(['\'', '"'])
                        && value_matches(candidate)
                        && !out.iter().any(|existing| existing == candidate)
                    {
                        out.push(candidate.to_string());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_seed_matching_output_arg_names(then_events, seeds, out);
                collect_seed_matching_output_arg_names(else_events, seeds, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_seed_matching_output_arg_names(body, seeds, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_seed_matching_output_arg_names(body, seeds, out);
                collect_seed_matching_output_arg_names(catch_events, seeds, out);
                collect_seed_matching_output_arg_names(finally_events, seeds, out);
            }
            _ => {}
        }
    }
}

fn output_arg_read_seed_nodes(
    func: FuncId,
    output_arg_names: &[String],
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    let output_seed_names = bonsai_idg::expand_bare_seed_names_with_descendants(output_arg_names.iter());
    idg.read_or_write_nodes_for_names(func, &output_seed_names)
        .into_iter()
        .filter(|node| {
            idg.resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::Read)
        })
        .collect()
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
    let mut seed_nodes = compose_idg_seed_nodes(
        IdgSeedRequest::rule_match(source_func, seeds, source_anchor, output_arg_names),
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
    entry_taint_call_records_from_idg_with_target_filters_and_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        &[],
        &[],
        None,
        None,
        max_precision,
        db,
        idg,
        false,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)] // Public IDG query surface carries seed, target, precision, db, and service context.
pub fn entry_taint_call_records_from_idg_with_target_filters_and_max_precision(
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
    call_result_passthroughs_materialized: bool,
) -> EntryTaintGraph {
    entry_taint_call_records_from_idg_with_target_filters_and_max_precision_and_caches(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        call_result_passthroughs,
        output_arg_flows,
        target_funcs,
        lineage_funcs,
        max_precision,
        db,
        idg,
        call_result_passthroughs_materialized,
        None,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn entry_taint_call_records_from_idg_with_target_filters_and_max_precision_and_caches(
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
    call_result_passthroughs_materialized: bool,
    caches: Option<&crate::inter::InterTaintCaches>,
) -> EntryTaintGraph {
    let global = db.global_index();
    let mut graph = EntryTaintGraph::default();

    let mut seed_nodes = compose_idg_seed_nodes(
        IdgSeedRequest::rule_match(source_func, seeds, source_anchor, output_arg_names),
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

    let seed_count_before_transfers = seed_nodes.len();
    apply_configured_transfer_fixpoint(
        &mut seed_nodes,
        receiver_state_propagations,
        if call_result_passthroughs_materialized {
            &[]
        } else {
            call_result_passthroughs
        },
        output_arg_flows,
        global.as_ref(),
        idg,
        max_precision,
        lineage_funcs,
    );
    let transfers_added_seeds = seed_nodes.len() != seed_count_before_transfers;
    let closure_evidence = if transfers_added_seeds {
        // Query-time declarative transfers add a derived output node as a
        // seed instead of mutating the immutable IDG. A target cut starting
        // at that derived node would omit the source-to-transfer prefix and
        // sever call-record lineage. Materialize the complete resolver-
        // derived function corridor whenever a transfer fired; it is still
        // scoped to `lineage_funcs`, and every retained edge is followed to
        // the exact precision fixpoint.
        closure_evidence_with_targets(&seed_nodes, idg, max_precision, None, lineage_funcs)
    } else if let Some(targets) = target_funcs {
        closure_evidence_with_targets(&seed_nodes, idg, max_precision, None, Some(targets))
    } else {
        closure_evidence_with_targets(&seed_nodes, idg, max_precision, None, None)
    };
    let bonsai_idg::IdgClosureEvidence {
        nodes: closure_nodes,
        symbolic_cross_calls,
    } = closure_evidence;
    let cross_calls = {
        let mut edges = idg.cross_call_edges_in_reachable_nodes_filtered_with_max_precision(
            &closure_nodes,
            max_precision,
            lineage_funcs,
        );
        edges.extend(symbolic_cross_calls.into_iter().filter(|edge| {
            lineage_funcs.is_none_or(|funcs| funcs.contains(&edge.caller) && funcs.contains(&edge.callee))
        }));
        // Allocation-insensitive projected heap state is valid closure
        // evidence, but it does not prove that one function calls another.
        // The closure above has already consumed those links to fixpoint;
        // keep them out of the compatibility call-record surface so callers
        // never receive a fabricated call edge.
        edges.retain(|edge| edge.relation.is_renderable_call());
        if bonsai_diagnostics::debug::is_enabled("idg-closure") {
            let all_edges =
                idg.cross_call_edges_in_reachable_nodes_with_max_precision(&closure_nodes, max_precision);
            bonsai_diagnostics::debug_log!(
                "idg-closure",
                "target cut nodes={} cross_calls={} unfiltered_cross_calls={} lineage_filter_funcs={}",
                closure_nodes.len(),
                edges.len(),
                all_edges.len(),
                lineage_funcs.map_or(0, |funcs| funcs.len())
            );
            let node_detail = closure_nodes
                .iter()
                .filter_map(|node| {
                    let point = idg.resolve_point(*node)?;
                    Some(format!(
                        "ws#{}=func{}:{:?}:{}@{}..{}",
                        node.0,
                        point.func.raw(),
                        point.kind,
                        point.name,
                        point.span.start,
                        point.span.end
                    ))
                })
                .collect::<Vec<_>>();
            bonsai_diagnostics::debug_log!("idg-closure", "node target cut detail={:?}", node_detail);
        }
        let call_order = call_preorder_from_source(source_func, &edges);
        edges.sort_by_key(|ce| {
            (
                call_order.get(&ce.caller).copied().unwrap_or(u32::MAX),
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
    let mut call_summary_cache = caches.map_or_else(CallEventSummaryCache::default, |caches| {
        CallEventSummaryCache::shared(caches.attribution_caches())
    });
    for ce in &cross_calls {
        let trace_id = next_trace_id;
        next_trace_id = next_trace_id.saturating_add(1);
        let parent_trace_id = first_inflow.get(&ce.caller).copied();
        let is_synthetic_return = ce.relation == bonsai_idg::CrossCallRelation::Return;
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
            edge_kind: ce.call_kind,
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
        &[],
        false,
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
    extra_seed_nodes: &[bonsai_idg::WsNodeId],
    call_result_passthroughs_materialized: bool,
) -> EntryTaintGraph {
    entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision_and_caches(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        receiver_state_propagations,
        call_result_passthroughs,
        output_arg_flows,
        target_nodes,
        target_funcs,
        lineage_funcs,
        max_precision,
        db,
        idg,
        extra_seed_nodes,
        call_result_passthroughs_materialized,
        None,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision_and_caches(
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
    extra_seed_nodes: &[bonsai_idg::WsNodeId],
    call_result_passthroughs_materialized: bool,
    caches: Option<&crate::inter::InterTaintCaches>,
) -> EntryTaintGraph {
    let global = db.global_index();
    let mut graph = EntryTaintGraph::default();

    // Compose the seed set. When the caller supplies `extra_seed_nodes`
    // (the legacy token-seeding API, which resolves sigil'd / call-name /
    // clean-overwrite-safe seeds ITSELF), use exactly those — mixing in
    // the rule-match policy's name-based read/write seeding would
    // re-add post-overwrite writes and the sink's own read, defeating SSA.
    // The security path passes an empty slice, so it keeps the
    // span-anchored rule-match seeding untouched.
    let mut seed_nodes = if extra_seed_nodes.is_empty() {
        compose_idg_seed_nodes(
            IdgSeedRequest::rule_match(source_func, seeds, source_anchor, output_arg_names),
            global.as_ref(),
            idg,
        )
    } else {
        extra_seed_nodes.to_vec()
    };
    seed_nodes.sort();
    seed_nodes.dedup();
    if seed_nodes.is_empty() {
        return graph;
    }

    // Call sites whose RETURN is a tainted seed — i.e. the source is a
    // call (`getenv(...)`, `input(...)`, `request.getParameter(...)`).
    // A nested call at one of these spans IS the source, so its return
    // is intrinsically tainted regardless of its own arguments. Without
    // this, `sink(source(arg))` (the single most common vuln shape) is
    // dropped: `tainted_arg_is_clean_nested_call_return` presumes an
    // unresolved nested call with args returns clean, and wrongly
    // filters the source's return out of the sink's tainted args.
    let source_call_spans: ahash::AHashSet<bonsai_common::Span> = seed_nodes
        .iter()
        .filter_map(|node| {
            let point = idg.resolve_point(*node)?;
            (point.kind == bonsai_idg::PointKind::CallRet).then_some(point.span)
        })
        .collect();

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

    let seed_count_before_transfers = seed_nodes.len();
    apply_configured_transfer_fixpoint(
        &mut seed_nodes,
        receiver_state_propagations,
        if call_result_passthroughs_materialized {
            &[]
        } else {
            call_result_passthroughs
        },
        output_arg_flows,
        global.as_ref(),
        idg,
        max_precision,
        lineage_funcs,
    );
    let transfers_added_seeds = seed_nodes.len() != seed_count_before_transfers;
    let target_nodes = target_nodes.filter(|nodes| !nodes.is_empty());
    let emission_target_funcs = if target_nodes.is_some() {
        None
    } else {
        target_funcs
    };
    let closure_evidence = if transfers_added_seeds {
        // See the call-record-only variant above. Derived transfer seeds must
        // retain the source prefix so terminal calls receive an evidenced
        // parent trace instead of an orphaned sink-local tail.
        closure_evidence_with_targets(&seed_nodes, idg, max_precision, None, lineage_funcs)
    } else if let Some(target_nodes) = target_nodes {
        closure_evidence_with_targets(&seed_nodes, idg, max_precision, Some(target_nodes), target_funcs)
    } else if let Some(targets) = target_funcs {
        closure_evidence_with_targets(&seed_nodes, idg, max_precision, None, Some(targets))
    } else {
        closure_evidence_with_targets(&seed_nodes, idg, max_precision, None, None)
    };
    let bonsai_idg::IdgClosureEvidence {
        nodes: closure_nodes,
        symbolic_cross_calls,
    } = closure_evidence;
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
        edges.extend(symbolic_cross_calls.into_iter().filter(|edge| {
            lineage_funcs.is_none_or(|funcs| funcs.contains(&edge.caller) && funcs.contains(&edge.callee))
        }));
        // See the call-record-only path above. Field-state links are
        // compiler dataflow evidence, not source-level calls.
        edges.retain(|edge| edge.relation.is_renderable_call());
        if bonsai_diagnostics::debug::is_enabled("idg-closure") {
            let all_edges =
                idg.cross_call_edges_in_reachable_nodes_with_max_precision(&closure_nodes, max_precision);
            bonsai_diagnostics::debug_log!(
                "idg-closure",
                "node target cut nodes={} cross_calls={} unfiltered_cross_calls={} lineage_filter_funcs={}",
                closure_nodes.len(),
                edges.len(),
                all_edges.len(),
                lineage_funcs.map_or(0, |funcs| funcs.len())
            );
            let node_detail = closure_nodes
                .iter()
                .filter_map(|node| {
                    let point = idg.resolve_point(*node)?;
                    Some(format!(
                        "ws#{}=func{}:{:?}:{}@{}..{}",
                        node.0,
                        point.func.raw(),
                        point.kind,
                        point.name,
                        point.span.start,
                        point.span.end
                    ))
                })
                .collect::<Vec<_>>();
            bonsai_diagnostics::debug_log!("idg-closure", "node target cut exact detail={:?}", node_detail);
        }
        // Compiler callgraph pre-order keeps a caller's first evidenced
        // inflow ahead of its descendants without running another semantic
        // graph search.
        let call_order = call_preorder_from_source(source_func, &edges);
        edges.sort_by_key(|ce| {
            (
                call_order.get(&ce.caller).copied().unwrap_or(u32::MAX),
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
    let mut call_summary_cache = caches.map_or_else(CallEventSummaryCache::default, |caches| {
        CallEventSummaryCache::shared(caches.attribution_caches())
    });
    for ce in &cross_calls {
        let trace_id = next_trace_id;
        next_trace_id = next_trace_id.saturating_add(1);
        let parent_trace_id = first_inflow.get(&ce.caller).copied();
        // Synthetic `Return → CallRet` edges (sentinel
        // `arg_idx = u32::MAX`) flip the natural call orientation:
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
        let is_synthetic_return = ce.relation == bonsai_idg::CrossCallRelation::Return;
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
            edge_kind: ce.call_kind,
        });
    }

    // Tainted call sites in closure → tainted_calls.
    let tainted_args_by_site =
        idg.tainted_call_args_in_reachable_nodes_for_funcs(&closure_nodes, emission_target_funcs);
    let mut by_site: ahash::AHashMap<(FuncId, bonsai_common::Span), Vec<u32>> = ahash::AHashMap::new();
    for (caller, call_span, arg_idx) in &tainted_args_by_site {
        if emission_target_funcs.is_some_and(|targets| !targets.contains(caller)) {
            continue;
        }
        by_site.entry((*caller, *call_span)).or_default().push(*arg_idx);
    }
    promote_nested_tainted_call_args(&mut by_site, global.as_ref(), &mut call_summary_cache);

    let mut tainted_calls: Vec<crate::inter::TaintedCall> = Vec::new();
    let compiled_call_result_passthroughs = compile_call_result_passthroughs(call_result_passthroughs);
    let cross_call_transit_index = CrossCallTransitIndex::new(&cross_calls);
    let mut passthrough_callee_cache = CalleeNameCache::default();
    let mut tainted_names_by_caller: ahash::AHashMap<FuncId, ahash::AHashSet<String>> =
        ahash::AHashMap::new();
    let mut function_summary_cache: ahash::AHashMap<FuncId, crate::inter::FunctionSummary> =
        ahash::AHashMap::default();
    let mut sorted_sites: Vec<((FuncId, bonsai_common::Span), Vec<u32>)> = by_site.into_iter().collect();
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
                    call_span,
                    *idx,
                    &call_summary,
                    &cross_call_transit_index,
                    idg,
                    global.as_ref(),
                    &mut call_summary_cache,
                    &mut function_summary_cache,
                    &compiled_call_result_passthroughs,
                    &mut passthrough_callee_cache,
                    &source_call_spans,
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
            if emission_target_funcs.is_some_and(|targets| !targets.contains(&func)) {
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
            if emission_target_funcs.is_some_and(|targets| !targets.contains(&func)) {
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
    // All three fixpoints run inside ONE outer loop: receiver-state
    // propagation must re-run after a passthrough / output-arg flow grows
    // the seed set, otherwise taint that only exists post-passthrough
    // (`uri = URI.create(input); pb.command(uri); pb.start()`) never
    // triggers a `taint_receiver_from_args` propagation (`pb.start()`'s
    // tainted-receiver sink is missed). `apply_receiver_state_fixpoint`
    // has its own internal fixpoint and only ADDS unique seeds, so
    // re-running it is idempotent once nothing new appears.
    loop {
        let mut grew = false;
        if !receiver_state_propagations.is_empty() {
            let before = seed_nodes.len();
            apply_receiver_state_fixpoint(
                seed_nodes,
                receiver_state_propagations,
                global,
                idg,
                max_precision,
                func_filter,
            );
            grew |= seed_nodes.len() != before;
        }
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

/// Recompute a transfer fixpoint only inside the compiler-derived function
/// corridor when one is available. This keeps each iteration from walking
/// unrelated workspace branches while preserving the ordinary unrestricted
/// closure for callers that do not have a sound corridor.
fn closure_with_func_filter(
    seed_nodes: &[bonsai_idg::WsNodeId],
    idg: &bonsai_idg::IdgQueryService,
    max_precision: Option<Precision>,
    func_filter: Option<&AHashSet<FuncId>>,
) -> Vec<bonsai_idg::WsNodeId> {
    if let Some(funcs) = func_filter.filter(|funcs| !funcs.is_empty()) {
        idg.forward_target_func_cut_with_max_precision(seed_nodes, funcs, max_precision)
    } else {
        idg.forward_closure_with_max_precision(seed_nodes, max_precision)
    }
}

/// Run one provenance-preserving compiler closure and apply the same
/// target-presence contract as the IDG target-cut helpers. Target queries do
/// not truncate the closure: they retain the complete realizable path only
/// when at least one requested target is reached.
fn closure_evidence_with_targets(
    seed_nodes: &[bonsai_idg::WsNodeId],
    idg: &bonsai_idg::IdgQueryService,
    max_precision: Option<Precision>,
    target_nodes: Option<&[bonsai_idg::WsNodeId]>,
    target_funcs: Option<&AHashSet<FuncId>>,
) -> bonsai_idg::IdgClosureEvidence {
    let mut evidence = idg.forward_closure_evidence_with_max_precision(seed_nodes, max_precision);
    let target_nodes = target_nodes.filter(|nodes| !nodes.is_empty());
    let target_funcs = target_funcs.filter(|funcs| !funcs.is_empty());
    if target_nodes.is_none() && target_funcs.is_none() {
        return evidence;
    }
    let target_node_set: ahash::AHashSet<bonsai_idg::WsNodeId> =
        target_nodes.into_iter().flatten().copied().collect();
    let reached = evidence.nodes.iter().any(|node| {
        target_node_set.contains(node)
            || target_funcs
                .is_some_and(|funcs| idg.func_of_node(*node).is_some_and(|func| funcs.contains(&func)))
    });
    if !reached {
        evidence.nodes.clear();
        evidence.symbolic_cross_calls.clear();
    }
    evidence
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
        let closure = closure_with_func_filter(seed_nodes, idg, max_precision, func_filter);
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
    let mut passthroughs_by_arg: ahash::AHashMap<u32, Vec<usize>> = ahash::AHashMap::default();
    let mut receiver_passthroughs: Vec<usize> = Vec::new();
    for (idx, configured) in passthroughs.iter().enumerate() {
        if configured.passthrough.input_receiver {
            receiver_passthroughs.push(idx);
        }
        for &arg_idx in &configured.passthrough.input_arg_indices {
            if let Ok(arg_idx) = u32::try_from(arg_idx) {
                passthroughs_by_arg.entry(arg_idx).or_default().push(idx);
            }
        }
    }
    let mut seeded: ahash::AHashSet<bonsai_idg::WsNodeId> = seed_nodes.iter().copied().collect();
    let mut applied: ahash::AHashSet<(FuncId, bonsai_common::Span, u32, String)> = ahash::AHashSet::default();
    let mut callee_name_cache = CalleeNameCache::default();
    let mut any_grew = false;
    loop {
        let closure = closure_with_func_filter(seed_nodes, idg, max_precision, func_filter);
        let tainted_args = idg.tainted_call_args_in_reachable_nodes_for_funcs(&closure, func_filter);
        let descendant_inputs = DescendantClosureIndex::from_closure(&closure, idg, func_filter);
        let mut call_summary_cache = CallEventSummaryCache::default();
        let mut grew = false;
        for (caller, call_span, arg_idx) in tainted_args {
            let Some(summary) = cached_call_event_summary(caller, call_span, global, &mut call_summary_cache)
            else {
                continue;
            };
            let candidate_indices = if arg_idx == u32::MAX {
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
                if !configured_receiver_type_matches(
                    passthrough.receiver_type.as_deref(),
                    &summary.receiver_types,
                ) {
                    continue;
                }
                let key = (caller, call_span, arg_idx, passthrough.callee.clone());
                if !applied.insert(key) {
                    continue;
                }
                if seed_call_result_passthrough_outputs(
                    seed_nodes,
                    &mut seeded,
                    idg,
                    caller,
                    call_span,
                    arg_idx == u32::MAX && passthrough.input_receiver,
                ) {
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
                    if !configured_receiver_type_matches(
                        passthrough.receiver_type.as_deref(),
                        &summary.receiver_types,
                    ) {
                        continue;
                    }
                    if passthrough.input_receiver
                        && call_receiver_has_descendant_input(summary, descendant_bases)
                    {
                        let key = (*caller, *call_span, u32::MAX, passthrough.callee.clone());
                        if applied.insert(key)
                            && seed_call_result_passthrough_outputs(
                                seed_nodes,
                                &mut seeded,
                                idg,
                                *caller,
                                *call_span,
                                true,
                            )
                        {
                            grew = true;
                            any_grew = true;
                        }
                    }
                    for &arg_idx in &passthrough.input_arg_indices {
                        let Ok(arg_idx_u32) = u32::try_from(arg_idx) else {
                            continue;
                        };
                        if !call_arg_has_descendant_input(summary, arg_idx, descendant_bases) {
                            continue;
                        }
                        let key = (*caller, *call_span, arg_idx_u32, passthrough.callee.clone());
                        if !applied.insert(key) {
                            continue;
                        }
                        if seed_call_result_passthrough_outputs(
                            seed_nodes,
                            &mut seeded,
                            idg,
                            *caller,
                            *call_span,
                            true,
                        ) {
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

fn seed_call_result_passthrough_outputs(
    seed_nodes: &mut Vec<bonsai_idg::WsNodeId>,
    seeded: &mut ahash::AHashSet<bonsai_idg::WsNodeId>,
    idg: &bonsai_idg::IdgQueryService,
    caller: FuncId,
    call_span: bonsai_common::Span,
    seed_descendant_targets: bool,
) -> bool {
    let mut grew = false;
    if let Some(ret_node) = idg.call_ret_node_at_site(caller, call_span) {
        if seeded.insert(ret_node) {
            seed_nodes.push(ret_node);
            grew = true;
        }
    }
    if seed_descendant_targets {
        for target in idg.call_ret_assignment_targets_at_site(caller, call_span) {
            let descendant_seed = format!("{}.*", target.name);
            for node in idg.read_or_write_nodes_for_names(caller, &[descendant_seed]) {
                if seeded.insert(node) {
                    seed_nodes.push(node);
                    grew = true;
                }
            }
        }
    }
    grew
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
        for (func, name) in idg.read_write_storage_names_in_reachable_nodes_for_funcs(closure, func_filter) {
            for base in descendant_storage_bases(&name) {
                out.bases_by_func.entry(func).or_default().insert(base);
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
        || summary.args_source_names.get(arg_idx).is_some_and(|sources| {
            sources
                .iter()
                .any(|source| input_text_has_descendant_base(source, descendant_bases))
        })
}

fn input_text_has_descendant_base(text: &str, descendant_bases: &ahash::AHashSet<String>) -> bool {
    input_storage_bases(text)
        .into_iter()
        .any(|base| descendant_bases.contains(&base))
}

fn input_storage_bases(text: &str) -> Vec<String> {
    storage_base_candidate(text).into_iter().collect()
}

fn storage_base_candidate(text: &str) -> Option<String> {
    let normalized = normalize_storage_text(text);
    if normalized.is_empty() {
        return None;
    }
    let base = normalized.split('.').next().unwrap_or("").trim();
    if is_bare_identifier(base) {
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
    let mut flows_by_arg: ahash::AHashMap<u32, Vec<usize>> = ahash::AHashMap::default();
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
            if let Ok(arg_idx) = u32::try_from(arg_idx) {
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
        let closure = closure_with_func_filter(seed_nodes, idg, max_precision, func_filter);
        let tainted_args = idg.tainted_call_args_in_reachable_nodes_for_funcs(&closure, func_filter);
        let mut call_summary_cache = CallEventSummaryCache::default();
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
                let mut output_nodes = idg.nodes_for_name_after_span(caller, &output, call_span);
                output_nodes.extend(output_arg_read_seed_nodes(caller, &[output.clone()], idg));
                output_nodes.sort();
                output_nodes.dedup();
                for node in output_nodes {
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
                let mut output_nodes = idg.nodes_for_name_after_span(caller, &output, call_span);
                output_nodes.extend(output_arg_read_seed_nodes(caller, &[output.clone()], idg));
                output_nodes.sort();
                output_nodes.dedup();
                for node in output_nodes {
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

fn configured_receiver_type_matches(expected: Option<&str>, observed: &[String]) -> bool {
    let Some(expected) = expected.map(str::trim).filter(|expected| !expected.is_empty()) else {
        return true;
    };
    let expected_tail = short_member_tail(expected);
    observed.iter().any(|actual| {
        let actual = actual.trim().trim_start_matches(['&', '*', '?', '!']);
        actual == expected || short_member_tail(actual) == expected_tail
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

/// Deterministic compiler callgraph pre-order rooted at `source_func`.
/// Callers absent from the returned map sort after the rooted component.
fn call_preorder_from_source(
    source_func: FuncId,
    edges: &[bonsai_idg::CrossCallEdge],
) -> ahash::AHashMap<FuncId, u32> {
    let mut adj: ahash::AHashMap<FuncId, Vec<FuncId>> = ahash::AHashMap::default();
    for ce in edges {
        adj.entry(ce.caller).or_default().push(ce.callee);
    }
    for callees in adj.values_mut() {
        callees.sort_unstable_by_key(|func| func.raw());
        callees.dedup();
    }
    let mut order = ahash::AHashMap::default();
    let mut pending = vec![source_func];
    while let Some(func) = pending.pop() {
        if order.contains_key(&func) {
            continue;
        }
        let next = u32::try_from(order.len()).unwrap_or(u32::MAX);
        order.insert(func, next);
        if let Some(callees) = adj.get(&func) {
            pending.extend(callees.iter().rev().copied());
        }
    }
    order
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
    call_kind: bonsai_lang_api::CallKind,
    args_value_text: Vec<String>,
    args_span: Vec<bonsai_common::Span>,
    args_place: Vec<Option<String>>,
    args_source_names: Vec<Vec<String>>,
    receiver: Option<String>,
    receiver_types: Vec<String>,
}

#[derive(Debug)]
struct FunctionCallEventSummaries {
    by_span: ahash::AHashMap<bonsai_common::Span, CallEventSummary>,
    /// Call spans sorted by `(file, start, reverse(end))`. This turns nested
    /// syntax lookup into a binary-search range query instead of a full scan
    /// of every call in a generated function for every tainted argument.
    spans: Vec<bonsai_common::Span>,
}

/// Immutable AST call summaries shared by every source query in one analysis
/// lifecycle. Security can issue thousands of distinct source closures over
/// the same functions; rebuilding and then dropping identical string-rich
/// summaries per source is pure repeated front-end work.
#[derive(Debug, Default)]
pub(crate) struct IdgAttributionCaches {
    call_events: parking_lot::RwLock<ahash::AHashMap<FuncId, std::sync::Arc<FunctionCallEventSummaries>>>,
}

impl IdgAttributionCaches {
    pub(crate) fn clear(&self) {
        self.call_events.write().clear();
    }
}

struct CallEventSummaryCache<'a> {
    by_func: ahash::AHashMap<FuncId, std::sync::Arc<FunctionCallEventSummaries>>,
    shared: Option<&'a IdgAttributionCaches>,
}

impl Default for CallEventSummaryCache<'_> {
    fn default() -> Self {
        Self {
            by_func: ahash::AHashMap::default(),
            shared: None,
        }
    }
}

impl<'a> CallEventSummaryCache<'a> {
    fn shared(shared: &'a IdgAttributionCaches) -> Self {
        Self {
            by_func: ahash::AHashMap::default(),
            shared: Some(shared),
        }
    }
}

impl CallEventSummary {
    fn output_arg_target(&self, index: usize) -> Option<String> {
        self.args_place
            .get(index)
            .and_then(|place| place.as_deref())
            .map(normalise_output_arg_target_text)
            .filter(|place| !place.is_empty())
            .or_else(|| {
                let text = normalise_output_arg_target_text(self.args_value_text.get(index)?);
                is_addressable_arg_target(&text).then_some(text)
            })
    }
}

fn normalise_output_arg_target_text(text: &str) -> String {
    normalise_qualified_text(text)
        .trim_start_matches(bonsai_common::REFERENCE_SIGILS)
        .trim()
        .to_string()
}

fn is_addressable_arg_target(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty()
        && !text.starts_with('.')
        && !text.ends_with('.')
        && text
            .chars()
            .all(|ch| ch == '.' || ch == '_' || ch.is_ascii_alphanumeric())
}

fn tainted_args_for_cross_call_edge(
    edge: &bonsai_idg::CrossCallEdge,
    callee_decl: Option<&bonsai_lang_api::Decl>,
    call_summary: Option<&CallEventSummary>,
) -> Vec<crate::inter::TaintedArg> {
    if edge.arg_idx == u32::MAX {
        if matches!(
            edge.relation,
            bonsai_idg::CrossCallRelation::Argument | bonsai_idg::CrossCallRelation::Capture
        ) {
            if let Some((summary, receiver)) = call_summary
                .and_then(|summary| summary.receiver.as_deref().map(|receiver| (summary, receiver)))
                .map(|(summary, receiver)| (summary, receiver.trim()))
                .filter(|(_, receiver)| !receiver.is_empty())
            {
                let (index, param_name) = if summary.args_value_text.is_empty() {
                    (usize::MAX, SYNTHETIC_RECEIVER_PARAM_NAME.to_string())
                } else if edge.param_idx != u32::MAX {
                    (
                        edge.param_idx as usize,
                        callee_decl
                            .and_then(|decl| decl.params.get(edge.param_idx as usize).cloned())
                            .unwrap_or_default(),
                    )
                } else {
                    // A sentinel with explicit arguments but no formal slot
                    // is provenance-only. Do not relabel the receiver as the
                    // tainted actual when the compiler could not prove that.
                    return Vec::new();
                };
                return vec![crate::inter::TaintedArg {
                    index,
                    value_text: receiver.to_string(),
                    param_name,
                }];
            }
        }
        if matches!(
            edge.relation,
            bonsai_idg::CrossCallRelation::Callback | bonsai_idg::CrossCallRelation::Capture
        ) && edge.param_idx != u32::MAX
        {
            let param_name = callee_decl
                .and_then(|decl| decl.params.get(edge.param_idx as usize).cloned())
                .unwrap_or_default();
            let value_text = if param_name.is_empty() {
                format!("param#{}", edge.param_idx)
            } else {
                param_name.clone()
            };
            return vec![crate::inter::TaintedArg {
                index: edge.param_idx as usize,
                value_text,
                param_name,
            }];
        }
        return Vec::new();
    }
    let value_text = call_summary
        .and_then(|summary| summary.args_value_text.get(edge.arg_idx as usize).cloned())
        .unwrap_or_default();
    let param_name = if edge.param_idx == u32::MAX {
        String::new()
    } else {
        callee_decl
            .and_then(|decl| decl.params.get(edge.param_idx as usize).cloned())
            .unwrap_or_default()
    };
    // `TaintedArg.index` is the call-site argument slot. Keep the IDG edge's
    // `arg_idx`; `param_idx` can differ for methods with implicit receivers.
    vec![crate::inter::TaintedArg {
        index: edge.arg_idx as usize,
        value_text,
        param_name,
    }]
}

fn promote_nested_tainted_call_args(
    by_site: &mut ahash::AHashMap<(FuncId, bonsai_common::Span), Vec<u32>>,
    global: &GlobalIndex,
    call_summary_cache: &mut CallEventSummaryCache<'_>,
) {
    let seeds = by_site
        .iter()
        .map(|((caller, span), args)| (*caller, *span, args.clone()))
        .collect::<Vec<_>>();
    for (caller, nested_span, nested_arg_indices) in seeds {
        let Some(nested_summary) =
            cached_call_event_summary(caller, nested_span, global, call_summary_cache).cloned()
        else {
            continue;
        };
        let tainted_values = nested_arg_indices
            .iter()
            .filter_map(|idx| nested_summary.args_value_text.get(*idx as usize))
            .cloned()
            .collect::<Vec<_>>();
        if tainted_values.is_empty() {
            continue;
        }
        let Some(summaries) = cached_call_event_summaries_for_func(caller, global, call_summary_cache) else {
            continue;
        };
        for (outer_span, outer_summary) in summaries {
            if *outer_span == nested_span {
                continue;
            }
            for (outer_idx, outer_arg_span) in outer_summary.args_span.iter().enumerate() {
                if !span_contains_or_equals(*outer_arg_span, nested_span) {
                    continue;
                }
                let Some(outer_value) = outer_summary.args_value_text.get(outer_idx) else {
                    continue;
                };
                if !tainted_values
                    .iter()
                    .any(|tainted| expression_mentions_tainted_value(outer_value, tainted))
                {
                    continue;
                }
                let Ok(outer_idx) = u32::try_from(outer_idx) else {
                    continue;
                };
                let promoted = by_site.entry((caller, *outer_span)).or_default();
                if !promoted.contains(&outer_idx) {
                    promoted.push(outer_idx);
                }
            }
        }
    }
}

fn expression_mentions_tainted_value(expression: &str, tainted_value: &str) -> bool {
    let expression = expression.trim();
    let tainted_value = tainted_value.trim();
    if expression.is_empty() || tainted_value.is_empty() {
        return false;
    }
    if expression == tainted_value {
        return true;
    }
    if is_bare_identifier(tainted_value) {
        return tokenise_identifiers_outside_strings(expression)
            .iter()
            .any(|token| token == tainted_value);
    }
    expression.contains(tainted_value)
}

// Caller, arg, the two summaries, db/global, and two reuse caches — each is
// load-bearing; a wrapper struct would only relocate the argument list.
#[derive(Default)]
struct CrossCallTransitIndex<'a> {
    by_site: ahash::AHashMap<(FuncId, bonsai_common::Span), Vec<&'a bonsai_idg::CrossCallEdge>>,
    tainted_return_spans: Vec<bonsai_common::Span>,
}

impl<'a> CrossCallTransitIndex<'a> {
    fn new(edges: &'a [bonsai_idg::CrossCallEdge]) -> Self {
        let mut index = Self::default();
        for edge in edges {
            index
                .by_site
                .entry((edge.caller, edge.call_span))
                .or_default()
                .push(edge);
            if edge.arg_idx == u32::MAX {
                index.tainted_return_spans.push(edge.call_span);
            }
        }
        index
            .tainted_return_spans
            .sort_by_key(|span| (span.file.raw(), span.start, std::cmp::Reverse(span.end)));
        index.tainted_return_spans.dedup();
        index
    }

    fn edges_at(
        &self,
        caller: FuncId,
        call_span: bonsai_common::Span,
    ) -> impl Iterator<Item = &'a bonsai_idg::CrossCallEdge> + '_ {
        self.by_site
            .get(&(caller, call_span))
            .into_iter()
            .flatten()
            .copied()
    }

    fn contains_tainted_return_in(&self, argument_span: bonsai_common::Span) -> bool {
        let first = self.tainted_return_spans.partition_point(|span| {
            (span.file.raw(), span.start) < (argument_span.file.raw(), argument_span.start)
        });
        let end = self.tainted_return_spans.partition_point(|span| {
            (span.file.raw(), span.start) <= (argument_span.file.raw(), argument_span.end)
        });
        self.tainted_return_spans[first..end]
            .iter()
            .any(|span| span_contains_or_equals(argument_span, *span))
    }
}

#[allow(clippy::too_many_arguments)]
fn tainted_arg_is_clean_nested_call_return(
    caller: FuncId,
    call_span: bonsai_common::Span,
    arg_idx: u32,
    call_summary: &CallEventSummary,
    cross_calls: &CrossCallTransitIndex<'_>,
    idg: &bonsai_idg::IdgQueryService,
    global: &GlobalIndex,
    call_summary_cache: &mut CallEventSummaryCache<'_>,
    function_summary_cache: &mut ahash::AHashMap<FuncId, crate::inter::FunctionSummary>,
    call_result_passthroughs: &[CompiledCallResultPassthrough<'_>],
    callee_name_cache: &mut CalleeNameCache,
    source_call_spans: &ahash::AHashSet<bonsai_common::Span>,
) -> bool {
    let idx = arg_idx as usize;
    let Some(arg_span) = call_summary.args_span.get(idx).copied() else {
        return false;
    };
    // Some adapters lower a language builtin/projection call to the exact
    // value place it reads (for example Erlang `maps:get(cmd, C)` becomes
    // `place = C.cmd`). If that structured place reached this CallArg in the
    // IDG, it is direct semantic evidence for the outer argument; do not
    // reinterpret the raw expression as an unknown nested return and prune
    // it. Ordinary nested calls have no `place` and continue through the
    // return-summary checks below.
    if call_summary
        .args_place
        .get(idx)
        .and_then(Option::as_deref)
        .is_some_and(|place| !place.trim().is_empty())
    {
        return false;
    }
    // The nested call is itself a tainted source (`sink(getenv(x))`):
    // its return is tainted no matter what its arguments are, so it is
    // never a "clean" nested return.
    if source_call_spans
        .iter()
        .any(|source_span| span_contains_or_equals(arg_span, *source_span))
    {
        return false;
    }
    // Clone only the one nested-call summary selected by the AST span. The
    // previous `.cloned()` copied the function's entire call-summary map for
    // every tainted argument, which turned large generated methods into a
    // quadratic allocation hot path during workspace-scale attribution.
    let nested = cached_nested_call_event_summary(caller, call_span, arg_span, global, call_summary_cache);
    let Some((nested_span, nested_summary)) = nested else {
        return false;
    };
    if matches!(nested_summary.call_kind, bonsai_lang_api::CallKind::Constructor) {
        return false;
    }
    if nested_call_return_matches_configured_passthrough(
        &nested_summary.name,
        nested_summary.args_value_text.len(),
        call_result_passthroughs,
        callee_name_cache,
    ) {
        return false;
    }

    // A nested call whose own RETURN is tainted — a source-bearing helper,
    // `sink(helper(x))` where `helper` returns a source or forwards a
    // tainted value out — is NOT a clean return, no matter what its own
    // arguments are. Such a return carries a synthetic `Return -> CallRet`
    // edge (sentinel `arg_idx == u32::MAX`) whose call site sits inside this
    // argument's span. The `param`-transit loop below deliberately skips
    // those sentinel edges (it models arg->return transit only), so
    // without this check the single-hop cross-function `sink(source())`
    // shape is dropped exactly like the direct case was.
    let nested_return_is_tainted = cross_calls.contains_tainted_return_in(arg_span);
    if nested_return_is_tainted {
        return false;
    }

    let mut tainted_params_by_callee: ahash::AHashMap<FuncId, ahash::AHashSet<usize>> =
        ahash::AHashMap::default();
    for edge in cross_calls.edges_at(caller, nested_span) {
        if edge.arg_idx == u32::MAX || edge.param_idx == u32::MAX {
            continue;
        }
        tainted_params_by_callee
            .entry(edge.callee)
            .or_default()
            .insert(edge.param_idx as usize);
    }

    if tainted_params_by_callee.is_empty() {
        return !nested_summary.args_value_text.is_empty();
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
            .or_insert_with(|| crate::inter::function_summary_from_idg(global, idg, callee));
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
    // Byte offsets are per-file, so containment is only meaningful within
    // the same file — otherwise a coincidental byte-range overlap across
    // two files falsely reports containment (e.g. exempting a sink arg
    // from the clean-nested-call filter because a source call in ANOTHER
    // file happens to share its byte range).
    outer.file == inner.file && inner.start >= outer.start && inner.end <= outer.end
}

fn cached_call_event_summary<'a>(
    func: FuncId,
    target_span: bonsai_common::Span,
    global: &GlobalIndex,
    cache: &'a mut CallEventSummaryCache<'_>,
) -> Option<&'a CallEventSummary> {
    cached_call_event_summaries_for_func(func, global, cache)
        .and_then(|summaries| summaries.get(&target_span))
}

fn cached_call_event_summaries_for_func<'a>(
    func: FuncId,
    global: &GlobalIndex,
    cache: &'a mut CallEventSummaryCache<'_>,
) -> Option<&'a ahash::AHashMap<bonsai_common::Span, CallEventSummary>> {
    if !cache.by_func.contains_key(&func) {
        let shared_hit = cache
            .shared
            .and_then(|shared| shared.call_events.read().get(&func).cloned());
        let summaries = shared_hit.unwrap_or_else(|| {
            let mut by_span: ahash::AHashMap<bonsai_common::Span, CallEventSummary> =
                ahash::AHashMap::default();
            if let Some(decl) = global.decl_of(bonsai_common::SymbolId::new(func.raw())) {
                collect_call_event_summaries(&decl.flow_events, &mut by_span);
            }
            let mut spans = by_span.keys().copied().collect::<Vec<_>>();
            spans.sort_by_key(|span| (span.file.raw(), span.start, std::cmp::Reverse(span.end)));
            let built = std::sync::Arc::new(FunctionCallEventSummaries { by_span, spans });
            if let Some(shared) = cache.shared {
                let mut write = shared.call_events.write();
                std::sync::Arc::clone(write.entry(func).or_insert_with(|| std::sync::Arc::clone(&built)))
            } else {
                built
            }
        });
        cache.by_func.insert(func, summaries);
    }
    Some(&cache.by_func.get(&func)?.by_span)
}

fn cached_nested_call_event_summary(
    func: FuncId,
    current_call_span: bonsai_common::Span,
    argument_span: bonsai_common::Span,
    global: &GlobalIndex,
    cache: &mut CallEventSummaryCache<'_>,
) -> Option<(bonsai_common::Span, CallEventSummary)> {
    let _ = cached_call_event_summaries_for_func(func, global, cache)?;
    let spans = &cache.by_func.get(&func)?.spans;
    let first = spans.partition_point(|span| {
        (span.file.raw(), span.start) < (argument_span.file.raw(), argument_span.start)
    });
    let end = spans.partition_point(|span| {
        (span.file.raw(), span.start) <= (argument_span.file.raw(), argument_span.end)
    });
    let nested_span = spans[first..end]
        .iter()
        .copied()
        // A language adapter may synthesize one semantic argument whose span
        // is the whole call expression. Exclude the current call identity.
        .filter(|span| *span != current_call_span && span_contains_or_equals(argument_span, *span))
        .min_by_key(|span| (span.start, std::cmp::Reverse(span.end)))?;
    let summary = cache.by_func.get(&func)?.by_span.get(&nested_span)?.clone();
    Some((nested_span, summary))
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
                call_kind,
                args,
                receiver,
                receiver_types,
            } => {
                out.insert(
                    *span,
                    CallEventSummary {
                        name: name.clone(),
                        call_kind: *call_kind,
                        args_value_text: args.iter().map(|arg| arg.value_text.clone()).collect(),
                        args_span: args.iter().map(|arg| arg.span).collect(),
                        args_place: args.iter().map(|arg| arg.place.clone()).collect(),
                        args_source_names: args.iter().map(|arg| arg.source_names.clone()).collect(),
                        receiver: receiver.clone(),
                        receiver_types: receiver_types.clone(),
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
                    call_kind: bonsai_lang_api::CallKind::Function,
                    args_value_text: source_call_args.clone(),
                    args_span: source_call_args.iter().map(|_| *span).collect(),
                    args_place: source_call_args
                        .iter()
                        .map(|arg| is_bare_identifier(arg.trim()).then(|| arg.trim().to_string()))
                        .collect(),
                    args_source_names: source_call_args
                        .iter()
                        .map(|arg| {
                            if is_bare_identifier(arg.trim()) {
                                vec![arg.trim().to_string()]
                            } else {
                                Vec::new()
                            }
                        })
                        .collect(),
                    receiver: None,
                    receiver_types: Vec::new(),
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
