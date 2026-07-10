//! IDG-backed interprocedural taint compatibility surface.
//!
//! The former per-function worklist lived in `inter/mod.rs`. All public
//! entry points now derive their result from one IDG forward closure. The
//! configuration/result types remain source-compatible for SDK consumers,
//! while scheduling-only fields such as `budget` are retained as no-ops.

mod summary;

use std::sync::atomic::{AtomicBool, Ordering};

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::EdgeKind;
use bonsai_common::{FuncId, Precision, Span, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::FlowEvent;

use crate::{text::normalise_qualified_text, IntraTaintResult, TokenSet};

#[allow(unreachable_pub)]
pub use summary::{
    function_summary, FunctionSummary, ParamSideEffect, ReturnAccessPath, ReturnElementTaint,
    ReturnFieldTaint,
};

#[derive(Clone, Debug)]
pub struct InterTaintConfig {
    /// Compatibility-only sanitizer inventory. Sanitizer attribution belongs
    /// to the security layer and does not kill propagation in the IDG.
    pub sanitizers: TokenSet,
    /// Retained for source compatibility. IDG closure is not chunked.
    pub budget: u32,
    /// Retained for source compatibility. IDG closure has no CFG worklist cap.
    pub intra_worklist_cap: Option<u32>,
    /// Retained for source compatibility; IDG sources are the composed seed
    /// nodes supplied to the query.
    pub source_bearing_functions: AHashSet<FuncId>,
    /// Declarative transfer-time shapes honored by the compatibility IDG.
    pub clean_output_overwrites: Vec<CleanOutputOverwrite>,
    pub source_output_args: Vec<SourceOutputArgs>,
    pub source_callback_args: Vec<SourceCallbackArgs>,
    /// Declarative query-time transfer overlays.
    pub call_result_passthroughs: Vec<CallResultPassthrough>,
    pub output_arg_flows: Vec<OutputArgFlow>,
    /// Retained for source compatibility. Indirect callback inputs are now
    /// derived from resolver-proven callable arguments instead of method-name
    /// inventories.
    pub callback_invocation_methods: AHashSet<String>,
    pub receiver_state_propagations: Vec<ReceiverStatePropagation>,
    pub max_edge_precision: Option<Precision>,
    /// Retained for source compatibility. IDG closure uses one node-bitset
    /// lattice.
    pub lattice_mode: crate::value_flow::LatticeMode,
}

impl Default for InterTaintConfig {
    fn default() -> Self {
        Self {
            sanitizers: TokenSet::default(),
            budget: 512,
            intra_worklist_cap: None,
            source_bearing_functions: AHashSet::default(),
            clean_output_overwrites: Vec::new(),
            source_output_args: Vec::new(),
            source_callback_args: Vec::new(),
            call_result_passthroughs: Vec::new(),
            output_arg_flows: Vec::new(),
            callback_invocation_methods: AHashSet::default(),
            receiver_state_propagations: Vec::new(),
            max_edge_precision: Some(Precision::Narrowed),
            lattice_mode: crate::value_flow::LatticeMode::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanOutputOverwrite {
    pub callee: String,
    pub output_arg_index: usize,
    pub value_start_arg_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceOutputArgs {
    pub callee: String,
    pub output_arg_indices: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceCallbackArgs {
    pub callee: String,
    pub callback_arg_index: usize,
    pub source_param_indices: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallResultPassthrough {
    pub callee: String,
    pub input_arg_indices: Vec<usize>,
    pub input_receiver: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputArgFlow {
    pub callee: String,
    pub output_arg_index: usize,
    pub value_start_arg_index: Option<usize>,
    pub value_arg_indices: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverStatePropagation {
    pub method: String,
    pub receiver_type: Option<String>,
}

/// Compatibility handle for callers that share analysis caches. IDG state is
/// cached on `AnalyzerDb`; this handle records whether it has participated in
/// a warm run so existing invalidation and lifecycle APIs remain meaningful.
#[derive(Debug, Default)]
pub struct InterTaintCaches {
    warmed: AtomicBool,
}

impl InterTaintCaches {
    pub fn seed_resolved_call_graph(&self, call_graph: &bonsai_callgraph::ResolvedCallGraph) {
        if !call_graph.inner().edges.is_empty() {
            self.mark_used();
        }
    }

    pub fn clear(&self) {
        self.warmed.store(false, Ordering::Release);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.warmed.load(Ordering::Acquire)
    }

    pub(crate) fn mark_used(&self) {
        self.warmed.store(true, Ordering::Release);
    }
}

#[derive(Clone, Debug, Default)]
pub struct InterTaintResult {
    pub per_function: AHashMap<FunctionSeed, IntraTaintResult>,
    pub call_records: Vec<CallPropagation>,
    pub tainted_calls: Vec<TaintedCall>,
    pub precision: Precision,
    pub pairs_analyzed: u32,
    pub saturated: bool,
    pub continuation: Option<InterTaintContinuation>,
}

#[derive(Clone, Debug, Default)]
pub struct InterTaintWorkItem {
    pub func: FuncId,
    pub seed: TokenSet,
    pub dyn_bindings: AHashMap<String, FuncId>,
    pub const_bindings: AHashMap<String, ConstValue>,
    pub lineage: Option<u64>,
    pub lineage_history: AHashSet<FunctionSeedBase>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConstValue {
    Bool(bool),
    Int(i64),
}

#[derive(Clone, Debug, Default)]
pub struct InterTaintContinuation {
    pub pending: Vec<InterTaintWorkItem>,
    pub seen: AHashSet<FunctionSeed>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FunctionSeed {
    pub func: FuncId,
    pub seed: Vec<String>,
    pub consts: Vec<(String, ConstValue)>,
    pub dyn_callees: Vec<(String, u32)>,
    pub lineage: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FunctionSeedBase {
    pub func: FuncId,
    pub seed: Vec<String>,
    pub consts: Vec<(String, ConstValue)>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CallPropagation {
    #[serde(default)]
    pub trace_id: u64,
    #[serde(default)]
    pub parent_trace_id: Option<u64>,
    pub caller: FuncId,
    pub callee: FuncId,
    pub call_span: Span,
    pub tainted_args: Vec<TaintedArg>,
    pub edge_kind: EdgeKind,
    pub edge_precision: Precision,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TaintedArg {
    pub index: usize,
    pub value_text: String,
    pub param_name: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TaintedArgAtCall {
    pub index: usize,
    pub value_text: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TaintedCall {
    #[serde(default)]
    pub parent_trace_id: Option<u64>,
    pub caller: FuncId,
    pub name: String,
    pub call_span: Span,
    pub tainted_args: Vec<TaintedArgAtCall>,
    pub tainted_receiver: Option<String>,
    #[serde(default)]
    pub kind: TaintedCallKind,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintedCallKind {
    #[default]
    Call,
    Write,
    Return,
}

#[must_use]
pub fn interprocedural_taint(
    entry_func: FuncId,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
) -> InterTaintResult {
    idg_backed_interprocedural_taint(entry_func, entry_sources, config, db)
}

fn idg_backed_interprocedural_taint(
    entry_func: FuncId,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
) -> InterTaintResult {
    if entry_sources.is_empty() {
        return InterTaintResult::default();
    }
    let idg = crate::idg_build::idg_service_for_inter_config(db, config);
    let global = db.global_index();
    let seed_nodes = crate::reachable::compose_idg_seed_nodes(
        crate::reachable::IdgSeedRequest::legacy_tokens(entry_func, entry_sources),
        global.as_ref(),
        idg.as_ref(),
    );
    let graph = crate::reachable::entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision(
        entry_func,
        entry_sources,
        None,
        &[],
        &config.receiver_state_propagations,
        &config.call_result_passthroughs,
        &config.output_arg_flows,
        None,
        None,
        None,
        config.max_edge_precision,
        db,
        idg.as_ref(),
        &seed_nodes,
    );
    entry_taint_graph_to_inter_result(graph, entry_func, entry_sources)
}

fn entry_taint_graph_to_inter_result(
    graph: crate::reachable::EntryTaintGraph,
    entry_func: FuncId,
    entry_sources: &TokenSet,
) -> InterTaintResult {
    let mut seeds_by_func: AHashMap<FuncId, AHashSet<String>> = AHashMap::default();
    seeds_by_func.insert(entry_func, entry_sources.iter().cloned().collect());
    for edge in &graph.call_records {
        seeds_by_func.entry(edge.caller).or_default();
        let callee_seed = seeds_by_func.entry(edge.callee).or_default();
        for arg in &edge.tainted_args {
            let param = arg.param_name.trim();
            if !param.is_empty() && param != crate::reachable::SYNTHETIC_RECEIVER_PARAM_NAME {
                callee_seed.insert(param.to_string());
            }
        }
    }
    for call in &graph.tainted_calls {
        seeds_by_func.entry(call.caller).or_default();
    }
    let per_function = seeds_by_func
        .into_iter()
        .map(|(func, seed)| {
            let mut seed: Vec<String> = seed.into_iter().collect();
            seed.sort();
            (
                FunctionSeed {
                    func,
                    seed,
                    ..FunctionSeed::default()
                },
                IntraTaintResult::default(),
            )
        })
        .collect();
    let call_records = graph
        .call_records
        .into_iter()
        .map(|edge| CallPropagation {
            trace_id: edge.trace_id,
            parent_trace_id: edge.parent_trace_id,
            caller: edge.caller,
            callee: edge.callee,
            call_span: edge.call_span,
            tainted_args: edge.tainted_args,
            edge_kind: edge.edge_kind,
            edge_precision: edge.precision,
        })
        .collect();
    InterTaintResult {
        per_function,
        call_records,
        tainted_calls: graph.tainted_calls,
        precision: graph.precision,
        pairs_analyzed: graph.pairs_analyzed,
        saturated: graph.saturated,
        continuation: None,
    }
}

#[must_use]
pub fn interprocedural_taint_with_caches(
    entry_func: FuncId,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> InterTaintResult {
    caches.mark_used();
    idg_backed_interprocedural_taint(entry_func, entry_sources, config, db)
}

#[must_use]
pub fn resume_interprocedural_taint_with_caches(
    mut previous: InterTaintResult,
    _config: &InterTaintConfig,
    _db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> InterTaintResult {
    caches.mark_used();
    previous.continuation = None;
    previous.saturated = false;
    previous
}

#[must_use]
pub fn interprocedural_taint_to_completion_with_caches(
    entry_func: FuncId,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> InterTaintResult {
    interprocedural_taint_with_caches(entry_func, entry_sources, config, db, caches)
}

#[must_use]
pub fn call_site_receives_taint(
    func: FuncId,
    sink_span: Span,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
) -> bool {
    idg_backed_call_site_receives_taint(func, sink_span, entry_sources, config, db)
}

#[must_use]
pub fn call_site_receives_taint_with_caches(
    func: FuncId,
    sink_span: Span,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> bool {
    caches.mark_used();
    idg_backed_call_site_receives_taint(func, sink_span, entry_sources, config, db)
}

fn idg_backed_call_site_receives_taint(
    func: FuncId,
    sink_span: Span,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
) -> bool {
    if entry_sources.is_empty() {
        return false;
    }
    let idg = crate::idg_build::idg_service_for_inter_config(db, config);
    let global = db.global_index();
    let seed_nodes = crate::reachable::compose_idg_seed_nodes(
        crate::reachable::IdgSeedRequest::legacy_tokens(func, entry_sources),
        global.as_ref(),
        idg.as_ref(),
    );
    let graph = crate::reachable::entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision(
        func,
        entry_sources,
        None,
        &[],
        &config.receiver_state_propagations,
        &config.call_result_passthroughs,
        &config.output_arg_flows,
        None,
        None,
        None,
        config.max_edge_precision,
        db,
        idg.as_ref(),
        &seed_nodes,
    );
    let spans_match = |candidate: Span| {
        candidate == sink_span
            || (candidate.file == sink_span.file
                && candidate.start <= sink_span.end
                && sink_span.start <= candidate.end)
    };
    let sink_event = global
        .decl_of(SymbolId::new(func.raw()))
        .and_then(|decl| most_specific_sink_event(&decl.flow_events, sink_span));
    if graph.tainted_calls.iter().any(|call| {
        call.caller == func
            && spans_match(call.call_span)
            && !(matches!(call.kind, TaintedCallKind::Return)
                && sink_event
                    .as_ref()
                    .is_some_and(|event| !matches!(event.kind, TaintedCallKind::Return)))
    }) || graph
        .call_records
        .iter()
        .any(|edge| edge.caller == func && spans_match(edge.call_span))
    {
        return true;
    }

    let Some(event) = sink_event else {
        return false;
    };
    let Some(receiver) = event
        .receiver
        .as_deref()
        .filter(|_| matches!(event.kind, TaintedCallKind::Call) && event.args_count == 0)
    else {
        return false;
    };
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
        return false;
    };
    let latest_writes = latest_receiver_field_writes_before(&decl.flow_events, receiver, event.span.start);
    graph.tainted_calls.iter().any(|call| {
        call.caller == func
            && matches!(call.kind, TaintedCallKind::Write)
            && latest_writes
                .get(&normalise_qualified_text(&call.name))
                .is_some_and(|span| *span == call.call_span)
    })
}

#[derive(Clone, Debug)]
struct SinkEventShape {
    kind: TaintedCallKind,
    span: Span,
    receiver: Option<String>,
    args_count: usize,
}

fn most_specific_sink_event(events: &[FlowEvent], sink_span: Span) -> Option<SinkEventShape> {
    fn consider(best: &mut Option<SinkEventShape>, candidate: SinkEventShape, sink_span: Span) {
        if candidate.span.file != sink_span.file
            || candidate.span.start > sink_span.end
            || sink_span.start > candidate.span.end
        {
            return;
        }
        let width = candidate.span.end.saturating_sub(candidate.span.start);
        let replace = best.as_ref().is_none_or(|current| {
            let current_width = current.span.end.saturating_sub(current.span.start);
            width < current_width
                || (width == current_width
                    && matches!(candidate.kind, TaintedCallKind::Call)
                    && !matches!(current.kind, TaintedCallKind::Call))
        });
        if replace {
            *best = Some(candidate);
        }
    }
    fn walk(events: &[FlowEvent], sink_span: Span, best: &mut Option<SinkEventShape>) {
        for event in events {
            match event {
                FlowEvent::Call {
                    span, receiver, args, ..
                } => consider(
                    best,
                    SinkEventShape {
                        kind: TaintedCallKind::Call,
                        span: *span,
                        receiver: receiver.clone(),
                        args_count: args.len(),
                    },
                    sink_span,
                ),
                FlowEvent::Assign { span, .. } => consider(
                    best,
                    SinkEventShape {
                        kind: TaintedCallKind::Write,
                        span: *span,
                        receiver: None,
                        args_count: 0,
                    },
                    sink_span,
                ),
                FlowEvent::Return { span, .. } => consider(
                    best,
                    SinkEventShape {
                        kind: TaintedCallKind::Return,
                        span: *span,
                        receiver: None,
                        args_count: 0,
                    },
                    sink_span,
                ),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    walk(then_events, sink_span, best);
                    walk(else_events, sink_span, best);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => walk(body, sink_span, best),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(body, sink_span, best);
                    walk(catch_events, sink_span, best);
                    walk(finally_events, sink_span, best);
                }
                _ => {}
            }
        }
    }
    let mut best = None;
    walk(events, sink_span, &mut best);
    best
}

fn latest_receiver_field_writes_before(
    events: &[FlowEvent],
    receiver: &str,
    before: u64,
) -> AHashMap<String, Span> {
    fn walk(events: &[FlowEvent], receiver: &str, before: u64, out: &mut AHashMap<String, Span>) {
        for event in events {
            match event {
                FlowEvent::Assign { target, span, .. } if span.end <= before => {
                    let target = normalise_qualified_text(target);
                    if target
                        .strip_prefix(receiver)
                        .is_some_and(|suffix| suffix.starts_with('.'))
                        && out
                            .get(&target)
                            .is_none_or(|current| (span.start, span.end) > (current.start, current.end))
                    {
                        out.insert(target, *span);
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    walk(then_events, receiver, before, out);
                    walk(else_events, receiver, before, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => walk(body, receiver, before, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(body, receiver, before, out);
                    walk(catch_events, receiver, before, out);
                    walk(finally_events, receiver, before, out);
                }
                _ => {}
            }
        }
    }
    let receiver = normalise_qualified_text(receiver);
    let mut out = AHashMap::default();
    if !receiver.is_empty() {
        walk(events, &receiver, before, &mut out);
    }
    out
}
