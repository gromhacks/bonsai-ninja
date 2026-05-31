//! Value-flow lattice and seed-free graph types.
//!
//! This module hosts the additive provenance-marker lattice that
//! complements (does not replace) the engine's `TokenSet` lattice. In
//! `LatticeMode::TokenSet` (the default, today's behavior), nothing
//! here is exercised. In `LatticeMode::Provenance`, propagation
//! produces the same `InterTaintResult` PLUS a `ValueFlowGraph` with
//! provenance edges so consumers can answer "where did this taint
//! come from / where does it flow?" without re-running the engine.

use ahash::{AHashMap, AHashSet};
use bonsai_common::{FuncId, Precision, Span, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_idg::IdgQueryService;
use bonsai_lang_api::DeclKind;
use serde::{Deserialize, Serialize};

use crate::inter::{
    interprocedural_taint_to_completion_with_caches, InterTaintCaches, InterTaintConfig, InterTaintResult,
};
use crate::reachable::collect_assign_targets;
use crate::TokenSet;

const SEMANTIC_FLOW_MAX_PRECISION: Precision = Precision::Narrowed;

/// Which lattice the engine should track during a propagation run.
///
/// `TokenSet` keeps today's flat identifier-set semantics — propagation
/// records `tainted` / `not tainted` per name. The Provenance mode is
/// strictly additive: it produces the same `tainted_calls` /
/// `call_records` AND, when enabled, a parallel `ValueFlowGraph` that
/// records which provenance markers reached which nodes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum LatticeMode {
    /// Today's behavior. Default.
    #[default]
    TokenSet,
    /// Track provenance markers in addition to the token set. Adds
    /// `ValueFlowGraph` to the result.
    Provenance,
}

/// One provenance marker: identifies a value at the point it became
/// "interesting" (a self-marked variable in the entry, a return
/// value, a param binding). Propagation records, for every
/// downstream node, the set of markers that contributed to its value.
///
/// Identity is `(origin_func, origin_span, value_text)`. Spans
/// disambiguate multiple definitions of the same name; `value_text`
/// captures the syntactic form so consumers can render lineage.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProvenanceMarker {
    pub origin_func: FuncId,
    pub origin_span: Span,
    pub value_text: String,
}

impl ProvenanceMarker {
    /// Construct a marker for a value observed at `origin_span` inside `origin_func`.
    #[must_use]
    pub fn new(origin_func: FuncId, origin_span: Span, value_text: impl Into<String>) -> Self {
        Self {
            origin_func,
            origin_span,
            value_text: value_text.into(),
        }
    }
}

/// Set of provenance markers — a richer lattice element than
/// `TokenSet`. Propagation joins by union.
pub type ProvenanceSet = AHashSet<ProvenanceMarker>;

/// One node in the unified value-flow graph: a `(function, span, value)`
/// triple corresponding to a concrete program point where a value is
/// observed (param binding, assignment target, call argument, return
/// value).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueFlowNode {
    pub func: FuncId,
    pub span: Span,
    pub value_text: String,
    pub kind: ValueFlowNodeKind,
}

/// What grammar role this node plays. Lets consumers query "all
/// param nodes" or "all call-arg nodes" without text matching.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueFlowNodeKind {
    Param,
    AssignTarget,
    CallArg,
    Return,
    Catch,
    Read,
}

/// One directed edge in the value-flow graph: a propagation step the
/// engine observed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueFlowEdge {
    pub from: ValueFlowNode,
    pub to: ValueFlowNode,
    /// Engine precision for this edge. Edges produced by virtual /
    /// over-approximate dispatch get the worst-case precision the
    /// engine could prove.
    pub precision: Precision,
    /// Origin span of the propagation step (call site, assignment
    /// target span, throw site). Lets consumers anchor lineage in
    /// the source.
    pub via_span: Span,
}

/// The unified seed-free value-flow graph for one entry function.
///
/// Populated from the interprocedural engine and wrapped by the
/// workspace cache for command and security consumers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ValueFlowGraph {
    /// Every node observed by the engine during this run.
    pub nodes: AHashSet<ValueFlowNode>,
    /// Outgoing adjacency keyed by node — supports forward closure.
    pub forward: AHashMap<ValueFlowNode, AHashSet<ValueFlowEdge>>,
    /// Incoming adjacency — supports backward closure.
    pub backward: AHashMap<ValueFlowNode, AHashSet<ValueFlowEdge>>,
    /// Worst precision observed across all edges in the graph.
    /// Defaults to `Exact` for an empty graph.
    pub precision: Precision,
    /// `true` when the engine saturated before draining. Findings
    /// produced from a saturated graph should be precision-tagged.
    pub saturated: bool,
}

impl ValueFlowGraph {
    /// Construct an empty graph; precision starts at `Exact` and is
    /// monotonically widened as edges are added.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: AHashSet::default(),
            forward: AHashMap::default(),
            backward: AHashMap::default(),
            precision: Precision::Exact,
            saturated: false,
        }
    }

    /// Insert one edge into the graph; updates both adjacency
    /// indexes and the worst-precision tag.
    pub fn add_edge(&mut self, edge: ValueFlowEdge) {
        self.nodes.insert(edge.from.clone());
        self.nodes.insert(edge.to.clone());
        // Worst-edge precision dominates: meet with the running tag.
        self.precision = self.precision.meet(edge.precision);
        self.forward
            .entry(edge.from.clone())
            .or_default()
            .insert(edge.clone());
        self.backward.entry(edge.to.clone()).or_default().insert(edge);
    }

    /// Semantic forward transitive closure from `node`. Visits every
    /// node reachable via exact/narrowed outgoing edges; weaker
    /// diagnostic edges are not evidence and are not traversed.
    #[must_use]
    pub fn forward_closure(&self, node: &ValueFlowNode) -> AHashSet<ValueFlowNode> {
        self.forward_closure_with_max_precision(node, SEMANTIC_FLOW_MAX_PRECISION)
    }

    fn forward_closure_with_max_precision(
        &self,
        node: &ValueFlowNode,
        max_precision: Precision,
    ) -> AHashSet<ValueFlowNode> {
        let mut reached = AHashSet::default();
        let mut stack = vec![node.clone()];
        while let Some(current) = stack.pop() {
            // Already-visited check doubles as the cycle terminator.
            if !reached.insert(current.clone()) {
                continue;
            }
            if let Some(edges) = self.forward.get(&current) {
                for edge in edges {
                    if edge.precision > max_precision || !edge.precision.is_semantic() {
                        continue;
                    }
                    stack.push(edge.to.clone());
                }
            }
        }
        // Self isn't a descendant of itself unless a cycle proved it.
        reached.remove(node);
        reached
    }

    /// Semantic backward transitive closure from `node`. Mirror of
    /// [`Self::forward_closure`].
    #[must_use]
    pub fn backward_closure(&self, node: &ValueFlowNode) -> AHashSet<ValueFlowNode> {
        self.backward_closure_with_max_precision(node, SEMANTIC_FLOW_MAX_PRECISION)
    }

    fn backward_closure_with_max_precision(
        &self,
        node: &ValueFlowNode,
        max_precision: Precision,
    ) -> AHashSet<ValueFlowNode> {
        let mut reached = AHashSet::default();
        let mut stack = vec![node.clone()];
        while let Some(current) = stack.pop() {
            if !reached.insert(current.clone()) {
                continue;
            }
            if let Some(edges) = self.backward.get(&current) {
                for edge in edges {
                    if edge.precision > max_precision || !edge.precision.is_semantic() {
                        continue;
                    }
                    stack.push(edge.from.clone());
                }
            }
        }
        reached.remove(node);
        reached
    }
}

/// Seed-free value-flow analysis for one entry function.
///
/// Builds a `ValueFlowGraph` by:
/// 1. Collecting every variable that's a candidate "self-source"
///    (entry's params + locally-bound assign targets in the body).
/// 2. Running the engine in `TokenSet` mode with that union seed.
/// 3. Translating the resulting `InterTaintResult.call_records` into
///    `ValueFlowEdge`s where the `from` node carries the marker for
///    the originating value and the `to` node carries the callee
///    param it lands on.
///
/// This implementation reuses the existing engine in `TokenSet` mode
/// — the `Provenance` lattice mode is the future engine-side
/// optimization that avoids repeated TokenSet runs. The post-process
/// approach trades CPU for simplicity: we get the same edges as a
/// native Provenance pass would emit, just by running the engine
/// once per source group and walking its records.
///
/// Caller responsibility: wrap in a per-FuncId cache (see
/// `crates/workspace/src/value_flow.rs`).
#[must_use]
pub fn value_flow_for_function(
    entry_func: FuncId,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
) -> ValueFlowGraph {
    // Convenience entry point: provision a fresh cache for one-off callers.
    let caches = InterTaintCaches::default();
    value_flow_for_function_with_caches(entry_func, db, config, &caches)
}

/// Same as `value_flow_for_function`, but threads a caller-provided
/// `InterTaintCaches` so batch consumers (e.g. a workspace analysis)
/// can amortise summary computation across many entry functions.
///
/// IDG-aware: when the workspace has seeded an [`IdgQueryService`]
/// onto `db`, the propagation step is satisfied by walking the IDG's
/// pre-built cross-file edge index instead of running the legacy
/// per-source engine. The `caches` argument is preserved for the
/// fallback path; the IDG path ignores it.
#[must_use]
pub fn value_flow_for_function_with_caches(
    entry_func: FuncId,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
    caches: &InterTaintCaches,
) -> ValueFlowGraph {
    let global = db.global_index();
    // No decl for this id → empty graph (e.g. caller asked about a stale FuncId).
    let Some(decl) = global.decl_of(SymbolId::new(entry_func.raw())).cloned() else {
        return ValueFlowGraph::new();
    };
    // Only callable decls (functions / methods / constructors) carry
    // value flow worth modeling — types and modules are skipped.
    if !matches!(
        decl.kind,
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
    ) {
        return ValueFlowGraph::new();
    }

    // IDG-backed path: when the workspace has seeded the IDG service,
    // the cross-call propagation step is a closure walk on the
    // pre-built workspace IDG. No per-source interprocedural worklist.
    if let Some(idg) = db.idg_service() {
        return build_graph_from_idg(entry_func, &decl, &idg, &global);
    }

    // Self-provenance seed — every param + assign target in the body
    // is its own value-flow source. This is a strict superset of the
    // current `taint_facts_and_graph_for_entry` seed; running the
    // engine once with the union seed yields a graph containing every
    // flow that any single-seed run would produce.
    let mut seed_set: TokenSet = decl.params.iter().filter(|p| !p.is_empty()).cloned().collect();
    collect_assign_targets(&decl.flow_events, &mut seed_set, true);
    // Empty seed → nothing to propagate; return empty rather than running the engine.
    if seed_set.is_empty() {
        return ValueFlowGraph::new();
    }

    let result = interprocedural_taint_to_completion_with_caches(entry_func, &seed_set, config, db, caches);
    build_graph_from_result(entry_func, &decl, &result)
}

/// Lift one engine result into a graph: register origin nodes for
/// each entry param, materialise intra-function assign edges, and
/// translate every recorded call propagation into one
/// `ValueFlowEdge`. Precision and the saturated flag carry over from
/// the engine result so consumers can tell when a graph was built
/// from an under-approximated run.
fn build_graph_from_result(
    entry_func: FuncId,
    entry_decl: &bonsai_lang_api::Decl,
    result: &InterTaintResult,
) -> ValueFlowGraph {
    let (mut graph, mut node_index) = build_intra_entry_graph(entry_func, entry_decl);
    graph.precision = result.precision;
    graph.saturated = result.saturated;

    // Walk every recorded propagation. Each `CallPropagation` says:
    // "in the caller, value X (at call_span) flowed into the callee's
    // parameter P." That's exactly one ValueFlowEdge.
    for propagation in &result.call_records {
        for tainted in &propagation.tainted_args {
            let from_key = (propagation.caller, tainted.value_text.clone());
            let from_node = find_call_arg_node(
                &graph,
                propagation.caller,
                propagation.call_span,
                &tainted.value_text,
            )
            .or_else(|| node_index.get(&from_key).cloned())
            .unwrap_or_else(|| {
                let synthesised = ValueFlowNode {
                    func: propagation.caller,
                    span: propagation.call_span,
                    value_text: tainted.value_text.clone(),
                    kind: ValueFlowNodeKind::CallArg,
                };
                node_index.insert(from_key.clone(), synthesised.clone());
                synthesised
            });
            let to_key = (propagation.callee, tainted.param_name.clone());
            let to_node = node_index.get(&to_key).cloned().unwrap_or_else(|| {
                let synthesised = ValueFlowNode {
                    func: propagation.callee,
                    span: propagation.call_span,
                    value_text: tainted.param_name.clone(),
                    kind: ValueFlowNodeKind::Param,
                };
                node_index.insert(to_key.clone(), synthesised.clone());
                synthesised
            });
            graph.add_edge(ValueFlowEdge {
                from: from_node,
                to: to_node,
                precision: propagation.edge_precision,
                via_span: propagation.call_span,
            });
        }
    }
    graph
}

/// IDG-driven graph builder. Replaces the per-source interprocedural
/// engine with a forward closure on the pre-built workspace IDG.
///
/// The graph is identical in shape to the engine-driven path:
/// 1. Intra-entry decl walk emits Param / Assign / Return nodes (and
///    intra-entry edges) — shared with the legacy path via
///    [`build_intra_entry_graph`].
/// 2. Cross-call edges are read from the semantic IDG closure
///    (exact/narrowed edges only). Each row becomes one
///    `ValueFlowEdge` from the caller's CallArg / origin node into
///    the callee's Param node.
fn build_graph_from_idg(
    entry_func: FuncId,
    entry_decl: &bonsai_lang_api::Decl,
    idg: &IdgQueryService,
    global: &bonsai_index::GlobalIndex,
) -> ValueFlowGraph {
    let (mut graph, mut node_index) = build_intra_entry_graph(entry_func, entry_decl);

    // Forward closure from entry's params. The IDG transfer pass
    // already wired Param→Read→Write chains intra-procedurally and
    // CallArg→Param + Return→CallRet edges across calls, so the
    // closure encodes every transitive propagation reachable from
    // the entry's locals.
    let seeds = idg.param_nodes_of(entry_func);
    if seeds.is_empty() {
        return graph;
    }
    let cross_calls = idg.cross_call_edges_in_closure_with_max_precision(&seeds, Some(Precision::Narrowed));

    // Pre-register every callee's `Param` node before we start
    // emitting edges. Without this, iteration order matters: if a
    // `helper → deeper` edge is processed before the matching
    // `entry → helper` edge, the helper-side endpoint gets
    // classified as `CallArg` (because no Param entry exists yet),
    // and the later `entry → helper` edge finds that CallArg in
    // the index and wires its destination there instead of
    // synthesising a fresh Param. Pre-seeding guarantees every
    // (callee_func, param_name) is a Param node regardless of order.
    for ce in &cross_calls {
        let param_name = callee_param_name(global, ce.callee, ce.param_idx).unwrap_or_default();
        if param_name.is_empty() {
            continue;
        }
        let to_key = (ce.callee, param_name.clone());
        node_index.entry(to_key).or_insert_with(|| {
            let node = ValueFlowNode {
                func: ce.callee,
                span: ce.call_span,
                value_text: param_name.clone(),
                kind: ValueFlowNodeKind::Param,
            };
            graph.nodes.insert(node.clone());
            node
        });
    }

    // Worst precision observed across cross-call edges drives the
    // graph-level precision tag (matches engine semantics).
    let mut worst = graph.precision;
    for ce in &cross_calls {
        worst = worst.meet(ce.precision);
        // Caller-side from node: prefer prior origin / assign target /
        // call-arg with matching (caller, value_text) so lineage chains
        // back. value_text comes from the caller's flow event at the
        // call span, indexed by arg position.
        let value_text =
            caller_arg_value_text(global, ce.caller, ce.call_span, ce.arg_idx).unwrap_or_default();
        let from_key = (ce.caller, value_text.clone());
        let from_node = find_call_arg_node(&graph, ce.caller, ce.call_span, &value_text)
            .or_else(|| node_index.get(&from_key).cloned())
            .unwrap_or_else(|| {
                let synthesised = ValueFlowNode {
                    func: ce.caller,
                    span: ce.call_span,
                    value_text: value_text.clone(),
                    kind: ValueFlowNodeKind::CallArg,
                };
                node_index.insert(from_key.clone(), synthesised.clone());
                synthesised
            });
        // Callee-side to node: param's name comes from callee_decl.params[param_idx].
        let param_name = callee_param_name(global, ce.callee, ce.param_idx).unwrap_or_default();
        let to_key = (ce.callee, param_name.clone());
        let to_node = node_index.get(&to_key).cloned().unwrap_or_else(|| {
            let synthesised = ValueFlowNode {
                func: ce.callee,
                span: ce.call_span,
                value_text: param_name.clone(),
                kind: ValueFlowNodeKind::Param,
            };
            node_index.insert(to_key.clone(), synthesised.clone());
            synthesised
        });
        graph.add_edge(ValueFlowEdge {
            from: from_node,
            to: to_node,
            precision: ce.precision,
            via_span: ce.call_span,
        });
    }
    graph.precision = worst;
    graph
}

fn find_call_arg_node(
    graph: &ValueFlowGraph,
    func: FuncId,
    call_span: Span,
    value_text: &str,
) -> Option<ValueFlowNode> {
    graph
        .nodes
        .iter()
        .find(|node| {
            node.func == func
                && node.span == call_span
                && node.value_text == value_text
                && matches!(node.kind, ValueFlowNodeKind::CallArg)
        })
        .cloned()
}

/// Look up the textual form of the `arg_idx`-th argument of the
/// `Call` event whose span is `call_span` inside `caller`. Returns
/// `None` when the caller isn't in the index, isn't callable, or
/// no Call event matches the span / index.
fn caller_arg_value_text(
    global: &bonsai_index::GlobalIndex,
    caller: FuncId,
    call_span: Span,
    arg_idx: u8,
) -> Option<String> {
    let decl = global.decl_of(SymbolId::new(caller.raw()))?;
    use bonsai_lang_api::FlowEvent;
    fn find_call_arg<'a>(
        events: &'a [FlowEvent],
        target_span: Span,
        idx: usize,
    ) -> Option<&'a bonsai_lang_api::CallArg> {
        for event in events {
            match event {
                FlowEvent::Call { span, args, .. } if *span == target_span => {
                    return args.get(idx);
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if let Some(found) = find_call_arg(then_events, target_span, idx) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_arg(else_events, target_span, idx) {
                        return Some(found);
                    }
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if let Some(found) = find_call_arg(body, target_span, idx) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_arg(catch_events, target_span, idx) {
                        return Some(found);
                    }
                    if let Some(found) = find_call_arg(finally_events, target_span, idx) {
                        return Some(found);
                    }
                }
                FlowEvent::Loop { body, .. } => {
                    if let Some(found) = find_call_arg(body, target_span, idx) {
                        return Some(found);
                    }
                }
                // H4: a call nested in a `with`/`using` (Using) or
                // `defer` (Defer) body is the dominant production path;
                // mirror the intra-entry walker and the IDG transfer
                // walker so its arg text is recovered (without this the
                // IDG path synthesises a disconnected CallArg and the
                // callee param is never reached).
                FlowEvent::Using { body, .. } | FlowEvent::Defer { body, .. } => {
                    if let Some(found) = find_call_arg(body, target_span, idx) {
                        return Some(found);
                    }
                }
                _ => {}
            }
        }
        None
    }
    let arg = find_call_arg(&decl.flow_events, call_span, arg_idx as usize)?;
    Some(arg.value_text.clone())
}

/// Look up the name of the `param_idx`-th parameter of `callee`.
fn callee_param_name(global: &bonsai_index::GlobalIndex, callee: FuncId, param_idx: u8) -> Option<String> {
    let decl = global.decl_of(SymbolId::new(callee.raw()))?;
    decl.params.get(param_idx as usize).cloned()
}

/// Shared "intra-entry" graph builder used by both the legacy
/// engine-driven and the IDG-driven paths. Emits the entry's
/// own Param, AssignTarget, and Return nodes plus their intra-
/// procedural edges, returning the partially populated graph plus
/// a `(FuncId, value_text) → ValueFlowNode` index that the call-edge
/// passes use to chain CallArgs back to their lineage origins.
fn build_intra_entry_graph(
    entry_func: FuncId,
    entry_decl: &bonsai_lang_api::Decl,
) -> (ValueFlowGraph, AHashMap<(FuncId, String), ValueFlowNode>) {
    let mut graph = ValueFlowGraph::new();

    // Seed nodes: entry's params get their own ValueFlowNode at the
    // function's entry span. We register them unconditionally so the
    // graph always exposes the "what are the origins" view, even when
    // a param doesn't appear in any propagation record (e.g. a param
    // that's read but never passed to a call).
    let entry_span = entry_decl.name_span;
    let mut origin_by_name: AHashMap<String, ValueFlowNode> = AHashMap::default();
    for param in &entry_decl.params {
        if param.is_empty() {
            continue;
        }
        let param_node = ValueFlowNode {
            func: entry_func,
            span: entry_span,
            value_text: param.clone(),
            kind: ValueFlowNodeKind::Param,
        };
        graph.nodes.insert(param_node.clone());
        // First binding wins — later events that read the same name
        // chain back to this origin instead of creating a duplicate.
        origin_by_name.entry(param.clone()).or_insert(param_node);
    }

    use bonsai_lang_api::FlowEvent;
    type FlowEnv = AHashMap<String, AHashSet<ValueFlowNode>>;

    fn merge_env(mut left: FlowEnv, right: FlowEnv) -> FlowEnv {
        for (name, nodes) in right {
            left.entry(name).or_default().extend(nodes);
        }
        left
    }

    fn source_nodes(env: &FlowEnv, func: FuncId, span: Span, name: &str) -> Vec<ValueFlowNode> {
        if name.is_empty() {
            return Vec::new();
        }
        if let Some(nodes) = env.get(name) {
            if !nodes.is_empty() {
                return nodes.iter().cloned().collect();
            }
        }
        vec![ValueFlowNode {
            func,
            span,
            value_text: name.to_string(),
            kind: ValueFlowNodeKind::Read,
        }]
    }

    // R3: collect every bare-identifier thrown value reachable in
    // `events`, descending nested control-flow bodies. The `Try` arm
    // uses this to wire an edge from a thrown tainted value to the
    // catch binding so `throw t; catch (e) sink(e)` keeps its lineage.
    fn collect_thrown_value_names(events: &[FlowEvent]) -> Vec<String> {
        let mut out = Vec::new();
        for event in events {
            match event {
                FlowEvent::Throw {
                    value_name: Some(name),
                    ..
                } if !name.is_empty() => out.push(name.clone()),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    out.extend(collect_thrown_value_names(then_events));
                    out.extend(collect_thrown_value_names(else_events));
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Using { body, .. }
                | FlowEvent::Defer { body, .. } => {
                    out.extend(collect_thrown_value_names(body));
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    out.extend(collect_thrown_value_names(body));
                    out.extend(collect_thrown_value_names(catch_events));
                    out.extend(collect_thrown_value_names(finally_events));
                }
                _ => {}
            }
        }
        out
    }

    fn walk_events(
        events: &[FlowEvent],
        graph: &mut ValueFlowGraph,
        func: FuncId,
        mut env: FlowEnv,
    ) -> FlowEnv {
        for event in events {
            match event {
                FlowEvent::Assign {
                    span,
                    target,
                    source_name,
                    source_names,
                    source_call_args,
                    ..
                } => {
                    if target.is_empty() {
                        continue;
                    }
                    let target_node = ValueFlowNode {
                        func,
                        span: *span,
                        value_text: target.clone(),
                        kind: ValueFlowNodeKind::AssignTarget,
                    };
                    graph.nodes.insert(target_node.clone());

                    let mut sources: AHashSet<String> = AHashSet::default();
                    if let Some(source) = source_name.as_deref() {
                        if !source.is_empty() {
                            sources.insert(source.to_string());
                        }
                    }
                    for source in source_names {
                        if !source.is_empty() {
                            sources.insert(source.clone());
                        }
                    }
                    for source in source_call_args {
                        if !source.is_empty() {
                            sources.insert(source.clone());
                        }
                    }
                    for source in sources {
                        for source_node in source_nodes(&env, func, *span, &source) {
                            graph.add_edge(ValueFlowEdge {
                                from: source_node,
                                to: target_node.clone(),
                                precision: Precision::Exact,
                                via_span: *span,
                            });
                        }
                    }

                    let mut defs = AHashSet::default();
                    defs.insert(target_node);
                    env.insert(target.clone(), defs);
                }
                FlowEvent::Call { span, args, .. } => {
                    for arg in args {
                        let node_text = if !arg.value_text.is_empty() {
                            arg.value_text.clone()
                        } else {
                            arg.place
                                .clone()
                                .or_else(|| arg.source_names.first().cloned())
                                .unwrap_or_default()
                        };
                        if node_text.is_empty() {
                            continue;
                        }
                        let arg_node = ValueFlowNode {
                            func,
                            span: *span,
                            value_text: node_text.clone(),
                            kind: ValueFlowNodeKind::CallArg,
                        };
                        graph.nodes.insert(arg_node.clone());

                        let mut sources: AHashSet<String> = AHashSet::default();
                        if let Some(place) = arg.place.as_deref() {
                            if !place.is_empty() {
                                sources.insert(place.to_string());
                            }
                        }
                        for source in &arg.source_names {
                            if !source.is_empty() {
                                sources.insert(source.clone());
                            }
                        }
                        if sources.is_empty() {
                            sources.insert(node_text);
                        }
                        for source in sources {
                            for source_node in source_nodes(&env, func, *span, &source) {
                                graph.add_edge(ValueFlowEdge {
                                    from: source_node,
                                    to: arg_node.clone(),
                                    precision: Precision::Exact,
                                    via_span: *span,
                                });
                            }
                        }
                    }
                }
                FlowEvent::Return {
                    span,
                    value_name,
                    value_text,
                } => {
                    let value = value_name.as_deref().unwrap_or_default();
                    let return_node = ValueFlowNode {
                        func,
                        span: *span,
                        value_text: value_name
                            .as_deref()
                            .or(value_text.as_deref())
                            .unwrap_or_default()
                            .to_string(),
                        kind: ValueFlowNodeKind::Return,
                    };
                    graph.nodes.insert(return_node.clone());
                    for from_node in source_nodes(&env, func, *span, value) {
                        graph.add_edge(ValueFlowEdge {
                            from: from_node,
                            to: return_node.clone(),
                            precision: Precision::Exact,
                            via_span: *span,
                        });
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    let before = env.clone();
                    let then_env = walk_events(then_events, graph, func, before.clone());
                    let else_env = if else_events.is_empty() {
                        before
                    } else {
                        walk_events(else_events, graph, func, before)
                    };
                    env = merge_env(then_env, else_env);
                }
                FlowEvent::Loop { body, .. } => {
                    let body_env = walk_events(body, graph, func, env.clone());
                    env = merge_env(env, body_env);
                }
                FlowEvent::Try {
                    span,
                    body,
                    catch_events,
                    finally_events,
                    catch_param,
                    ..
                } => {
                    let before = env.clone();
                    let body_env = walk_events(body, graph, func, before.clone());
                    let catch_env = if catch_events.is_empty() {
                        before
                    } else {
                        let mut catch_start = before;
                        if let Some(param) = catch_param.as_deref() {
                            if !param.is_empty() {
                                let catch_node = ValueFlowNode {
                                    func,
                                    span: *span,
                                    value_text: param.to_string(),
                                    kind: ValueFlowNodeKind::Catch,
                                };
                                graph.nodes.insert(catch_node.clone());
                                // R3: wire an edge from each tainted value
                                // thrown in the body to the catch binding
                                // so lineage survives `throw t; catch(e)
                                // sink(e)` on the legacy walker path.
                                for thrown in collect_thrown_value_names(body) {
                                    for from_node in source_nodes(&body_env, func, *span, &thrown) {
                                        graph.add_edge(ValueFlowEdge {
                                            from: from_node,
                                            to: catch_node.clone(),
                                            precision: Precision::Exact,
                                            via_span: *span,
                                        });
                                    }
                                }
                                catch_start
                                    .entry(param.to_string())
                                    .or_default()
                                    .insert(catch_node);
                            }
                        }
                        walk_events(catch_events, graph, func, catch_start)
                    };
                    env = walk_events(finally_events, graph, func, merge_env(body_env, catch_env));
                }
                FlowEvent::Using { body, .. } => {
                    env = walk_events(body, graph, func, env);
                }
                FlowEvent::Defer { body, .. } => {
                    let _ = walk_events(body, graph, func, env.clone());
                }
                // R3: `yield v` emits `v` to the generator's consumer;
                // model it as a Return-kind output node so backward
                // lineage from the consumer reaches the yielded value's
                // origins (the catch-all `_` arm used to drop it).
                FlowEvent::Yield { span, value_text } => {
                    if let Some(value) = value_text.as_deref() {
                        if !value.is_empty() {
                            let yield_node = ValueFlowNode {
                                func,
                                span: *span,
                                value_text: value.to_string(),
                                kind: ValueFlowNodeKind::Return,
                            };
                            graph.nodes.insert(yield_node.clone());
                            for from_node in source_nodes(&env, func, *span, value) {
                                graph.add_edge(ValueFlowEdge {
                                    from: from_node,
                                    to: yield_node.clone(),
                                    precision: Precision::Exact,
                                    via_span: *span,
                                });
                            }
                        }
                    }
                }
                // R3: an awaited value re-enters under the same name, so
                // the existing env binding already carries its lineage;
                // handle the arm explicitly (mirroring the inter pass's
                // informational treatment) rather than via the catch-all.
                FlowEvent::Await { .. } => {}
                _ => {}
            }
        }
        env
    }

    let mut env: FlowEnv = AHashMap::default();
    for (name, node) in &origin_by_name {
        env.entry(name.clone()).or_default().insert(node.clone());
    }
    let _ = walk_events(&entry_decl.flow_events, &mut graph, entry_func, env);

    // Index existing nodes by (func, value_text) so the call-edge
    // pass can stitch CallArgs back to prior origin / assign-target /
    // param nodes carrying the same name. Without this, the
    // assign-target `x` and the call-arg `x` would have distinct
    // identities (different spans) and the forward-closure would
    // break at the call boundary.
    let mut node_index: AHashMap<(FuncId, String), ValueFlowNode> = AHashMap::default();
    for node in &graph.nodes {
        node_index
            .entry((node.func, node.value_text.clone()))
            .or_insert_with(|| node.clone());
    }

    (graph, node_index)
}

#[cfg(test)]
#[path = "value_flow_tests.rs"]
mod tests;
