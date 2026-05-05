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
use bonsai_lang_api::DeclKind;
use serde::{Deserialize, Serialize};

use crate::inter::{
    interprocedural_taint_to_completion_with_caches, InterTaintCaches, InterTaintConfig, InterTaintResult,
};
use crate::reachable::collect_assign_targets;
use crate::TokenSet;

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
/// Phase 1 lands the type. Phase 2 has the engine populate it. Phase
/// 3 wraps the per-function graphs into a workspace cache.
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

    /// Forward transitive closure from `node`. Visits every node
    /// reachable via outgoing edges, depth-first; cycles terminate
    /// via a visited set.
    #[must_use]
    pub fn forward_closure(&self, node: &ValueFlowNode) -> AHashSet<ValueFlowNode> {
        let mut reached = AHashSet::default();
        let mut stack = vec![node.clone()];
        while let Some(current) = stack.pop() {
            // Already-visited check doubles as the cycle terminator.
            if !reached.insert(current.clone()) {
                continue;
            }
            if let Some(edges) = self.forward.get(&current) {
                for edge in edges {
                    stack.push(edge.to.clone());
                }
            }
        }
        // Self isn't a descendant of itself unless a cycle proved it.
        reached.remove(node);
        reached
    }

    /// Backward transitive closure from `node`. Mirror of
    /// `forward_closure`.
    #[must_use]
    pub fn backward_closure(&self, node: &ValueFlowNode) -> AHashSet<ValueFlowNode> {
        let mut reached = AHashSet::default();
        let mut stack = vec![node.clone()];
        while let Some(current) = stack.pop() {
            if !reached.insert(current.clone()) {
                continue;
            }
            if let Some(edges) = self.backward.get(&current) {
                for edge in edges {
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
/// Phase 2 deliverable. Builds a `ValueFlowGraph` by:
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
/// `crates/workspace/src/value_flow.rs`, Phase 3).
#[must_use]
pub fn value_flow_for_function(
    entry_func: FuncId,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
) -> ValueFlowGraph {
    // Convenience entry point: provision a fresh cache for one-off callers.
    let mut caches = InterTaintCaches::default();
    value_flow_for_function_with_caches(entry_func, db, config, &mut caches)
}

/// Same as `value_flow_for_function`, but threads a caller-provided
/// `InterTaintCaches` so batch consumers (e.g. a workspace analysis)
/// can amortise summary computation across many entry functions.
#[must_use]
pub fn value_flow_for_function_with_caches(
    entry_func: FuncId,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
    caches: &mut InterTaintCaches,
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
    let mut graph = ValueFlowGraph::new();
    graph.precision = result.precision;
    graph.saturated = result.saturated;

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

    // Walk the entry's flow events to capture intra-function assign
    // edges (`x = args` → edge `args` → `x`). Without this, only the
    // last hop (call-arg → callee-param) is captured; param→local
    // bindings are invisible. The interprocedural engine has already
    // done CFG-aware propagation; we're just lifting its conclusions
    // into graph form.
    use bonsai_lang_api::FlowEvent;
    for event in &entry_decl.flow_events {
        if let FlowEvent::Assign {
            span,
            target,
            source_name,
            source_names,
            ..
        } = event
        {
            if target.is_empty() {
                continue;
            }
            let target_node = ValueFlowNode {
                func: entry_func,
                span: *span,
                value_text: target.clone(),
                kind: ValueFlowNodeKind::AssignTarget,
            };
            graph.nodes.insert(target_node.clone());
            // Single-source assign: `x = y`.
            if let Some(source) = source_name.as_deref() {
                if !source.is_empty() {
                    // Prefer an existing origin node so lineage chains; otherwise synthesise a Read.
                    let source_node = origin_by_name
                        .get(source)
                        .cloned()
                        .unwrap_or_else(|| ValueFlowNode {
                            func: entry_func,
                            span: *span,
                            value_text: source.to_string(),
                            kind: ValueFlowNodeKind::Read,
                        });
                    graph.add_edge(ValueFlowEdge {
                        from: source_node,
                        to: target_node.clone(),
                        precision: Precision::Exact,
                        via_span: *span,
                    });
                }
            }
            // Multi-source assigns (e.g. `x = a + b`).
            for source in source_names {
                if source.is_empty() {
                    continue;
                }
                let source_node = origin_by_name
                    .get(source)
                    .cloned()
                    .unwrap_or_else(|| ValueFlowNode {
                        func: entry_func,
                        span: *span,
                        value_text: source.clone(),
                        kind: ValueFlowNodeKind::Read,
                    });
                graph.add_edge(ValueFlowEdge {
                    from: source_node,
                    to: target_node.clone(),
                    precision: Precision::Exact,
                    via_span: *span,
                });
            }
        }
    }

    // Index existing nodes by (func, value_text) so we can stitch
    // call-arg edges to prior assign-target / param nodes carrying
    // the same name. Without this, the assign-target `x` and the
    // call-arg `x` are distinct node identities (different spans)
    // and the forward-closure breaks at the call boundary.
    let mut node_index: AHashMap<(FuncId, String), ValueFlowNode> = AHashMap::default();
    for node in &graph.nodes {
        node_index
            .entry((node.func, node.value_text.clone()))
            .or_insert_with(|| node.clone());
    }

    // Walk every recorded propagation. Each `CallPropagation` says:
    // "in the caller, value X (at call_span) flowed into the callee's
    // parameter P." That's exactly one ValueFlowEdge.
    for propagation in &result.call_records {
        for tainted in &propagation.tainted_args {
            // Caller-side `from` node — prefer an existing node with
            // matching (caller, value_text) so the arg's lineage
            // chains back to its prior binding (param / assign
            // target). Falls back to a fresh CallArg node when no
            // prior binding exists (e.g. literal operand or
            // member-access expression).
            let from_key = (propagation.caller, tainted.value_text.clone());
            let from_node = node_index.get(&from_key).cloned().unwrap_or_else(|| {
                let synthesised = ValueFlowNode {
                    func: propagation.caller,
                    span: propagation.call_span,
                    value_text: tainted.value_text.clone(),
                    kind: ValueFlowNodeKind::CallArg,
                };
                node_index.insert(from_key.clone(), synthesised.clone());
                synthesised
            });
            // Callee-side `to` node — the param binding receiving
            // the value. We don't have the param's exact span here
            // (it's in the callee's decl, not in this propagation
            // record), so anchor on the call span as the
            // observation point. Phase 3 will resolve the precise
            // callee-param span via the global index.
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

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::FileId;

    fn span(file: FileId, start: u64, end: u64) -> Span {
        Span { file, start, end }
    }

    fn node(func: u32, start: u64, text: &str, kind: ValueFlowNodeKind) -> ValueFlowNode {
        ValueFlowNode {
            func: FuncId::new(func),
            span: span(FileId::new(0), start, start + text.len() as u64),
            value_text: text.to_string(),
            kind,
        }
    }

    #[test]
    fn forward_closure_reaches_descendants() {
        let mut g = ValueFlowGraph::new();
        let a = node(1, 0, "a", ValueFlowNodeKind::Param);
        let b = node(1, 4, "b", ValueFlowNodeKind::AssignTarget);
        let c = node(1, 8, "c", ValueFlowNodeKind::CallArg);
        g.add_edge(ValueFlowEdge {
            from: a.clone(),
            to: b.clone(),
            precision: Precision::Exact,
            via_span: span(FileId::new(0), 0, 1),
        });
        g.add_edge(ValueFlowEdge {
            from: b.clone(),
            to: c.clone(),
            precision: Precision::Exact,
            via_span: span(FileId::new(0), 4, 5),
        });
        let reach = g.forward_closure(&a);
        assert!(reach.contains(&b));
        assert!(reach.contains(&c));
        assert!(!reach.contains(&a));
    }

    #[test]
    fn backward_closure_reaches_ancestors() {
        let mut g = ValueFlowGraph::new();
        let a = node(1, 0, "a", ValueFlowNodeKind::Param);
        let b = node(1, 4, "b", ValueFlowNodeKind::AssignTarget);
        g.add_edge(ValueFlowEdge {
            from: a.clone(),
            to: b.clone(),
            precision: Precision::Exact,
            via_span: span(FileId::new(0), 0, 1),
        });
        assert!(g.backward_closure(&b).contains(&a));
        assert!(g.forward_closure(&a).contains(&b));
    }

    #[test]
    fn add_edge_meets_precision_to_worst() {
        let mut g = ValueFlowGraph::new();
        let a = node(1, 0, "a", ValueFlowNodeKind::Param);
        let b = node(1, 4, "b", ValueFlowNodeKind::AssignTarget);
        g.add_edge(ValueFlowEdge {
            from: a.clone(),
            to: b.clone(),
            precision: Precision::OverApproximate,
            via_span: span(FileId::new(0), 0, 1),
        });
        assert_eq!(g.precision, Precision::OverApproximate);
    }

    #[test]
    fn lattice_mode_default_is_token_set() {
        assert_eq!(LatticeMode::default(), LatticeMode::TokenSet);
    }
}
