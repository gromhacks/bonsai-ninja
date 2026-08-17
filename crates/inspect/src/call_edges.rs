use bonsai_common::{FuncId, Span};
use bonsai_lang_api::{Decl, FlowEvent};
use bonsai_workspace::Workspace;
use std::sync::Arc;

/// Cached call-edge source-span resolver used by inspect renderers.
///
/// This lives in `bonsai_inspect` rather than the CLI so every flow
/// renderer consumes the same semantic callgraph edge spans. It never
/// re-resolves by callee name: if the resolved callgraph did not emit
/// an exact/narrowed edge, there is no public call-site evidence to
/// render for that hop.
pub struct CallEdgeResolver<'a> {
    workspace: &'a Workspace,
    resolved: Option<Arc<bonsai_callgraph::ResolvedCallGraph>>,
    edge_spans: ahash::AHashMap<(FuncId, FuncId), Option<Span>>,
}

impl<'a> CallEdgeResolver<'a> {
    #[must_use]
    pub fn new(workspace: &'a Workspace) -> Self {
        Self {
            workspace,
            resolved: None,
            edge_spans: ahash::AHashMap::new(),
        }
    }

    /// Resolve call-site spans against the same exact query-scoped graph used
    /// for chain enumeration. A presentation verifier must never replace a
    /// compiler-proven corridor with a whole-workspace graph build.
    #[must_use]
    pub fn with_resolved_graph(
        workspace: &'a Workspace,
        resolved: Arc<bonsai_callgraph::ResolvedCallGraph>,
    ) -> Self {
        Self {
            workspace,
            resolved: Some(resolved),
            edge_spans: ahash::AHashMap::new(),
        }
    }

    fn find_call_span_to_func(&mut self, caller_func: FuncId, target_func: FuncId) -> Option<Span> {
        if let Some(hit) = self.edge_spans.get(&(caller_func, target_func)) {
            return *hit;
        }
        let workspace_graph;
        let graph = if let Some(resolved) = self.resolved.as_deref() {
            resolved
        } else {
            workspace_graph = self.workspace.cached_resolved_call_graph();
            workspace_graph.as_ref()
        };
        if let Some(span) = graph
            .callees_of(caller_func)
            .find(|edge| edge.to == target_func && edge.precision.is_semantic())
            .map(|edge| edge.span)
        {
            self.edge_spans.insert((caller_func, target_func), Some(span));
            return Some(span);
        }
        self.edge_spans.insert((caller_func, target_func), None);
        None
    }

    #[must_use]
    pub fn call_spans_for_chain(&mut self, chain: &[FuncId]) -> Vec<Option<Span>> {
        let mut spans = Vec::with_capacity(chain.len());
        for pair in chain.windows(2) {
            let (caller_id, callee_id) = (pair[0], pair[1]);
            let span = self.find_call_span_to_func(caller_id, callee_id);
            spans.push(span);
        }
        spans.push(None);
        spans
    }

    /// True when every consecutive pair in the chain represents a call
    /// edge pinned to an actual call site in the caller's flow events.
    pub fn chain_edges_resolvable(&mut self, chain: &[FuncId]) -> bool {
        if chain.len() < 2 {
            return true;
        }
        for pair in chain.windows(2) {
            let (caller_id, callee_id) = (pair[0], pair[1]);
            if self.find_call_span_to_func(caller_id, callee_id).is_none() {
                return false;
            }
        }
        true
    }
}

#[must_use]
pub fn find_call_span_to_func_uncached(
    workspace: &Workspace,
    caller_decl: &Decl,
    target_func: FuncId,
    _target_name: &str,
) -> Option<Span> {
    let caller_func = FuncId::new(caller_decl.symbol.raw());
    workspace
        .cached_resolved_call_graph()
        .callees_of(caller_func)
        .find(|edge| edge.to == target_func && edge.precision.is_semantic())
        .map(|edge| edge.span)
}

/// Syntactic-only edge predicate. Returns the span of the first
/// `Call` whose name string-matches `target` (or `*.target`) or
/// whose receiver-arg short-name matches. Used by display-only
/// paths that don't have a FuncId in hand. Public chain-edge
/// evidence must use the resolved callgraph span APIs above instead
/// of this syntactic helper.
#[must_use]
pub fn find_call_span_by_name(events: &[FlowEvent], target: &str) -> Option<Span> {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                span,
                receiver,
                args,
                ..
            } if name == target
                || name.ends_with(&format!(".{target}"))
                || (receiver.is_some()
                    && args
                        .iter()
                        .any(|arg| bonsai_resolve::short_tail(arg.value_text.trim()) == target)) =>
            {
                return Some(*span);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(s) = find_call_span_by_name(then_events, target) {
                    return Some(s);
                }
                if let Some(s) = find_call_span_by_name(else_events, target) {
                    return Some(s);
                }
            }
            FlowEvent::Loop { body, .. } => {
                if let Some(s) = find_call_span_by_name(body, target) {
                    return Some(s);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(s) = find_call_span_by_name(body, target)
                    .or_else(|| find_call_span_by_name(catch_events, target))
                    .or_else(|| find_call_span_by_name(finally_events, target))
                {
                    return Some(s);
                }
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(s) = find_call_span_by_name(body, target) {
                    return Some(s);
                }
            }
            FlowEvent::Assign {
                source_call: Some(name),
                span,
                ..
            } if name == target || name.ends_with(&format!(".{target}")) => {
                return Some(*span);
            }
            _ => {}
        }
    }
    None
}
