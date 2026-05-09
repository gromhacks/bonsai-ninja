use bonsai_common::{FuncId, Span, SymbolId};
use bonsai_lang_api::{AliasTarget, Decl, FlowEvent};
use bonsai_workspace::Workspace;

/// Cached call-edge source-span resolver used by inspect renderers.
///
/// This lives in `bonsai_inspect` rather than the CLI because resolving
/// a rendered chain edge back to a concrete source call site depends on
/// resolver aliases, local callable bindings, and global symbol lookup.
/// The CLI should only consume the resulting spans.
pub struct CallEdgeResolver<'a> {
    workspace: &'a Workspace,
    aliases_by_file: ahash::AHashMap<bonsai_common::FileId, ahash::AHashMap<String, AliasTarget>>,
    local_bindings_by_func: ahash::AHashMap<FuncId, ahash::AHashMap<String, FuncId>>,
    edge_spans: ahash::AHashMap<(FuncId, FuncId), Option<Span>>,
}

impl<'a> CallEdgeResolver<'a> {
    #[must_use]
    pub fn new(workspace: &'a Workspace) -> Self {
        Self {
            workspace,
            aliases_by_file: ahash::AHashMap::new(),
            local_bindings_by_func: ahash::AHashMap::new(),
            edge_spans: ahash::AHashMap::new(),
        }
    }

    fn aliases_for_file(&mut self, file: bonsai_common::FileId) -> &ahash::AHashMap<String, AliasTarget> {
        self.aliases_by_file.entry(file).or_insert_with(|| {
            bonsai_lang_api::alias_map_from_import_specs(&self.workspace.db().imports_for(file))
                .into_iter()
                .collect()
        })
    }

    fn local_bindings_for_func(
        &mut self,
        caller_func: FuncId,
        caller_decl: &Decl,
    ) -> &ahash::AHashMap<String, FuncId> {
        self.local_bindings_by_func.entry(caller_func).or_insert_with(|| {
            let global = self.workspace.db().global_index();
            bonsai_callgraph::collect_local_callable_bindings(&caller_decl.flow_events, &global, caller_decl)
        })
    }

    fn find_call_span_to_func(
        &mut self,
        caller_func: FuncId,
        caller_decl: &Decl,
        target_func: FuncId,
        target_name: &str,
    ) -> Option<Span> {
        if let Some(hit) = self.edge_spans.get(&(caller_func, target_func)) {
            return *hit;
        }
        let mut aliases = self.aliases_for_file(caller_decl.span.file).clone();
        bonsai_lang_api::extend_alias_map_with_flow_events(&mut aliases, &caller_decl.flow_events);
        let local_bindings = self.local_bindings_for_func(caller_func, caller_decl).clone();
        let global = self.workspace.db().global_index();
        // Single canonical edge predicate — same primitive
        // `bonsai_workspace::flow_ids` consumes, so inspect's
        // chain renderer and the browse-row F: id hash agree
        // on the resolvable edge set.
        let span = bonsai_callgraph::find_call_span_resolved(
            &caller_decl.flow_events,
            target_func,
            target_name,
            &global,
            &aliases,
            &local_bindings,
            caller_decl,
        );
        self.edge_spans.insert((caller_func, target_func), span);
        span
    }

    #[must_use]
    pub fn call_spans_for_chain(&mut self, chain: &[FuncId]) -> Vec<Option<Span>> {
        let global = self.workspace.db().global_index();
        let mut spans = Vec::with_capacity(chain.len());
        for pair in chain.windows(2) {
            let (caller_id, callee_id) = (pair[0], pair[1]);
            let span = global
                .decl_of(SymbolId::new(caller_id.raw()))
                .zip(global.decl_of(SymbolId::new(callee_id.raw())))
                .and_then(|(caller_decl, callee_decl)| {
                    self.find_call_span_to_func(caller_id, caller_decl, callee_id, &callee_decl.name)
                });
            spans.push(span);
        }
        spans.push(None);
        spans
    }

    /// DFS-enumerate every resolvable call path starting from `base`'s
    /// tail, appending each to the return vector.
    #[must_use]
    pub fn enumerate_call_paths_from(
        &mut self,
        chain_cache: &crate::ChainCache<'_>,
        base: &[FuncId],
        max_extra: usize,
        max_paths: usize,
    ) -> Vec<Vec<FuncId>> {
        if base.is_empty() {
            return Vec::new();
        }
        let global = self.workspace.db().global_index();
        let mut out: Vec<Vec<FuncId>> = Vec::new();
        let mut stack: Vec<(Vec<FuncId>, usize)> = vec![(base.to_vec(), 0)];
        while let Some((path, extra)) = stack.pop() {
            if out.len() >= max_paths {
                break;
            }
            let tail = *path.last().expect("non-empty path");
            let Some(tail_decl) = global.decl_of(SymbolId::new(tail.raw())) else {
                out.push(path);
                continue;
            };
            if extra >= max_extra {
                out.push(path);
                continue;
            }
            let callees = chain_cache.callees_of_resolved(tail);
            let mut resolvable: Vec<FuncId> = callees
                .into_iter()
                .filter(|callee| {
                    if path.contains(callee) {
                        return false;
                    }
                    let Some(callee_decl) = global.decl_of(SymbolId::new(callee.raw())) else {
                        return false;
                    };
                    self.find_call_span_to_func(tail, tail_decl, *callee, &callee_decl.name)
                        .is_some()
                })
                .collect();
            if resolvable.is_empty() {
                out.push(path);
                continue;
            }
            resolvable.sort_by_key(|func| func.raw());
            for callee in resolvable.into_iter().rev() {
                let mut next = path.clone();
                next.push(callee);
                stack.push((next, extra + 1));
            }
        }
        if out.is_empty() {
            out.push(base.to_vec());
        }
        out
    }

    /// True when every consecutive pair in the chain represents a call
    /// edge pinned to an actual call site in the caller's flow events.
    pub fn chain_edges_resolvable(&mut self, chain: &[FuncId]) -> bool {
        if chain.len() < 2 {
            return true;
        }
        let global = self.workspace.db().global_index();
        for pair in chain.windows(2) {
            let (caller_id, callee_id) = (pair[0], pair[1]);
            let Some(caller_decl) = global.decl_of(SymbolId::new(caller_id.raw())) else {
                return false;
            };
            let Some(callee_decl) = global.decl_of(SymbolId::new(callee_id.raw())) else {
                return false;
            };
            if self
                .find_call_span_to_func(caller_id, caller_decl, callee_id, &callee_decl.name)
                .is_none()
            {
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
    target_name: &str,
) -> Option<Span> {
    let global = workspace.db().global_index();
    let mut aliases: ahash::AHashMap<String, AliasTarget> =
        bonsai_lang_api::alias_map_from_import_specs(&workspace.db().imports_for(caller_decl.span.file))
            .into_iter()
            .collect();
    bonsai_lang_api::extend_alias_map_with_flow_events(&mut aliases, &caller_decl.flow_events);
    let local_bindings =
        bonsai_callgraph::collect_local_callable_bindings(&caller_decl.flow_events, &global, caller_decl);
    bonsai_callgraph::find_call_span_resolved(
        &caller_decl.flow_events,
        target_func,
        target_name,
        &global,
        &aliases,
        &local_bindings,
        caller_decl,
    )
}

/// Syntactic-only edge predicate. Returns the span of the first
/// `Call` whose name string-matches `target` (or `*.target`) or
/// whose receiver-arg short-name matches. Used by display-only
/// paths that don't have a FuncId in hand;
/// [`bonsai_callgraph::find_call_span_resolved`] is the canonical
/// alias-aware version every chain-edge consumer should prefer.
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
