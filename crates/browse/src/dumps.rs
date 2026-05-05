//! Debug-dump command data layer (`dump-hir`, `dump-cfg`,
//! `dump-callgraph`, `dump-edges`, `dump-resolve`, `dump-taint`,
//! `dump-ast`). The data extraction lives here; the CLI binary
//! renders the structured results.

use crate::common::collect_callees;
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_lang_api::{Decl, DeclKind, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// `dump-hir` payload: the decl header + its full flow-event tree.
/// Mirrors the JSON the CLI emits.
#[derive(Serialize, Clone, Debug)]
pub struct HirDump {
    pub name: String,
    pub kind: String,
    pub params: Vec<String>,
    pub span: bonsai_common::Span,
    pub flow_events: Vec<FlowEvent>,
}

impl HirDump {
    /// Lift a [`Decl`] into the externally-serialised HIR shape.
    fn from_decl(decl: &Decl) -> Self {
        Self {
            name: decl.name.clone(),
            kind: format!("{:?}", decl.kind).to_lowercase(),
            params: decl.params.clone(),
            span: decl.span,
            flow_events: decl.flow_events.clone(),
        }
    }
}

/// Fetch the HIR (`flow_events` tree + decl header) for the
/// nearest function/method/constructor named `symbol`. Returns
/// `None` when no callable decl matches.
pub fn dump_hir(ws: &Workspace, symbol: &str) -> Option<HirDump> {
    nearest_callable(ws, symbol).map(|d| HirDump::from_decl(&d))
}

/// Build the basic-block CFG for the nearest function/method/
/// constructor named `symbol`. Returns `None` when no callable
/// decl matches.
pub fn dump_cfg(ws: &Workspace, symbol: &str) -> Option<bonsai_cfg::Cfg> {
    let decl = nearest_callable(ws, symbol)?;
    Some(bonsai_cfg::build_cfg_from_flow(&decl.name, &decl.flow_events))
}

/// One row in the `dump-callgraph` table: a function with its
/// caller-in count and outgoing-callee count.
#[derive(Serialize, Clone, Debug)]
pub struct CallgraphRow {
    pub function: String,
    pub callers: usize,
    pub outgoing: usize,
}

/// Build the per-function callers / outgoing summary, sorted
/// hottest-first (most callers, then most outgoing, then alpha).
pub fn dump_callgraph(ws: &Workspace) -> Vec<CallgraphRow> {
    callgraph_summary(ws, &ws.resolved_call_graph())
}

/// Variant of [`dump_callgraph`] that takes a pre-built resolved
/// call graph. Useful when the caller already has one in hand
/// (e.g. through `bonsai_inspect::ChainCache::resolved_graph`).
pub fn callgraph_summary(ws: &Workspace, resolved: &ResolvedCallGraph) -> Vec<CallgraphRow> {
    use rayon::prelude::*;
    let global = ws.db().global_index();
    let files: Vec<_> = global.all_files().collect();
    let mut rows: Vec<CallgraphRow> = files
        .par_iter()
        .flat_map_iter(|&file| {
            let mut per_file: Vec<CallgraphRow> = Vec::new();
            for func_decl in global.functions_in(file) {
                // Outgoing callees come from the decl's flow events,
                // de-duped on textual name (the resolver merges
                // virtuals into a single edge anyway).
                let mut outgoing: Vec<String> = Vec::new();
                collect_callees(&func_decl.flow_events, &mut outgoing);
                outgoing.sort();
                outgoing.dedup();
                let func = bonsai_common::FuncId::new(func_decl.symbol.raw());
                let caller_count = resolved.callers_of(func).count();
                per_file.push(CallgraphRow {
                    function: func_decl.name.clone(),
                    callers: caller_count,
                    outgoing: outgoing.len(),
                });
            }
            per_file.into_iter()
        })
        .collect();
    // Hottest first: most callers, then most outgoing, alpha tiebreak.
    rows.sort_by(|a, b| {
        b.callers
            .cmp(&a.callers)
            .then_with(|| b.outgoing.cmp(&a.outgoing))
            .then_with(|| a.function.cmp(&b.function))
    });
    rows
}

/// Resolve `symbol` to a function / method / constructor decl, with
/// short-name fallback. When the bare name matches multiple symbols
/// across translation units, we sort candidates by (file path, name
/// span start) and pick the first deterministically — adapter-emitted
/// `find_by_name` order isn't stable enough to rely on for display.
pub(crate) fn nearest_callable(ws: &Workspace, symbol: &str) -> Option<Decl> {
    let global = ws.db().global_index();
    let vfs = ws.db().vfs();
    let mut candidates: Vec<Decl> = global
        .find_by_name(symbol)
        .iter()
        .filter_map(|sym| global.decl_of(*sym).cloned())
        .filter(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
        .collect();
    // Stable tiebreak: file path first, then position in file, then
    // SymbolId. Adapter `find_by_name` order isn't deterministic
    // enough for display — without this sort the same query could
    // return different decls across runs.
    candidates.sort_by(|a, b| {
        let a_path = vfs
            .path(a.span.file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let b_path = vfs
            .path(b.span.file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        a_path
            .cmp(&b_path)
            .then_with(|| a.name_span.start.cmp(&b.name_span.start))
            .then_with(|| a.symbol.raw().cmp(&b.symbol.raw()))
    });
    candidates.into_iter().next()
}
