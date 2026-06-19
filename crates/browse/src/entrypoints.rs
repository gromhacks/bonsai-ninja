//! `bonsai-ninja entrypoints` data layer.
//!
//! Entry points are callable declarations that have no resolved
//! semantic in-workspace callers. This is intentionally rulepack-free:
//! it is a deterministic callgraph root view for code navigation.

use crate::common::{collect_callee_names, format_span, make_name_filter};
use bonsai_common::FuncId;
use bonsai_lang_api::DeclKind;
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`entrypoints`].
#[derive(Copy, Clone, Default, Debug)]
pub struct EntryPointsFilters<'a> {
    /// `--kind function|method|constructor`
    pub kind: Option<&'a str>,
    /// `--file substring` against the decl's source path.
    pub file: Option<&'a str>,
    /// `--name substring` (or regex when `regex` is true). Matches
    /// short and qualified names.
    pub name: Option<&'a str>,
    /// Treat `name` as a regex instead of a substring.
    pub regex: bool,
}

/// One row of `entrypoints` output.
#[derive(Serialize, Clone, Debug)]
pub struct EntryPointOut {
    pub name: String,
    pub qualified_name: Option<String>,
    pub kind: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub params: Vec<String>,
    pub callees: Vec<String>,
    pub reason: String,
}

/// Collect callable declarations with no semantic caller in the
/// resolved callgraph.
pub fn entrypoints(ws: &Workspace, f: &EntryPointsFilters<'_>) -> Result<Vec<EntryPointOut>, regex::Error> {
    let global = ws.db().global_index();
    let graph = ws.resolved_call_graph();
    let name_match = make_name_filter(f.name, f.regex)?;
    let mut out = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !is_callable_entry_kind(decl.kind) {
                continue;
            }
            let kind = format!("{:?}", decl.kind).to_lowercase();
            if f.kind
                .is_some_and(|needle| !kind.contains(&needle.to_lowercase()))
            {
                continue;
            }
            let (path, line, column) = format_span(&decl.name_span, ws);
            if f.file.is_some_and(|needle| !path.contains(needle)) {
                continue;
            }
            let qualified_matches = decl
                .qualified_name
                .as_deref()
                .is_some_and(|qualified| name_match(qualified));
            if !name_match(&decl.name) && !qualified_matches {
                continue;
            }
            let func = FuncId::new(decl.symbol.raw());
            if graph.callers_of(func).any(|edge| edge.precision.is_semantic()) {
                continue;
            }
            let mut callees = collect_callee_names(&decl.flow_events);
            let mut seen = ahash::AHashSet::default();
            callees.retain(|callee| seen.insert(callee.clone()));
            out.push(EntryPointOut {
                name: decl.name.clone(),
                qualified_name: decl.qualified_name.clone(),
                kind,
                file: path,
                line,
                column,
                params: decl.params.clone(),
                callees,
                reason: "no_semantic_callers".to_string(),
            });
        }
    }
    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
    });
    Ok(out)
}

fn is_callable_entry_kind(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
    )
}
