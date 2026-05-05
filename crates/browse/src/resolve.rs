//! `bonsai-ninja dump-resolve` data layer.
//!
//! Stage-by-stage trace of the name resolver: short-callee
//! qualification, per-file alias rewrite, primary
//! `collect_callable_targets` lookup, literal-name fallback. The
//! handler deliberately re-implements the same stages the resolved
//! call graph builder would apply, then reports each stage's
//! intermediate state — the trace exposes the algorithm, not just
//! its final output.

use crate::common::format_span;
use bonsai_callgraph::{collect_callable_targets, short_callee};
use bonsai_hash::fnv1a_names_low32;
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`dump_resolve`].
#[derive(Copy, Clone, Default, Debug)]
pub struct ResolveFilters<'a> {
    /// Apply the alias map of the file whose path contains this
    /// substring. When `None`, the lookup runs in "global" mode (no
    /// alias rewrite).
    pub in_file: Option<&'a str>,
    /// Drill into one candidate by its `R:`-prefixed id.
    pub candidate_id: Option<&'a str>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ResolveCandidate {
    pub candidate_id: String,
    pub name: String,
    pub kind: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    /// Stable u32 `FuncId` value. Lets external tooling cross-
    /// reference with `dump-edges` / `dump-callgraph` FuncIds.
    pub func_id: u32,
}

#[derive(Serialize, Clone, Debug)]
pub struct ResolveTrace {
    pub query: String,
    pub in_file: Option<String>,
    pub short: String,
    pub alias_map_size: usize,
    pub alias_rewrite: Option<(String, String)>,
    pub primary_lookup_name: String,
    pub primary_candidate_count: usize,
    pub fallback_applied: bool,
    pub fallback_candidate_count: usize,
    pub candidates: Vec<ResolveCandidate>,
    pub outcome: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suggestions: Vec<String>,
}

/// Outcome of a [`dump_resolve`] call. `CandidateNotFound` signals
/// that `--candidate R:id` didn't match anything in the trace.
/// Boxed to keep the variant-size difference bounded — `Trace` is
/// several hundred bytes while `CandidateNotFound` is zero.
#[derive(Debug)]
pub enum ResolveOutcome {
    Trace(Box<ResolveTrace>),
    CandidateNotFound,
}

/// Stable content-hash id for one resolver candidate: `R:` + 8 hex
/// chars over `(query, file_context, candidate_file:line, candidate_name)`.
#[must_use]
pub fn compute_candidate_id(
    query: &str,
    in_file: Option<&str>,
    candidate_file: &str,
    candidate_line: u32,
    candidate_name: &str,
) -> String {
    let file_context = in_file.unwrap_or("<global>");
    let location_token = format!("{candidate_file}:{candidate_line}");
    let tokens = [
        query.to_string(),
        file_context.to_string(),
        location_token,
        candidate_name.to_string(),
    ];
    format!("R:{:08x}", fnv1a_names_low32(&tokens))
}

/// Run the resolver against `query` and return the per-stage
/// trace. `suggestions_for` lets the caller wire in their own
/// did-you-mean source — passing `|_, _| Vec::new()` is fine when
/// suggestions don't matter.
pub fn dump_resolve<F>(
    ws: &Workspace,
    query: &str,
    f: &ResolveFilters<'_>,
    suggestions_for: F,
) -> ResolveOutcome
where
    F: FnOnce(&Workspace, &str) -> Vec<String>,
{
    let global = ws.db().global_index();

    // `--in-file` matches a file path substring. The same shape
    // any other browse filter uses.
    let resolved_file_id: Option<bonsai_common::FileId> = f.in_file.and_then(|needle| {
        global.all_files().find(|file_id| {
            ws.vfs()
                .path(*file_id)
                .is_ok_and(|p| p.display().to_string().contains(needle))
        })
    });
    let applied_file_display: Option<String> =
        resolved_file_id.and_then(|file_id| ws.vfs().path(file_id).ok().map(|p| p.display().to_string()));

    let short = short_callee(query).to_string();

    // Stage 1: alias rewrite. When the user supplied `--in-file`,
    // apply that file's import aliases to the short callee name.
    let (alias_map_size, alias_rewrite, post_alias_name) = match resolved_file_id {
        Some(file_id) => {
            let alias_map = bonsai_resolve::alias_map_for_file(&ws.db().imports_for(file_id));
            let size = alias_map.len();
            match alias_map.get(short.as_str()) {
                Some(original) => (size, Some((short.clone(), original.clone())), original.clone()),
                None => (size, None, short.clone()),
            }
        }
        None => (0, None, short.clone()),
    };

    // Stage 2: primary lookup against the global decl index.
    let primary = collect_callable_targets(global.as_ref(), &post_alias_name);
    let primary_count = primary.len();

    // Stage 3: fallback. If the alias-rewritten lookup came up empty
    // AND the rewrite changed the name, retry with the original
    // query — covers idioms where the alias map wrote the wrong
    // suffix.
    let (fallback_applied, fallback) = if primary.is_empty() && post_alias_name != query {
        let fallback_targets = collect_callable_targets(global.as_ref(), query);
        (true, fallback_targets)
    } else {
        (false, Vec::new())
    };
    let final_func_ids = if primary.is_empty() {
        fallback.clone()
    } else {
        primary.clone()
    };

    let mut candidates: Vec<ResolveCandidate> = Vec::new();
    for func_id in &final_func_ids {
        let symbol_id = bonsai_common::SymbolId::new(func_id.raw());
        let Some(decl) = global.decl_of(symbol_id) else {
            continue;
        };
        let (candidate_file, candidate_line, candidate_column) = format_span(&decl.name_span, ws);
        candidates.push(ResolveCandidate {
            candidate_id: compute_candidate_id(
                query,
                applied_file_display.as_deref(),
                &candidate_file,
                candidate_line,
                &decl.name,
            ),
            name: decl.name.clone(),
            kind: format!("{:?}", decl.kind).to_lowercase(),
            file: candidate_file,
            line: candidate_line,
            column: candidate_column,
            func_id: func_id.raw(),
        });
    }

    // Same precision tagging the resolved call graph uses: 0 = no
    // target, 1 = single target (narrowed), 2+ = virtual / over-
    // approximate.
    let outcome = if candidates.is_empty() {
        "unresolved"
    } else if candidates.len() == 1 {
        "narrowed"
    } else {
        "over-approximate"
    }
    .to_string();

    // Did-you-mean suggestions are only useful when nothing
    // resolved — skip the lookup otherwise.
    let suggestions: Vec<String> = if candidates.is_empty() {
        suggestions_for(ws, query)
    } else {
        Vec::new()
    };

    if let Some(target_id) = f.candidate_id {
        candidates.retain(|c| c.candidate_id == target_id);
        if candidates.is_empty() {
            return ResolveOutcome::CandidateNotFound;
        }
    }

    ResolveOutcome::Trace(Box::new(ResolveTrace {
        query: query.to_string(),
        in_file: applied_file_display,
        short,
        alias_map_size,
        alias_rewrite,
        primary_lookup_name: post_alias_name,
        primary_candidate_count: primary_count,
        fallback_applied,
        fallback_candidate_count: fallback.len(),
        candidates,
        outcome,
        suggestions,
    }))
}
