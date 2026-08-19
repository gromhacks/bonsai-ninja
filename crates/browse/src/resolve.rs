//! `bonsai-ninja dump-resolve` data layer.
//!
//! Stage-by-stage trace of the name resolver: short-callee
//! qualification, per-file alias rewrite, and semantic contextual
//! lookup when a file context is supplied. The handler reports each
//! stage's intermediate state — the trace exposes the algorithm, not
//! just its final output.

use crate::common::{file_path_matches_filter, format_span, workspace_relative_path};
use bonsai_callgraph::{collect_callable_targets, short_callee};
use bonsai_common::{FileId, FuncId, Span};
use bonsai_hash::fnv1a_names_low32;
use bonsai_lang_api::{AliasTarget, ModulePath};
use bonsai_resolve::{resolve_callable_with_context, ResolveContext};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`dump_resolve`].
#[derive(Copy, Clone, Default, Debug)]
pub struct ResolveFilters<'a> {
    /// Apply the alias map of the file whose workspace-relative path
    /// matches this text. Explicit absolute paths are also accepted. When
    /// `None`, the lookup runs in "global" mode (no alias rewrite).
    pub in_file: Option<&'a str>,
    /// Optional one-based source line used only to disambiguate multiple
    /// exact call sites with the same adapter-lowered callee spelling.
    pub line: Option<u32>,
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
    /// `exact-call-site` when the query joined adapter-lowered syntax to the
    /// canonical callgraph; otherwise `contextual-name`.
    pub resolution_scope: String,
    /// Number of exact syntax call sites considered in the selected file.
    pub matched_call_sites: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_site_line: Option<u32>,
    /// True only when the requested resolver scope produced a semantic
    /// single-target result or a complete unresolved result. Multi-
    /// candidate output is an exact name inventory for debugging, not
    /// complete call-site resolution.
    pub analysis_complete: bool,
    pub analysis_incomplete_reasons: Vec<String>,
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
    FileContextNotFound { needle: String },
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

#[derive(Debug)]
struct ExactCallSiteResolution {
    matched_sites: usize,
    selected_line: Option<u32>,
    targets: Vec<FuncId>,
    outcome: &'static str,
    incomplete_reasons: Vec<String>,
}

fn exact_call_site_resolution(
    ws: &Workspace,
    file: FileId,
    query: &str,
    line: Option<u32>,
) -> Option<ExactCallSiteResolution> {
    let index = ws.exact_decl_index_shared(file)?;
    let mut sites = Vec::new();
    for decl in &index.defs {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        collect_exact_named_call_sites(
            &decl.flow_events,
            query.trim(),
            FuncId::new(decl.symbol.raw()),
            ws,
            line,
            &mut sites,
        );
    }
    sites.sort_unstable_by_key(|(caller, span, _)| (caller.raw(), span.start, span.end));
    sites.dedup();
    if sites.is_empty() {
        return None;
    }

    let selected_line = sites
        .first()
        .map(|(_, _, line)| *line)
        .filter(|_| sites.len() == 1);
    let keys = sites
        .iter()
        .map(|(caller, span, _)| (*caller, *span))
        .collect::<ahash::AHashSet<_>>();
    let mut targets_by_site: ahash::AHashMap<(FuncId, Span), Vec<FuncId>> =
        keys.iter().copied().map(|key| (key, Vec::new())).collect();
    let mut unresolved = ahash::AHashSet::new();
    let visited = ws.visit_persisted_callgraph_partitions(
        |partition_file, _nodes, outgoing, _incoming, unresolved_sites| {
            if partition_file != file {
                return;
            }
            for edge in outgoing.iter().filter(|edge| edge.precision.is_semantic()) {
                let key = (edge.from, edge.span);
                if let Some(targets) = targets_by_site.get_mut(&key) {
                    targets.push(edge.to);
                }
            }
            unresolved.extend(
                unresolved_sites
                    .iter()
                    .map(|site| (site.caller, site.span))
                    .filter(|key| keys.contains(key)),
            );
        },
    );
    match visited {
        Some(Ok(())) => {}
        Some(Err(error)) => {
            return Some(ExactCallSiteResolution {
                matched_sites: sites.len(),
                selected_line,
                targets: Vec::new(),
                outcome: "unresolved",
                incomplete_reasons: vec![format!("callgraph-sidecar-error:{error}")],
            });
        }
        None => {
            let graph = ws.resolved_call_graph_for_files(&[file]);
            for edge in graph
                .inner()
                .edges
                .iter()
                .filter(|edge| edge.precision.is_semantic())
            {
                let key = (edge.from, edge.span);
                if let Some(targets) = targets_by_site.get_mut(&key) {
                    targets.push(edge.to);
                }
            }
            unresolved.extend(
                graph
                    .unresolved_workspace_call_sites()
                    .filter(|key| keys.contains(key)),
            );
        }
    }

    for targets in targets_by_site.values_mut() {
        targets.sort_unstable_by_key(|target| target.raw());
        targets.dedup();
    }
    let mut distinct = targets_by_site.values().cloned().collect::<Vec<_>>();
    distinct.sort_by(|left, right| {
        left.iter()
            .map(|func| func.raw())
            .cmp(right.iter().map(|func| func.raw()))
    });
    distinct.dedup();
    if distinct.len() > 1 {
        let mut targets = distinct.into_iter().flatten().collect::<Vec<_>>();
        targets.sort_unstable_by_key(|target| target.raw());
        targets.dedup();
        return Some(ExactCallSiteResolution {
            matched_sites: sites.len(),
            selected_line,
            targets,
            outcome: "ambiguous",
            incomplete_reasons: vec![format!(
                "`{query}` matched {} call sites with different semantic targets; pass --line to select one",
                sites.len()
            )],
        });
    }
    let targets = distinct.pop().unwrap_or_default();
    if targets.is_empty() {
        let has_workspace_gap = keys.iter().any(|key| unresolved.contains(key));
        let incomplete_reasons = if has_workspace_gap {
            vec!["unresolved-workspace-call-site".to_string()]
        } else {
            Vec::new()
        };
        return Some(ExactCallSiteResolution {
            matched_sites: sites.len(),
            selected_line,
            targets,
            outcome: if has_workspace_gap {
                "unresolved"
            } else {
                "external"
            },
            incomplete_reasons,
        });
    }
    Some(ExactCallSiteResolution {
        matched_sites: sites.len(),
        selected_line,
        // Multiple compiler-justified virtual targets are a complete
        // narrowed result, not an analysis gap. `ambiguous` is reserved for
        // equal spellings at different call sites that resolve differently.
        outcome: "narrowed",
        incomplete_reasons: Vec::new(),
        targets,
    })
}

fn collect_exact_named_call_sites(
    events: &[bonsai_lang_api::FlowEvent],
    query: &str,
    caller: FuncId,
    ws: &Workspace,
    line_filter: Option<u32>,
    out: &mut Vec<(FuncId, Span, u32)>,
) {
    for event in events {
        match event {
            bonsai_lang_api::FlowEvent::Call { span, name, .. } => {
                let (_, line, _) = format_span(span, ws);
                if name.trim() == query && line_filter.is_none_or(|selected| selected == line) {
                    out.push((caller, *span, line));
                }
            }
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_exact_named_call_sites(then_events, query, caller, ws, line_filter, out);
                collect_exact_named_call_sites(else_events, query, caller, ws, line_filter, out);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. }
            | bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                collect_exact_named_call_sites(body, query, caller, ws, line_filter, out);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_exact_named_call_sites(body, query, caller, ws, line_filter, out);
                collect_exact_named_call_sites(catch_events, query, caller, ws, line_filter, out);
                collect_exact_named_call_sites(finally_events, query, caller, ws, line_filter, out);
            }
            _ => {}
        }
    }
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
    let global = ws.compiler_header_index();

    // `--in-file` matches a workspace-relative file path. The same shape
    // any other browse filter uses.
    let resolved_file_id: Option<bonsai_common::FileId> = f.in_file.and_then(|needle| {
        global.all_files().find(|file_id| {
            ws.vfs()
                .path(*file_id)
                .is_ok_and(|p| file_path_matches_filter(ws, &p.display().to_string(), needle))
        })
    });
    let applied_file_display: Option<String> = resolved_file_id.and_then(|file_id| {
        ws.vfs()
            .path(file_id)
            .ok()
            .map(|path| workspace_relative_path(ws, &path.display().to_string()))
    });
    if let (Some(needle), None) = (f.in_file, resolved_file_id) {
        return ResolveOutcome::FileContextNotFound {
            needle: needle.to_string(),
        };
    }

    let short = short_callee(query).to_string();

    // Stage 1: alias rewrite. When the user supplied `--in-file`,
    // inspect that file's import aliases. The contextual resolver gets
    // the typed alias map and applies the rewrite semantically; the
    // string value here is display-only trace evidence.
    let typed_alias_map: ahash::AHashMap<String, AliasTarget> = resolved_file_id
        .map(|file_id| {
            bonsai_lang_api::alias_map_from_import_specs(&ws.db().imports_for(file_id))
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    let (alias_map_size, alias_rewrite, post_alias_name) = match resolved_file_id {
        Some(_) => {
            let size = typed_alias_map.len();
            match typed_alias_map.get(short.as_str()) {
                Some(target) => {
                    let target_text = alias_target_display(target);
                    (size, Some((short.clone(), target_text.clone())), target_text)
                }
                None => (size, None, short.clone()),
            }
        }
        None => (0, None, short.clone()),
    };

    // When the query exactly names an adapter-lowered call in the selected
    // file, join that syntax identity to the canonical callgraph. This keeps
    // receiver/type evidence intact (`self.inner.spawn` must never be reduced
    // to an unrelated bare `spawn`). A source line is needed only when equal
    // spellings genuinely resolve to different targets.
    let exact_call_site = resolved_file_id.and_then(|file| {
        let selected = exact_call_site_resolution(ws, file, query, f.line);
        if selected.is_none() && f.line.is_some() {
            exact_call_site_resolution(ws, file, query, None).map(|unfiltered| ExactCallSiteResolution {
                matched_sites: unfiltered.matched_sites,
                selected_line: None,
                targets: Vec::new(),
                outcome: "unresolved",
                incomplete_reasons: vec![format!(
                    "`{query}` has exact call sites in the selected file, but none at line {}",
                    f.line.expect("checked above")
                )],
            })
        } else {
            selected
        }
    });

    // Stage 2: primary lookup. With `--in-file`, this uses the
    // semantic resolver path: caller file, module path, visibility,
    // and typed alias map. Without a file context, the command remains
    // a contextless name inventory and marks multi-candidate outcomes
    // as ambiguous instead of presenting them as flow edges.
    let primary = if let Some(exact) = exact_call_site.as_ref() {
        exact.targets.clone()
    } else if let Some(file_id) = resolved_file_id {
        let module_path = module_path_for_file(global.as_ref(), file_id);
        let path_lookup = |candidate_file: FileId| {
            ws.vfs()
                .path(candidate_file)
                .ok()
                .map(|path| path.display().to_string())
        };
        let ctx = ResolveContext::new(file_id, &module_path)
            .with_alias_map(&typed_alias_map)
            .with_file_path_lookup(&path_lookup)
            .with_same_directory_unqualified_calls(
                ws.db()
                    .adapter_for(file_id)
                    .is_some_and(|adapter| adapter.capabilities().same_directory_unqualified_calls),
            );
        resolve_callable_with_context(global.as_ref(), &short, &ctx)
    } else {
        collect_callable_targets(global.as_ref(), &post_alias_name)
    };
    let primary_count = primary.len();

    // Stage 3: legacy contextless fallback. Never apply it when a file
    // context is available: a broad literal retry would undo the
    // semantic narrowing the user asked `--in-file` to provide.
    let (fallback_applied, fallback) = if exact_call_site.is_none()
        && resolved_file_id.is_none()
        && primary.is_empty()
        && post_alias_name != query
    {
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
        let candidate_file = workspace_relative_path(ws, &candidate_file);
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

    // A global resolver lookup without a concrete call site can prove a
    // single target or report ambiguity. Ambiguous candidate sets are not
    // semantic call edges; contextual call resolution must narrow them
    // before any flow surface follows them.
    let outcome = exact_call_site.as_ref().map_or_else(
        || {
            if candidates.is_empty() {
                "unresolved"
            } else if candidates.len() == 1 {
                "narrowed"
            } else {
                "ambiguous"
            }
        },
        |exact| exact.outcome,
    );
    let outcome = outcome.to_string();

    // Did-you-mean suggestions are only useful when nothing
    // resolved — skip the lookup otherwise.
    let suggestions: Vec<String> = if candidates.is_empty() && outcome == "unresolved" {
        suggestions_for(ws, query)
    } else {
        Vec::new()
    };

    let analysis_incomplete_reasons = exact_call_site.as_ref().map_or_else(
        || {
            resolve_incomplete_reasons(
                query,
                resolved_file_id.is_some(),
                fallback_applied,
                fallback.len(),
                candidates.len(),
            )
        },
        |exact| exact.incomplete_reasons.clone(),
    );
    let analysis_complete = analysis_incomplete_reasons.is_empty();

    if let Some(target_id) = f.candidate_id {
        candidates.retain(|c| c.candidate_id == target_id);
        if candidates.is_empty() {
            return ResolveOutcome::CandidateNotFound;
        }
    }

    ResolveOutcome::Trace(Box::new(ResolveTrace {
        query: query.to_string(),
        in_file: applied_file_display,
        resolution_scope: if exact_call_site.is_some() {
            "exact-call-site"
        } else {
            "contextual-name"
        }
        .to_string(),
        matched_call_sites: exact_call_site.as_ref().map_or(0, |exact| exact.matched_sites),
        call_site_line: exact_call_site.as_ref().and_then(|exact| exact.selected_line),
        analysis_complete,
        analysis_incomplete_reasons,
        short,
        alias_map_size,
        alias_rewrite,
        primary_lookup_name: if exact_call_site.is_some() {
            query.to_string()
        } else {
            post_alias_name
        },
        primary_candidate_count: primary_count,
        fallback_applied,
        fallback_candidate_count: fallback.len(),
        candidates,
        outcome,
        suggestions,
    }))
}

fn resolve_incomplete_reasons(
    query: &str,
    has_file_context: bool,
    fallback_applied: bool,
    fallback_candidate_count: usize,
    candidate_count: usize,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if fallback_applied {
        reasons.push(format!(
            "contextless-fallback:{query}: literal retry returned {fallback_candidate_count} candidate(s)"
        ));
    }
    if candidate_count > 1 {
        let reason = if has_file_context {
            "ambiguous-semantic-resolution"
        } else {
            "context-required"
        };
        reasons.push(format!(
            "{reason}:{query}: matched {candidate_count} candidate(s); rerun with --in-file <path> for call-site/module context"
        ));
    }
    reasons
}

fn module_path_for_file(global: &bonsai_index::GlobalIndex, file_id: FileId) -> ModulePath {
    global
        .decls_in(file_id)
        .first()
        .map(|decl| decl.module_path.clone())
        .unwrap_or_default()
}

fn alias_target_display(target: &AliasTarget) -> String {
    match target {
        AliasTarget::Member { module, member } if module.is_empty() => member.clone(),
        AliasTarget::Member { module, member } => format!("{module}.{member}"),
        AliasTarget::Namespace { module } => module.clone(),
        AliasTarget::Type { type_name } => type_name.clone(),
    }
}
