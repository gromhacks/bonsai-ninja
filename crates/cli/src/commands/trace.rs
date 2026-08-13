//! `bonsai-ninja trace` — walk a flow from source to sink and render
//! the call tree indent-style. JSON mode emits the raw `TraceResult`
//! (with paging-wrapper under `--context` / `--page`); DOT mode
//! emits a Graphviz graph; text mode paints the themed depth tree.
//!
//! Error-path helpers (`augment_not_found`, `nearest_names`,
//! `levenshtein`) live in this module because they're only invoked
//! from the trace dispatch to annotate "no such symbol" errors with
//! spelling suggestions.

use anyhow::Result;
use bonsai_sdk::{summarize_incomplete_reasons, summarize_precision, CrossModuleOptions, Workspace};
use bonsai_sdk::{PathSummary, TraceResult, TraceStep, TraceStepKind};
use serde::Serialize;
use std::collections::BTreeSet;

use crate::args::OutputFormat;
use crate::footer::render_paging_footer;
use crate::page_cache;
use crate::paging;
use crate::progress;
use crate::{cli_print, cli_println, ui};

use super::{open_project_index_only as open_project, page_info_to_json, paged_json_incomplete_reasons};

const TRACE_SEMANTIC_CACHE_KIND: &str = "trace-result-v1";

#[derive(Clone, Serialize)]
struct TracePageRow<'a> {
    path: &'a PathSummary,
    // One step is the smallest independently pageable trace fact. Keeping an
    // entire path in one row made a single deep path exceed `--context` even
    // though no semantic work was capped.
    steps: Vec<&'a TraceStep>,
    #[serde(skip)]
    cost: u64,
}

pub(crate) fn cmd_trace(
    root: &std::path::Path,
    function: Option<String>,
    from: Option<String>,
    to: Option<String>,
    paging_cfg: paging::PagingConfig,
    format: OutputFormat,
    trace_opts: CrossModuleOptions,
) -> Result<()> {
    // The semantic key deliberately excludes format, page, context, and
    // colour. A trace is compiler output; text/JSON/DOT are renderers over
    // the same artifact and must not trigger another graph traversal.
    let max_depth = trace_opts.max_depth.to_string();
    let max_steps = trace_opts.max_steps.to_string();
    let max_branch_fanout = trace_opts.max_branch_fanout.to_string();
    let max_loop_iters = trace_opts.max_loop_iters.to_string();
    let filters_hash = paging::hash_filters(&[
        ("function", function.as_deref().unwrap_or("")),
        ("from", from.as_deref().unwrap_or("")),
        ("to", to.as_deref().unwrap_or("")),
        ("max_depth", max_depth.as_str()),
        ("max_steps", max_steps.as_str()),
        ("max_branch_fanout", max_branch_fanout.as_str()),
        ("max_loop_iters", max_loop_iters.as_str()),
    ]);
    let (project, _footer) = open_project(root)?;
    let ws = project.workspace();
    let cached_trace =
        match page_cache::read_keyed_payload::<TraceResult>(root, filters_hash, TRACE_SEMANTIC_CACHE_KIND) {
            Ok(cached) => cached,
            Err(error) => {
                tracing::debug!("ignoring unreadable trace semantic cache: {error}");
                None
            }
        };
    let trace = if let Some(cached) = cached_trace {
        cached
    } else {
        // Path enumeration walks the resolved call graph from the seed; on
        // big workspaces this can take many seconds before the first line
        // of output appears, so spin during traversal.
        let spin = progress::ScopedSpinner::new("walking call paths");
        let computed = match (&function, &from, &to) {
            (Some(f), None, None) => project
                .trace()
                .from_with_options(f, trace_opts)
                .map_err(|e| augment_not_found(e, ws, f))?,
            (None, Some(f), Some(t)) => project
                .trace()
                .source_to_sink_with_options(f, t, trace_opts)
                .map_err(|e| augment_source_or_sink_not_found(e, ws, f, t))?,
            _ => anyhow::bail!("specify --symbol <name> or a complete --from <name> --to <name> corridor"),
        };
        spin.finish();
        if let Err(error) =
            page_cache::save_keyed_payload(root, filters_hash, TRACE_SEMANTIC_CACHE_KIND, &computed)
        {
            tracing::debug!("trace semantic cache save failed: {error}");
        }
        computed
    };
    match format {
        OutputFormat::Json => {
            // Programmatic trace is token-budgeted by default. Keep
            // the native TraceResult shape when the full result fits
            // the first page; otherwise emit a page wrapper.
            if paging_cfg.json_wrapped() {
                let force_wrapper = paging_cfg.context.is_some()
                    || !matches!(paging_cfg.page, paging::PageArg::First)
                    || crate::filter::active().is_active();
                let page_rows = trace_page_rows(&trace);
                page_cache::emit_paged_text(
                    root,
                    &page_rows,
                    &paging_cfg,
                    "trace",
                    filters_hash,
                    |row| row.cost,
                    |slice, info, _cfg| {
                        if !force_wrapper && info.page_number == 1 && info.is_last {
                            cli_println!("{}", project.trace().to_json(&trace)?);
                            return Ok(());
                        }
                        let mut analysis_incomplete_reasons =
                            trace.summary.analysis_incomplete_reasons.clone();
                        analysis_incomplete_reasons.extend(trace.summary.truncation_reasons.iter().cloned());
                        if !trace.summary.analysis_complete && analysis_incomplete_reasons.is_empty() {
                            analysis_incomplete_reasons
                                .push("trace analysis incomplete: unknown reason".to_string());
                        }
                        analysis_incomplete_reasons.extend(paged_json_incomplete_reasons("trace", info));
                        analysis_incomplete_reasons.sort();
                        analysis_incomplete_reasons.dedup();
                        let path_ids = slice.iter().map(|row| row.path.path_id).collect::<BTreeSet<_>>();
                        let step_ids = slice
                            .iter()
                            .flat_map(|row| row.steps.iter().map(|step| step.id))
                            .collect::<BTreeSet<_>>();
                        let state_ids = slice
                            .iter()
                            .flat_map(|row| row.steps.iter())
                            .flat_map(|step| [step.state_before, step.state_after])
                            .flatten()
                            .collect::<BTreeSet<_>>();
                        let mut seen_paths = BTreeSet::new();
                        let paths = slice
                            .iter()
                            .filter_map(|row| seen_paths.insert(row.path.path_id).then_some(row.path))
                            .collect::<Vec<_>>();
                        let steps = slice
                            .iter()
                            .flat_map(|row| row.steps.iter().copied())
                            .collect::<Vec<_>>();
                        let edges = trace
                            .edges
                            .iter()
                            // Assign each edge to the page containing its
                            // destination. Cross-page boundary edges retain
                            // their global step ids and every exact edge is
                            // emitted once while pages are traversed.
                            .filter(|edge| step_ids.contains(&edge.to_step))
                            .collect::<Vec<_>>();
                        let states = trace
                            .states
                            .iter()
                            .filter(|state| state_ids.contains(&state.id))
                            .collect::<Vec<_>>();
                        let mut rendered_info = info.clone();
                        let wrapped = serde_json::json!({
                            "analysis_complete": analysis_incomplete_reasons.is_empty(),
                            "analysis_incomplete_reasons": analysis_incomplete_reasons,
                            "trace_id": &trace.trace_id,
                            "query": &trace.query,
                            "summary": &trace.summary,
                            "paths": paths,
                            "steps": steps,
                            "edges": edges,
                            "states": states,
                            "diagnostics": &trace.diagnostics,
                            "metadata": &trace.metadata,
                            "included_path_ids": path_ids,
                            "page": page_info_to_json(&rendered_info),
                        });
                        let first_render = serde_json::to_string_pretty(&wrapped)?;
                        rendered_info.tokens_used = paging::bytes_to_tokens(first_render.len() as u64 + 1);
                        let wrapped = serde_json::json!({
                            "analysis_complete": analysis_incomplete_reasons.is_empty(),
                            "analysis_incomplete_reasons": analysis_incomplete_reasons,
                            "trace_id": &trace.trace_id,
                            "query": &trace.query,
                            "summary": &trace.summary,
                            "paths": paths,
                            "steps": steps,
                            "edges": edges,
                            "states": states,
                            "diagnostics": &trace.diagnostics,
                            "metadata": &trace.metadata,
                            "included_path_ids": path_ids,
                            "page": page_info_to_json(&rendered_info),
                        });
                        cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
                        Ok(())
                    },
                )?;
            } else {
                cli_println!("{}", project.trace().to_json(&trace)?);
            }
        }
        OutputFormat::Text => {
            let lines = trace_text_lines(&trace, root, &trace.paths);
            page_cache::emit_paged_text(
                root,
                &lines,
                &paging_cfg,
                "trace",
                filters_hash,
                |line| line.len() as u64 + 128,
                |paged, info, _cfg| {
                    for line in paged {
                        cli_println!("{line}");
                    }
                    render_paging_footer(info, "bonsai-ninja trace <workspace> <symbol>");
                    Ok(())
                },
            )?;
        }
        OutputFormat::Dot => cli_print!("{}", project.trace().to_dot(&trace)),
    }
    Ok(())
}

fn trace_page_rows(trace: &TraceResult) -> Vec<TracePageRow<'_>> {
    trace
        .paths
        .iter()
        .flat_map(|path| {
            trace
                .steps
                .iter()
                .filter(move |step| step.path_id == path.path_id)
                .map(move |step| {
                    // Pretty JSON repeats indentation and field names around
                    // each step. Include conservative edge/state allowance so
                    // the selected page stays inside its render budget.
                    let serialized = serde_json::to_vec(step).map_or(0, |bytes| bytes.len());
                    TracePageRow {
                        path,
                        steps: vec![step],
                        cost: serialized.saturating_add(384) as u64,
                    }
                })
        })
        .collect()
}

/// CLI-themed text rendering for `trace`. Indents by call depth so the
/// reader sees the call tree shape, prints workspace-relative paths, and
/// uses the same `▸ flow` / `[module]` / source-snippet conventions as
/// `inspect`. Closes with a semantic precision summary.
///
/// `to_text` (in `bonsai_sdk::trace_render`) is still available for SDK
/// consumers that want a plain transcript without ANSI; this CLI path
/// is the one users hit by default.
fn trace_text_lines(
    trace: &TraceResult,
    workspace_root: &std::path::Path,
    paged_paths: &[PathSummary],
) -> Vec<String> {
    use TraceStepKind as K;
    let ui = ui();
    let mut lines = Vec::new();
    let entry_label = trace
        .query
        .entry_symbol
        .as_deref()
        .or(trace.query.target_symbol.as_deref())
        .unwrap_or("<unknown>");
    let sink_label = trace.query.sink_symbol.as_deref();
    let header = if let Some(sink) = sink_label {
        format!("▸ trace {} → {}", entry_label, sink)
    } else {
        format!("▸ trace {}", entry_label)
    };
    lines.push(String::new());
    lines.push(ui.heading(&header));
    lines.push(String::new());
    lines.push(format!(
        "  {} {}    {} {}    {} {}    {} {}",
        ui.label("language"),
        ui.name(&trace.summary.language),
        ui.label("paths"),
        ui.name(&trace.summary.explored_paths.to_string()),
        ui.label("steps"),
        ui.name(&trace.summary.total_steps.to_string()),
        ui.label("precision"),
        ui.name(&format!("{:?}", trace.summary.precision)),
    ));
    if trace.summary.truncated_paths > 0 {
        lines.push(format!(
            "  {} {}",
            ui.label("truncated paths"),
            ui.warn(&trace.summary.truncated_paths.to_string()),
        ));
    }
    if !trace.summary.analysis_complete {
        let mut reasons = trace.summary.truncation_reasons.clone();
        reasons.extend(trace.summary.analysis_incomplete_reasons.iter().cloned());
        reasons.sort();
        reasons.dedup();
        let reasons = summarize_incomplete_reasons(&reasons, 8);
        lines.extend(ui.wrapped_warn_labeled_lines("analysis incomplete", &reasons));
    }
    let ws_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());

    for path in paged_paths {
        lines.push(String::new());
        lines.push(format!(
            "{} {}  {}",
            ui.label("PATH"),
            ui.name(&path.path_id.to_string()),
            ui.dim(&format!(
                "[steps {}-{}, terminated by {:?}, precision {:?}]",
                path.first_step, path.last_step, path.terminated_by, path.precision
            )),
        ));
        lines.push(ui.ruler('─', 70));

        let mut depth: usize = 0;
        for step in trace.steps.iter().filter(|s| s.path_id == path.path_id) {
            // Adjust depth BEFORE printing for ExitFunction/Return so the
            // exit aligns with the matching enter.
            if matches!(step.kind, K::ExitFunction | K::Return) && depth > 0 {
                depth -= 1;
            }
            let indent = "  ".repeat(depth + 1);
            let (kind, label) = if step.precision.is_semantic() {
                (step.kind, step_label(step))
            } else {
                (
                    K::Diagnostic,
                    "Suppressed diagnostic-precision trace step".to_string(),
                )
            };
            let kind_tag = format!("[{}]", short_step_kind(kind));
            lines.push(format!(
                "{}{} {}  {}",
                indent,
                ui.kind(&kind_tag),
                ui.name(&label),
                ui.dim(&format_step_loc(
                    &step.span.file,
                    step.span.start_line,
                    step.span.start_col,
                    &ws_root
                )),
            ));
            // Indent FURTHER inside the function we just entered so
            // subsequent statements visibly nest under the call.
            if matches!(step.kind, K::EnterFunction | K::Call) {
                depth = depth.saturating_add(1);
                if matches!(step.kind, K::Call) && depth > 0 {
                    // Call alone doesn't enter a body in the trace
                    // sequence — the matching `EnterFunction` will. Undo
                    // the bump so we don't double-indent.
                    depth -= 1;
                }
            }
        }
    }

    let summary = summarize_precision(trace);
    lines.push(String::new());
    let non_semantic = summary.over_approximate.saturating_add(summary.unknown);
    let mut tally = format!(
        "{}  exact={}  narrowed={}",
        ui.label("precision tally"),
        ui.name(&summary.exact.to_string()),
        ui.name(&summary.narrowed.to_string()),
    );
    if non_semantic > 0 {
        tally.push_str(&format!(
            "  diagnostic-precision-suppressed={}",
            ui.warn(&non_semantic.to_string())
        ));
    }
    lines.push(tally);
    lines.push(String::new());
    lines
}

/// Compact `[tag]` shown in front of every trace step. Maps each
/// `TraceStepKind` to a short, lowercase identifier so the rendered
/// transcript stays scannable.
fn short_step_kind(kind: TraceStepKind) -> &'static str {
    use TraceStepKind as K;
    match kind {
        K::EnterFunction => "enter",
        K::ExitFunction => "exit",
        K::EvalExpr => "eval",
        K::Assign => "assign",
        K::LoadVariable => "load",
        K::StoreVariable => "store",
        K::BranchSplit => "branch",
        K::BranchTaken => "taken",
        K::LoopEnter => "loop",
        K::LoopIterate => "iter",
        K::LoopExit => "loop-exit",
        K::Call => "call",
        K::Return => "return",
        K::Throw => "throw",
        K::Catch => "catch",
        K::Await => "await",
        K::Yield => "yield",
        K::Lifecycle => "lifecycle",
        K::Merge => "merge",
        K::Diagnostic => "diag",
    }
}

/// Human-readable label for one trace step. Prefers the engine's
/// supplied message; otherwise synthesises one from the kind +
/// function name (e.g. `call os.system`, `return from handle_request`).
fn step_label(step: &TraceStep) -> String {
    use TraceStepKind as K;
    if !step.message.is_empty() {
        return step.message.clone();
    }
    match step.kind {
        K::EnterFunction => format!("enter {}", step.function),
        K::ExitFunction | K::Return => format!("return from {}", step.function),
        K::Call => format!("call {}", step.function),
        K::BranchSplit => "branch split".to_string(),
        other => format!("{other:?}"),
    }
}

/// Format a `(file, line, col)` triple as `(rel-path:line:col)`,
/// preferring workspace-relative paths so the trace stays readable
/// when the workspace root is deeply nested.
fn format_step_loc(file: &str, line: u32, col: u32, ws_root: &std::path::Path) -> String {
    let path = std::path::Path::new(file);
    // Synthesized spans can sit outside the workspace; fall back to the absolute path.
    let rel = path
        .strip_prefix(ws_root)
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| file.to_string());
    format!("({rel}:{line}:{col})")
}

/// Wrap a `SymbolNotFound` into a user-friendly "did you mean X" error;
/// pass other errors through unchanged.
fn augment_not_found(e: bonsai_sdk::WorkspaceError, ws: &Workspace, symbol: &str) -> anyhow::Error {
    if matches!(e, bonsai_sdk::WorkspaceError::SymbolNotFound(_)) {
        not_found_with_suggestions(ws, symbol)
    } else if let bonsai_sdk::WorkspaceError::AmbiguousSymbol {
        count, candidates, ..
    } = &e
    {
        ambiguous_symbol_error(symbol, *count, candidates)
    } else {
        anyhow::Error::from(e)
    }
}

/// Variant of [`augment_not_found`] for source-to-sink traces. Uses the
/// `SymbolNotFound` error's own payload so the suggestion we print is
/// for the symbol that actually failed to resolve, not the other side
/// of the pair.
fn augment_source_or_sink_not_found(
    e: bonsai_sdk::WorkspaceError,
    ws: &Workspace,
    _from: &str,
    _to: &str,
) -> anyhow::Error {
    match &e {
        bonsai_sdk::WorkspaceError::SymbolNotFound(name) => {
            let which = name.clone();
            not_found_with_suggestions(ws, &which)
        }
        bonsai_sdk::WorkspaceError::AmbiguousSymbol {
            query,
            count,
            candidates,
        } => ambiguous_symbol_error(query, *count, candidates),
        _ => anyhow::Error::from(e),
    }
}

fn ambiguous_symbol_error(symbol: &str, count: usize, candidates: &[String]) -> anyhow::Error {
    let preview = candidates
        .iter()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n  ");
    anyhow::anyhow!(
        "trace: symbol `{symbol}` is ambiguous ({count} callable decls). \
         Use path:name or path:line:name.\n  {preview}"
    )
}

pub(crate) fn not_found_with_suggestions(ws: &Workspace, symbol: &str) -> anyhow::Error {
    let needle = symbol.to_lowercase();
    let global = ws.compiler_linkage_index();
    // Collect all candidate names with a similarity score. Higher score =
    // more relevant. Combines: substring containment (either direction),
    // shared-prefix length, and normalized Levenshtein.
    let mut scored: Vec<(i32, String)> = Vec::new();
    for f in global.all_files() {
        for d in global.decls_in(f) {
            let n = &d.name;
            let nl = n.to_lowercase();
            let prefix = common_prefix_len(&nl, &needle);
            let contains_ab = nl.contains(&needle);
            let contains_ba = needle.contains(&nl) && nl.len() >= 3;
            let max_len = nl.len().max(needle.len()) as i32;
            let dist = levenshtein(&nl, &needle) as i32;
            let ratio = if max_len == 0 {
                0
            } else {
                (max_len - dist) * 100 / max_len
            };
            let mut score = 0;
            if contains_ab {
                score += 80;
            }
            if contains_ba {
                score += 60;
            }
            score += (prefix as i32) * 10;
            score += ratio;
            if score >= 30 {
                scored.push((score, n.clone()));
            }
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.len().cmp(&b.1.len())));
    scored.dedup_by(|a, b| a.1 == b.1);
    if scored.is_empty() {
        anyhow::anyhow!("symbol not found: {symbol}")
    } else {
        anyhow::anyhow!(
            "symbol not found: {symbol}\n  did you mean: {}",
            scored
                .iter()
                .take(8)
                .map(|(_, n)| n.clone())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Number of leading characters two strings share. Powers the
/// "did you mean" prefix-bias heuristic.
fn common_prefix_len(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

/// Return up to `limit` workspace decl names that look similar to
/// `symbol`, sorted by relevance. Shares the scoring heuristic with
/// [`not_found_with_suggestions`] but returns the names instead of
/// formatting them into an error.
pub(crate) fn nearest_names(ws: &Workspace, symbol: &str, limit: usize) -> Vec<String> {
    let needle = symbol.to_lowercase();
    let global = ws.compiler_linkage_index();
    let mut scored: Vec<(i32, String)> = Vec::new();
    for f in global.all_files() {
        for d in global.decls_in(f) {
            let nl = d.name.to_lowercase();
            let prefix = common_prefix_len(&nl, &needle);
            let max_len = nl.len().max(needle.len()) as i32;
            let dist = levenshtein(&nl, &needle) as i32;
            let ratio = if max_len == 0 {
                0
            } else {
                (max_len - dist) * 100 / max_len
            };
            let mut score = 0;
            if nl.contains(&needle) {
                score += 80;
            }
            if needle.contains(&nl) && nl.len() >= 3 {
                score += 60;
            }
            score += (prefix as i32) * 10;
            score += ratio;
            if score >= 30 {
                scored.push((score, d.name.clone()));
            }
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.len().cmp(&b.1.len())));
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(limit).map(|(_, n)| n).collect()
}

/// Classic two-row Levenshtein edit distance over byte slices. Used
/// only for ranking suggestion candidates, so byte-level is fine.
fn levenshtein(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0; b.len() + 1];
    for left_index in 1..=a.len() {
        curr[0] = left_index;
        for right_index in 1..=b.len() {
            let cost = usize::from(a[left_index - 1] != b[right_index - 1]);
            curr[right_index] = (prev[right_index] + 1)
                .min(curr[right_index - 1] + 1)
                .min(prev[right_index - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

#[cfg(test)]
#[path = "trace_tests.rs"]
mod tests;
