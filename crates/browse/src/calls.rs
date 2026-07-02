//! `bonsai-ninja calls` data layer.
//!
//! Returns every syntactic call site in the workspace, filtered by
//! callee text / caller / file / call-kind. This is not a resolved
//! callgraph edge surface; semantic caller→callee edges live in
//! `dump-edges` and exports. Combines two passes — flow-event calls
//! (carry the enclosing function and call kind) and ref-table calls
//! (catches module-level / non-decl calls the flow-event walker
//! doesn't reach).

use crate::common::{file_path_matches_filter, format_span, make_name_filter, textual_relevance_key};
use bonsai_lang_api::{FlowEvent, RefKind};
use bonsai_workspace::Workspace;
use serde::Serialize;

pub(crate) const CALLSITE_RESOLUTION_SCOPE: &str = "syntactic-call-site";

/// Filter bundle for [`calls`]. All fields optional; `None` skips
/// that filter. `regex` controls how `callee` and `caller` are
/// interpreted.
#[derive(Copy, Clone, Default, Debug)]
pub struct CallsFilters<'a> {
    /// `--callee X` — substring (or regex) over the callee text
    /// (`os.system`, `cursor.execute`).
    pub callee: Option<&'a str>,
    /// `--file substring` against the call site's source path.
    pub file: Option<&'a str>,
    /// `--caller X` — substring over the enclosing function's
    /// name. `None` matches every caller including module-level
    /// calls (which have no enclosing function).
    pub caller: Option<&'a str>,
    /// `--call-kind` filter (`function`, `method`, `constructor`,
    /// `dynamic` …) — case-insensitive equality against the
    /// adapter-emitted [`bonsai_lang_api::CallKind`] tag.
    pub call_kind: Option<&'a str>,
    /// Treat `callee` / `caller` as regexes instead of substrings.
    pub regex: bool,
}

/// One row of `calls` output. Field names match the JSON schema
/// the CLI emits.
#[derive(Serialize, Clone, Debug)]
pub struct CallOut {
    /// Explicitly declares that this row is a call-site inventory fact,
    /// not a resolved semantic caller→callee edge.
    pub resolution_scope: &'static str,
    /// Callee text as written at the call site (`os.system`,
    /// `self.execute`).
    pub callee: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    /// Enclosing function name when the call lives in a function
    /// body; `None` for module-level / top-of-file calls
    /// (Python script statements, JS top-level `require(...)`).
    pub caller: Option<String>,
    /// Adapter-emitted call kind (`function`, `method`,
    /// `constructor`, `dynamic`, …). `None` for refs surfaced via
    /// the ref-table fallback (see the two-pass note below).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_kind: Option<String>,
}

/// Collect every call site matching the filters. Sorted by `(file,
/// line, callee)` and de-duplicated on `(callee, file, line, col)`
/// — the flow-event and ref-table passes can both surface the same
/// call.
pub fn calls(ws: &Workspace, f: &CallsFilters<'_>) -> Result<Vec<CallOut>, regex::Error> {
    use rayon::prelude::*;
    let global = ws.db().global_index();
    let callee_match = make_name_filter(f.callee, f.regex)?;
    let files: Vec<_> = global.all_files().collect();
    // `fold` accumulates per-thread (not per-file) so we don't pay
    // the per-file `Vec` allocation cost — `calls` on hub names
    // like TypeScript's `visitNode` produces millions of records,
    // and the per-file allocator overhead drowned out parallelism
    // with the naive `flat_map_iter` shape. `fold` + `reduce` keeps
    // each thread's accumulator hot and merges only at the end.
    let mut out: Vec<CallOut> = files
        .par_iter()
        .fold(Vec::new, |mut acc, &file| {
            // Pass 1 — flow-event walk per decl. Carries the
            // enclosing function name so the row's `caller` is
            // populated.
            for decl in global.decls_in(file) {
                walk_calls(&decl.flow_events, Some(decl.name.clone()), ws, &mut acc);
            }
            // Pass 2 — ref-table fallback. Catches module-level /
            // top-of-file calls (Python script statements, JS
            // top-level `require(...)`) the flow-event walker doesn't
            // reach because they live outside any decl.
            if let Some(idx) = global.file_index(file) {
                // Some adapters emit a synthetic `RefKind::Call` for
                // bare-identifier subscript receivers (`params[:x]`,
                // `row[0]`) so security rules shaped as
                // `kind: call callee.name: params` fire on framework-
                // DSL idioms. That's the right shape for rule
                // matching, but for the human-facing `calls` table it
                // produces noise rows like `row` in `return row[0]`.
                // Drop any Call ref at a span where a matching Read
                // ref exists — that's the signature of the subscript-
                // DSL synthesis (every real call emits only the Call
                // ref, never both). Indexed lookups stay O(1) via a
                // HashSet keyed on `(span.start, span.end)`.
                let read_spans: ahash::AHashSet<(u64, u64)> = idx
                    .refs
                    .iter()
                    .filter(|reference| reference.kind == RefKind::Read)
                    .map(|reference| (reference.span.start, reference.span.end))
                    .collect();
                for reference in &idx.refs {
                    if reference.kind == RefKind::Call
                        && !read_spans.contains(&(reference.span.start, reference.span.end))
                    {
                        let (path, line, column) = format_span(&reference.span, ws);
                        acc.push(CallOut {
                            resolution_scope: CALLSITE_RESOLUTION_SCOPE,
                            callee: normalize_whitespace(&reference.name),
                            file: path,
                            line,
                            column,
                            caller: None,
                            call_kind: None,
                        });
                    }
                }
            }
            acc
        })
        .reduce(Vec::new, |mut larger, mut smaller| {
            // Cheaper to extend the larger vec with the smaller.
            if smaller.len() > larger.len() {
                std::mem::swap(&mut larger, &mut smaller);
            }
            larger.extend(smaller);
            larger
        });
    out.retain(|call| {
        if f.file
            .is_some_and(|needle| !file_path_matches_filter(ws, &call.file, needle))
        {
            return false;
        }
        if !callee_match(&call.callee) {
            return false;
        }
        if let Some(needle) = f.caller {
            if !call.caller.as_deref().is_some_and(|s| s.contains(needle)) {
                return false;
            }
        }
        if let Some(want_kind) = f.call_kind {
            if !call
                .call_kind
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(want_kind))
            {
                return false;
            }
        }
        true
    });
    drop_assignment_call_rows_shadowed_by_explicit_calls(&mut out);
    // Dedup pass first: the flow-event walk and the ref-table scan
    // both surface the same physical call (flow-event knows the
    // enclosing function, ref-table doesn't), producing two rows at
    // the same `(callee, file, line, col)` — one with `caller=Some`,
    // one with `caller=None`. Sort so duplicates are adjacent AND
    // named-caller rows come first (`is_none` is `false` for
    // `Some`, so `Some` sorts ahead of `None`); `dedup_by` keeps the
    // first, which drops the bogus `-` row.
    out.sort_by(|a, b| {
        a.callee
            .cmp(&b.callee)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.caller.is_none().cmp(&b.caller.is_none()))
    });
    out.dedup_by(|a, b| a.callee == b.callee && a.file == b.file && a.line == b.line && a.column == b.column);
    // Stage 2 dedup: qualified vs. bare-name collision at the same
    // `(file, line, col)`. The flow-event walk emits the fully-
    // qualified callee (`Runtime.getRuntime().exec`) while the ref
    // table emits only the final segment (`exec`). When both sit
    // at the same column they describe the same physical call; the
    // bare form is noise because the qualified form contains it as
    // a `.`-separated suffix. Keep the longest dominant form.
    out.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| b.callee.len().cmp(&a.callee.len()))
    });
    let mut collapsed: Vec<CallOut> = Vec::with_capacity(out.len());
    for row in out {
        let drop = collapsed.last().is_some_and(|prev| {
            prev.file == row.file
                && prev.line == row.line
                && prev.column == row.column
                && is_bare_suffix_of(&row.callee, &prev.callee)
        });
        if drop {
            continue;
        }
        collapsed.push(row);
    }
    let mut out = collapsed;
    // Final display order: group by callee, then by caller for
    // readable per-target clustering, then file/line tiebreakers.
    let callee_rank = |call: &CallOut| {
        if f.callee.is_some() && !f.regex {
            textual_relevance_key(&call.callee, f.callee, false)
        } else {
            (u8::MAX, usize::MAX)
        }
    };
    let caller_rank = |call: &CallOut| {
        if f.caller.is_some() && !f.regex {
            call.caller.as_deref().map_or((u8::MAX, usize::MAX), |caller| {
                textual_relevance_key(caller, f.caller, false)
            })
        } else {
            (u8::MAX, usize::MAX)
        }
    };
    out.sort_by(|a, b| {
        callee_rank(a)
            .cmp(&callee_rank(b))
            .then_with(|| caller_rank(a).cmp(&caller_rank(b)))
            .then_with(|| {
                a.callee
                    .cmp(&b.callee)
                    .then_with(|| a.caller.cmp(&b.caller))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
            })
    });
    Ok(out)
}

/// Drop rows synthesized from `Assign.source_call` when an explicit
/// `Call` event already exists at the same `(callee, file, line,
/// caller)`. Both forms carry real evidence used by analyses
/// (Assign for return-taint, Call for arg propagation), but the
/// browse output is a deduplicated display. The dedup belongs in
/// the browse layer because both fact shapes are still needed by
/// downstream analyses.
fn drop_assignment_call_rows_shadowed_by_explicit_calls(out: &mut Vec<CallOut>) {
    let explicit_calls: ahash::AHashSet<(String, String, u32, Option<String>)> = out
        .iter()
        .filter(|row| row.call_kind.is_some())
        .map(|row| (row.callee.clone(), row.file.clone(), row.line, row.caller.clone()))
        .collect();
    out.retain(|row| {
        row.call_kind.is_some()
            || !explicit_calls.contains(&(row.callee.clone(), row.file.clone(), row.line, row.caller.clone()))
    });
}

/// Collapse every run of whitespace (spaces, tabs, newlines) in
/// `raw` into a single space so a multi-line Rust / Swift method
/// chain displayed as a callee stays on one line. Matches the
/// kit-level helper used at FlowEvent construction, but applied
/// here too for defence in depth — any Call event that slips
/// through without normalisation still renders cleanly.
fn normalize_whitespace(raw: &str) -> String {
    let mut collapsed = String::with_capacity(raw.len());
    let mut prev_was_ws = false;
    for ch in raw.chars() {
        if ch.is_whitespace() {
            if !prev_was_ws && !collapsed.is_empty() {
                collapsed.push(' ');
                prev_was_ws = true;
            } else if collapsed.is_empty() {
                // Leading whitespace: skip entirely.
                prev_was_ws = true;
            }
        } else {
            collapsed.push(ch);
            prev_was_ws = false;
        }
    }
    if collapsed.ends_with(' ') {
        collapsed.pop();
    }
    collapsed
}

/// True when `bare` is either equal to `qualified` or appears as a
/// trailing segment after a language-member separator — `.` (most
/// languages), `->` (PHP / C / C++ pointer-access), or `::` (Rust
/// / C++ namespace). Matches the adapter forms we see in practice:
/// `exec` vs. `Runtime.getRuntime().exec`, `close` vs. `$conn->close`,
/// `Vec::new` vs. `std::vec::Vec::new`.
fn is_bare_suffix_of(bare: &str, qualified: &str) -> bool {
    if bare == qualified {
        return true;
    }
    if qualified.len() <= bare.len() || !qualified.ends_with(bare) {
        return false;
    }
    let head = &qualified[..qualified.len() - bare.len()];
    head.ends_with('.') || head.ends_with("->") || head.ends_with("::")
}

/// Recursively walk a decl's flow events, pushing one [`CallOut`]
/// per `FlowEvent::Call` and per `FlowEvent::Assign` whose RHS is
/// a call. `caller` is the enclosing function's name so each row
/// can name its container.
fn walk_calls(events: &[FlowEvent], caller: Option<String>, ws: &Workspace, out: &mut Vec<CallOut>) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                call_kind,
                ..
            } => {
                let (path, line, column) = format_span(span, ws);
                out.push(CallOut {
                    resolution_scope: CALLSITE_RESOLUTION_SCOPE,
                    callee: normalize_whitespace(name),
                    file: path,
                    line,
                    column,
                    caller: caller.clone(),
                    call_kind: Some(format!("{:?}", call_kind).to_lowercase()),
                });
            }
            FlowEvent::Assign {
                span,
                source_call: Some(name),
                ..
            } => {
                // RHS-of-assign call: `x = foo()`. We emit a row
                // without a `call_kind` so the dedup pass can drop
                // it when an explicit `Call` row covers the same
                // call site.
                let (path, line, column) = format_span(span, ws);
                out.push(CallOut {
                    resolution_scope: CALLSITE_RESOLUTION_SCOPE,
                    callee: normalize_whitespace(name),
                    file: path,
                    line,
                    column,
                    caller: caller.clone(),
                    call_kind: None,
                });
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_calls(then_events, caller.clone(), ws, out);
                walk_calls(else_events, caller.clone(), ws, out);
            }
            FlowEvent::Loop { body, .. } => walk_calls(body, caller.clone(), ws, out),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_calls(body, caller.clone(), ws, out);
                walk_calls(catch_events, caller.clone(), ws, out);
                walk_calls(finally_events, caller.clone(), ws, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk_calls(body, caller.clone(), ws, out);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "calls_tests.rs"]
mod tests;
