//! `bonsai-ninja dump-edges` data layer.
//!
//! One [`EdgeRecord`] per resolved call edge in the workspace.
//! Same resolution pass [`bonsai_callgraph::ResolvedCallGraph::build_with`]
//! does, but each record carries the call-site span so consumers can
//! jump to the exact `FlowEvent::Call` that produced the edge.

use crate::common::format_span;
use bonsai_callgraph::{collect_callable_targets, short_callee};
use bonsai_hash::fnv1a_names_low32;
use bonsai_lang_api::{CallArg, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Stable, library-level mirror of `bonsai_common::Precision`.
/// Filtering across the FFI boundary uses this enum so frontends
/// don't need to depend on `bonsai_common` directly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrecisionClass {
    Exact,
    Narrowed,
    OverApproximate,
    Unknown,
}

impl PrecisionClass {
    /// Parse the public string form (`"exact"` / `"narrowed"` /
    /// `"over-approximate"` / `"unknown"`) back to the enum.
    /// Unknown spellings map to [`Self::Unknown`] so a caller can
    /// stay open-ended without unwrapping.
    #[must_use]
    pub fn from_label(s: &str) -> Self {
        match s {
            "exact" => Self::Exact,
            "narrowed" => Self::Narrowed,
            "over-approximate" => Self::OverApproximate,
            _ => Self::Unknown,
        }
    }
    /// Compare an external [`PrecisionClass`] filter against the
    /// internal [`bonsai_common::Precision`] tag carried on every
    /// resolved edge.
    pub fn matches(self, precision: bonsai_common::Precision) -> bool {
        use bonsai_common::Precision;
        matches!(
            (self, precision),
            (Self::Exact, Precision::Exact)
                | (Self::Narrowed, Precision::Narrowed)
                | (Self::OverApproximate, Precision::OverApproximate)
                | (Self::Unknown, Precision::Unknown)
        )
    }
}

/// Filter bundle for [`dump_edges`]. Match-anywhere semantics on
/// `from`/`to`; an `edge_id` filter narrows to a single edge.
#[derive(Copy, Clone, Default, Debug)]
pub struct EdgesFilters<'a> {
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub precision: Option<PrecisionClass>,
    pub edge_id: Option<&'a str>,
}

/// One resolved call edge. `call_*` fields point at the
/// `FlowEvent::Call` span; `caller_*` / `callee_*` point at the
/// decl name spans. `kind` is `direct` / `virtual`; `precision` is
/// `exact` / `narrowed` / `over-approximate` / `unknown` (string
/// form so JSON consumers don't need a typed enum).
#[derive(Serialize, Clone, Debug)]
pub struct EdgeRecord {
    pub edge_id: String,
    pub caller_name: String,
    pub caller_file: String,
    pub caller_line: u32,
    pub callee_name: String,
    pub callee_file: String,
    pub callee_line: u32,
    pub call_file: String,
    pub call_line: u32,
    pub call_column: u32,
    pub call_text: String,
    pub kind: String,
    pub precision: String,
}

/// Stable content-hash id for one resolved call edge: `E:` + 8 hex
/// chars (low 32 bits of FNV-1a-64) over `(caller, callee,
/// call_site)`. Same hash family as the inspect flow / group ids.
#[must_use]
pub fn compute_edge_id(
    caller_name: &str,
    callee_name: &str,
    call_file: &str,
    call_line: u32,
    call_column: u32,
) -> String {
    let call_site_token = format!("{call_file}:{call_line}:{call_column}");
    let tokens = [caller_name.to_string(), callee_name.to_string(), call_site_token];
    format!("E:{:08x}", fnv1a_names_low32(&tokens))
}

/// Collect every resolved call edge in the workspace, then apply
/// the filters. Sorted weakest-precision-first so a `--precision
/// over-approximate` (or unfiltered) caller sees the most
/// review-worthy edges at the top.
pub fn dump_edges(ws: &Workspace, f: &EdgesFilters<'_>) -> Vec<EdgeRecord> {
    use rayon::prelude::*;
    let global = ws.db().global_index();
    let files: Vec<_> = global.all_files().collect();
    // Parallel file walk. Each file parses once (cached), produces
    // its alias map, and emits edges for every decl. Rayon merges
    // per-file Vecs; the explicit sort at the bottom gives
    // deterministic output regardless of worker order.
    //
    // TypeScript compiler (452k LOC) dropped from 36s → ~7s here.
    let mut records: Vec<EdgeRecord> = files
        .par_iter()
        .fold(Vec::new, |mut acc, &file| {
            // One alias map per file (imported-name → resolved
            // module export). Built once and shared across all
            // decls in the file so we don't re-scan imports per
            // call site.
            let alias_map = bonsai_resolve::alias_map_for_file(&ws.db().imports_for(file));
            for decl in global.decls_in(file) {
                let caller_name = decl.name.clone();
                let (caller_file, caller_line, _) = format_span(&decl.name_span, ws);
                collect_edges_in_events(
                    &decl.flow_events,
                    &caller_name,
                    &caller_file,
                    caller_line,
                    &alias_map,
                    ws,
                    global.as_ref(),
                    &mut acc,
                );
            }
            acc
        })
        .reduce(Vec::new, |mut larger, mut smaller| {
            if smaller.len() > larger.len() {
                std::mem::swap(&mut larger, &mut smaller);
            }
            larger.extend(smaller);
            larger
        });
    records.retain(|edge| {
        f.from.is_none_or(|needle| edge.caller_name.contains(needle))
            && f.to.is_none_or(|needle| edge.callee_name.contains(needle))
            && f.precision
                .is_none_or(|p| p.matches(PrecisionClass::from_label(&edge.precision).into_precision()))
            && f.edge_id.is_none_or(|id| edge.edge_id == id)
    });
    records.sort_by(|a, b| {
        precision_sort_key(&a.precision)
            .cmp(&precision_sort_key(&b.precision))
            .then_with(|| a.caller_name.cmp(&b.caller_name))
            .then_with(|| a.callee_name.cmp(&b.callee_name))
            .then_with(|| a.call_line.cmp(&b.call_line))
    });
    records
}

impl PrecisionClass {
    /// Convert the public class enum back to the internal
    /// `bonsai_common::Precision` so the filter can be matched
    /// against the resolver's per-edge precision tag.
    fn into_precision(self) -> bonsai_common::Precision {
        match self {
            Self::Exact => bonsai_common::Precision::Exact,
            Self::Narrowed => bonsai_common::Precision::Narrowed,
            Self::OverApproximate => bonsai_common::Precision::OverApproximate,
            Self::Unknown => bonsai_common::Precision::Unknown,
        }
    }
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn collect_edges_in_events(
    events: &[FlowEvent],
    caller_name: &str,
    caller_file: &str,
    caller_line: u32,
    aliases: &ahash::AHashMap<String, String>,
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    out: &mut Vec<EdgeRecord>,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, span, args, .. } => {
                let short = short_callee(name);
                // Apply the file's import aliases first so
                // `import { exec } from "child_process"` resolves
                // `exec(...)` to `child_process.exec`.
                let resolved_name = aliases.get(short).map(String::as_str).unwrap_or(short);
                let mut candidates = collect_callable_targets(global, resolved_name);
                // Fallback: try the original (qualified) name when
                // alias rewriting produced nothing. Catches calls
                // like `Foo.bar(...)` where `bar` alone has no
                // workspace target but `Foo.bar` does.
                if candidates.is_empty() && resolved_name != name.as_str() {
                    candidates = collect_callable_targets(global, name);
                }
                if candidates.is_empty() {
                    continue;
                }
                // One target = direct/narrowed; several = virtual/
                // over-approximate (the resolver couldn't pick a
                // single decl from name alone).
                let (kind, precision) = if candidates.len() == 1 {
                    ("direct".to_string(), "narrowed".to_string())
                } else {
                    ("virtual".to_string(), "over-approximate".to_string())
                };
                let (call_file, call_line, call_column) = format_span(span, ws);
                let call_text = render_call_preview(name, args);
                for callee_func in candidates {
                    let callee_decl = global.decl_of(bonsai_common::SymbolId::new(callee_func.raw()));
                    let (callee_file, callee_line) = if let Some(decl) = callee_decl {
                        let (path, line, _) = format_span(&decl.name_span, ws);
                        (path, line)
                    } else {
                        ("<unknown>".to_string(), 0)
                    };
                    let callee_name =
                        callee_decl.map_or_else(|| resolved_name.to_string(), |decl| decl.name.clone());
                    let edge_id =
                        compute_edge_id(caller_name, &callee_name, &call_file, call_line, call_column);
                    out.push(EdgeRecord {
                        edge_id,
                        caller_name: caller_name.to_string(),
                        caller_file: caller_file.to_string(),
                        caller_line,
                        callee_name,
                        callee_file,
                        callee_line,
                        call_file: call_file.clone(),
                        call_line,
                        call_column,
                        call_text: call_text.clone(),
                        kind: kind.clone(),
                        precision: precision.clone(),
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_edges_in_events(
                    then_events,
                    caller_name,
                    caller_file,
                    caller_line,
                    aliases,
                    ws,
                    global,
                    out,
                );
                collect_edges_in_events(
                    else_events,
                    caller_name,
                    caller_file,
                    caller_line,
                    aliases,
                    ws,
                    global,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_edges_in_events(
                    body,
                    caller_name,
                    caller_file,
                    caller_line,
                    aliases,
                    ws,
                    global,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_edges_in_events(
                    body,
                    caller_name,
                    caller_file,
                    caller_line,
                    aliases,
                    ws,
                    global,
                    out,
                );
                collect_edges_in_events(
                    catch_events,
                    caller_name,
                    caller_file,
                    caller_line,
                    aliases,
                    ws,
                    global,
                    out,
                );
                collect_edges_in_events(
                    finally_events,
                    caller_name,
                    caller_file,
                    caller_line,
                    aliases,
                    ws,
                    global,
                    out,
                );
            }
            _ => {}
        }
    }
}

/// Build the `name(arg1, key=arg2, ...)` preview string we attach
/// to each edge so a reader can see the actual call without
/// re-opening the source file. Truncated at 80 bytes (UTF-8
/// safe) so a long argument list never wrecks the table layout.
fn render_call_preview(name: &str, args: &[CallArg]) -> String {
    let arg_display: Vec<String> = args
        .iter()
        .map(|arg| match arg.name.as_deref() {
            Some(keyword) => format!("{keyword}={}", arg.value_text),
            None => arg.value_text.clone(),
        })
        .collect();
    let rendered = format!("{name}({})", arg_display.join(", "));
    crate::common::truncate_at_char_boundary(&rendered, 80, "...")
}

/// Lower number = weaker precision; weaker edges sort first so
/// `--precision over-approximate` (or unfiltered) shows the most
/// review-worthy edges at the top of the table.
fn precision_sort_key(precision: &str) -> u8 {
    match precision {
        "unknown" => 0,
        "over-approximate" => 1,
        "narrowed" => 2,
        "exact" => 3,
        _ => 4,
    }
}
