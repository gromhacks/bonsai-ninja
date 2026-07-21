//! Structured per-hop source evidence shared by the text flow renderer and
//! the JSON/SARIF serializers. Each hop carries its full function body as
//! numbered lines, with `step`/`role` set on the lines that bear a flow
//! event - the same code and annotations the terminal view prints, so
//! machine-readable output embeds the evidence rather than just the chain.

use ahash::AHashMap;
use bonsai_common::{cached_span_map_arc, FuncId, SymbolId};
use bonsai_workspace::Workspace;
use serde::{Deserialize, Serialize};

use crate::finding::{FindingMatch, TaintPropagationStep};

/// Role a flow step plays on the line it annotates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowRole {
    Source,
    Taint,
    Sink,
}

/// One source line within a hop body. `step`/`role` are present only on the
/// lines that carry a flow event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowSourceLine {
    pub n: u32,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<FlowRole>,
}

/// One function along the flow, with its full body as numbered lines.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowFunctionBody {
    pub function: String,
    /// Workspace-relative module path, matching the text view's header.
    pub file: String,
    pub start_line: u32,
    pub lines: Vec<FlowSourceLine>,
}

#[derive(Clone, Debug)]
struct CachedFunctionBody {
    function: String,
    file: String,
    start_line: u32,
    end_line: u32,
    lines: Vec<FlowSourceLine>,
}

/// Per-analysis cache for flow evidence source bodies.
///
/// Large taint reports often contain thousands of findings over the same
/// handful of functions. Caching the unannotated function body avoids
/// repeatedly snapshotting and splitting identical files while keeping the
/// final annotated `FlowFunctionBody` output unchanged.
pub struct FlowBodyCache<'a> {
    ws: &'a Workspace,
    bodies: AHashMap<FuncId, Option<CachedFunctionBody>>,
}

impl<'a> FlowBodyCache<'a> {
    pub fn new(ws: &'a Workspace) -> Self {
        Self {
            ws,
            bodies: AHashMap::new(),
        }
    }

    fn cached_body(&mut self, func: FuncId) -> Option<&CachedFunctionBody> {
        if !self.bodies.contains_key(&func) {
            let body = build_cached_function_body(self.ws, func);
            self.bodies.insert(func, body);
        }
        self.bodies.get(&func).and_then(Option::as_ref)
    }

    /// Build the per-hop function bodies for a resolved flow.
    ///
    /// This is the cached equivalent of [`build_flow_bodies`].
    pub fn build_flow_bodies(
        &mut self,
        chain_funcs: &[FuncId],
        source: &FindingMatch,
        taint_path: &[TaintPropagationStep],
        terminal_role: FlowRole,
    ) -> Vec<FlowFunctionBody> {
        if chain_funcs.is_empty() {
            return Vec::new();
        }
        // Resolve every hop body first; events are then placed by file +
        // line-range containment, not by position. `normalize_taint_path`
        // collapses same-line steps, so the path can be shorter than the
        // chain and a positional zip would house annotations in the wrong
        // hop (or drop the sink annotation entirely).
        let mut hops: Vec<CachedFunctionBody> = chain_funcs
            .iter()
            .filter_map(|func| self.cached_body(*func).cloned())
            .collect();

        // Flow events in dataflow order: the source read first, then each
        // propagation step; the final step carries `terminal_role`.
        let mut events: Vec<(usize, u32, FlowRole)> = Vec::new();
        if source.line > 0 {
            if let Some(idx) = hop_index_for(&hops, &source.file, source.line, source.enclosing_fn.as_deref())
            {
                events.push((idx, source.line, FlowRole::Source));
            }
        }
        let last_step = taint_path.len().saturating_sub(1);
        for (idx, call) in taint_path.iter().enumerate() {
            let role = if idx == last_step {
                terminal_role
            } else {
                FlowRole::Taint
            };
            if let Some(hop) = hop_index_for(&hops, &call.file, call.line, Some(&call.caller)) {
                events.push((hop, call.line, role));
            }
        }
        // A line can bear several events (a source read feeding a sink
        // call on the same line). One annotation per line: the strongest
        // role wins so the sink marker is never silently dropped.
        let mut placed: Vec<(usize, u32, FlowRole)> = Vec::new();
        for (hop, line, role) in events {
            if let Some(existing) = placed.iter_mut().find(|p| p.0 == hop && p.1 == line) {
                if role_strength(role) > role_strength(existing.2) {
                    existing.2 = role;
                }
            } else {
                placed.push((hop, line, role));
            }
        }
        for (step, (hop, line, role)) in placed.into_iter().enumerate() {
            annotate_line(&mut hops[hop].lines, line, role, step as u32 + 1);
        }

        hops.into_iter()
            .map(|cached| FlowFunctionBody {
                function: cached.function,
                file: cached.file,
                start_line: cached.start_line,
                lines: cached.lines,
            })
            .collect()
    }
}

/// Hop whose body contains `file:line`. Prefers the hop matching the
/// event's enclosing/caller function (bare name, `@file:line` suffix
/// stripped), then the narrowest containing body so nested closures
/// beat their parents.
fn hop_index_for(
    hops: &[CachedFunctionBody],
    file: &str,
    line: u32,
    enclosing: Option<&str>,
) -> Option<usize> {
    let contains = |hop: &CachedFunctionBody| {
        same_file(&hop.file, file) && line >= hop.start_line && line <= hop.end_line
    };
    let candidates: Vec<usize> = hops
        .iter()
        .enumerate()
        .filter(|(_, hop)| contains(hop))
        .map(|(idx, _)| idx)
        .collect();
    if let Some(name) = enclosing {
        let bare = name.split('@').next().unwrap_or(name);
        if let Some(&idx) = candidates.iter().find(|&&idx| hops[idx].function == bare) {
            return Some(idx);
        }
    }
    candidates
        .into_iter()
        .min_by_key(|&idx| hops[idx].end_line - hops[idx].start_line)
}

/// Paths come from the same VFS so they normally compare equal; accept a
/// path-component suffix so relative/absolute spellings still match.
fn same_file(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let (long, short) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    !short.is_empty() && long.ends_with(short) && long[..long.len() - short.len()].ends_with(['/', '\\'])
}

/// Sink > Source > Taint when several events share one line.
fn role_strength(role: FlowRole) -> u8 {
    match role {
        FlowRole::Sink => 3,
        FlowRole::Source => 2,
        FlowRole::Taint => 1,
    }
}

/// Set the step/role on the first un-annotated line matching `line`.
fn annotate_line(lines: &mut [FlowSourceLine], line: u32, role: FlowRole, step: u32) {
    if let Some(slot) = lines.iter_mut().find(|l| l.n == line && l.role.is_none()) {
        slot.step = Some(step);
        slot.role = Some(role);
    }
}

fn build_cached_function_body(ws: &Workspace, func: FuncId) -> Option<CachedFunctionBody> {
    let decl = ws.exact_decl(SymbolId::new(func.raw()))?;
    let file = decl.span.file;
    let snapshot = ws.vfs().snapshot(file).ok()?;
    let src = snapshot.text.as_ref();
    let span_map = cached_span_map_arc(file, snapshot.version, &snapshot.text);
    let body_span = decl.body_span.unwrap_or(decl.span);
    let header_line = span_map.line_col(decl.name_span.start).line;
    let start_line = span_map.line_col(body_span.start).line;
    let end_line = span_map.line_col(body_span.end.saturating_sub(1)).line;
    let first_line = header_line.min(start_line);

    let src_lines: Vec<&str> = src.split('\n').collect();
    let lines: Vec<FlowSourceLine> = (first_line..=end_line)
        .map(|n| FlowSourceLine {
            n,
            text: src_lines
                .get(n.saturating_sub(1) as usize)
                .copied()
                .unwrap_or("")
                .to_string(),
            step: None,
            role: None,
        })
        .collect();

    Some(CachedFunctionBody {
        function: decl.name.clone(),
        file: snapshot.path.display().to_string(),
        start_line: first_line,
        end_line,
        lines,
    })
}

/// Build the per-hop function bodies for a resolved flow.
///
/// `chain_funcs` is the entry -> ... -> terminal chain. Each event (the
/// source read, every propagation step) is placed in the hop whose body
/// contains its file:line; the path may be shorter than the chain when
/// same-line steps were collapsed. Step numbers run in flow order (source =
/// 1, ...), matching the text renderer. `terminal_role` is the role of the last
/// step - `Sink` for a taint finding, `Taint` for a source lineage that ends at
/// a non-sink terminal. Returns empty when there is no multi-hop chain.
pub fn build_flow_bodies(
    ws: &Workspace,
    chain_funcs: &[FuncId],
    source: &FindingMatch,
    taint_path: &[TaintPropagationStep],
    terminal_role: FlowRole,
) -> Vec<FlowFunctionBody> {
    FlowBodyCache::new(ws).build_flow_bodies(chain_funcs, source, taint_path, terminal_role)
}
