//! Structured per-hop source evidence shared by the text flow renderer and
//! the JSON/SARIF serializers. Each hop carries its full function body as
//! numbered lines, with `step`/`role` set on the lines that bear a flow
//! event - the same code and annotations the terminal view prints, so
//! machine-readable output embeds the evidence rather than just the chain.

use ahash::AHashMap;
use bonsai_common::{cached_span_map_arc, FuncId, SymbolId};
use bonsai_workspace::Workspace;
use serde::Serialize;

use crate::finding::{FindingMatch, TaintPropagationStep};

/// Role a flow step plays on the line it annotates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowRole {
    Source,
    Taint,
    Sink,
}

/// One source line within a hop body. `step`/`role` are present only on the
/// lines that carry a flow event.
#[derive(Clone, Debug, Serialize)]
pub struct FlowSourceLine {
    pub n: u32,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<FlowRole>,
}

/// One function along the flow, with its full body as numbered lines.
#[derive(Clone, Debug, Serialize)]
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
        let last_step = taint_path.len().saturating_sub(1);
        let mut bodies = Vec::with_capacity(chain_funcs.len());
        let mut step = 0u32;

        for (idx, func) in chain_funcs.iter().enumerate() {
            let Some(cached) = self.cached_body(*func) else {
                continue;
            };
            let mut lines = cached.lines.clone();

            // Source sits in the entry hop.
            if idx == 0 && source.line >= cached.start_line && source.line <= cached.end_line {
                step += 1;
                annotate_line(&mut lines, source.line, FlowRole::Source, step);
            }
            // The call that leaves this hop; the final step is the sink.
            if let Some(call) = taint_path.get(idx) {
                step += 1;
                let role = if idx == last_step {
                    terminal_role
                } else {
                    FlowRole::Taint
                };
                annotate_line(&mut lines, call.line, role, step);
            }

            bodies.push(FlowFunctionBody {
                function: cached.function.clone(),
                file: cached.file.clone(),
                start_line: cached.start_line,
                lines,
            });
        }
        bodies
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
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(func.raw()))?;
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
/// `chain_funcs` is the entry -> ... -> terminal chain; `taint_path[i]` is the
/// call that leaves `chain_funcs[i]`. Step numbers run in flow order (source =
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
