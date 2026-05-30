//! Structured per-hop source evidence shared by the text flow renderer and
//! the JSON/SARIF serializers. Each hop carries its full function body as
//! numbered lines, with `step`/`role` set on the lines that bear a flow
//! event - the same code and annotations the terminal view prints, so
//! machine-readable output embeds the evidence rather than just the chain.

use bonsai_common::{cached_span_map, FuncId, SymbolId};
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

/// Set the step/role on the first un-annotated line matching `line`.
fn annotate_line(lines: &mut [FlowSourceLine], line: u32, role: FlowRole, step: u32) {
    if let Some(slot) = lines.iter_mut().find(|l| l.n == line && l.role.is_none()) {
        slot.step = Some(step);
        slot.role = Some(role);
    }
}

/// Build the per-hop function bodies for a resolved flow.
///
/// `chain_funcs` is the entry -> ... -> sink-enclosing-fn chain; `taint_path[i]`
/// is the call that leaves `chain_funcs[i]`. Step numbers run in flow order
/// (source = 1, ..., sink last), matching the text renderer. Returns empty
/// when there is no multi-hop chain to render.
pub fn build_flow_bodies(
    ws: &Workspace,
    chain_funcs: &[FuncId],
    source: &FindingMatch,
    sink: &FindingMatch,
    taint_path: &[TaintPropagationStep],
) -> Vec<FlowFunctionBody> {
    let _ = sink; // sink role is carried by the final taint_path step
    if chain_funcs.is_empty() {
        return Vec::new();
    }
    let global = ws.db().global_index();
    let last_step = taint_path.len().saturating_sub(1);
    let mut bodies = Vec::with_capacity(chain_funcs.len());
    let mut step = 0u32;

    for (idx, func) in chain_funcs.iter().enumerate() {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        let file = decl.span.file;
        let Ok(snapshot) = ws.vfs().snapshot(file) else {
            continue;
        };
        let src = snapshot.text.as_ref();
        let span_map = cached_span_map(file, snapshot.version, src);
        let body_span = decl.body_span.unwrap_or(decl.span);
        let header_line = span_map.line_col(decl.name_span.start).line;
        let start_line = span_map.line_col(body_span.start).line;
        let end_line = span_map.line_col(body_span.end.saturating_sub(1)).line;
        let first_line = header_line.min(start_line);

        let src_lines: Vec<&str> = src.split('\n').collect();
        let mut lines: Vec<FlowSourceLine> = (first_line..=end_line)
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

        // Source sits in the entry hop.
        if idx == 0 && source.line >= first_line && source.line <= end_line {
            step += 1;
            annotate_line(&mut lines, source.line, FlowRole::Source, step);
        }
        // The call that leaves this hop; the final step is the sink.
        if let Some(call) = taint_path.get(idx) {
            step += 1;
            let role = if idx == last_step { FlowRole::Sink } else { FlowRole::Taint };
            annotate_line(&mut lines, call.line, role, step);
        }

        bodies.push(FlowFunctionBody {
            function: decl.name.clone(),
            file: snapshot.path.display().to_string(),
            start_line: first_line,
            lines,
        });
    }
    bodies
}
