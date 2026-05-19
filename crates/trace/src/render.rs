//! Secondary renderers on top of [`TraceResult`].
//!
//! JSON is the canonical serialization; these are human-facing projections
//! layered on top. Never add fields here without also adding them to the
//! JSON schema — the whole point is that the JSON drives every surface.

use crate::{TraceEdgeKind, TraceResult, TraceStep, TraceStepKind};

/// Compact one-line-per-step text transcript, plus a header summary. This
/// is what CLI users see by default when they pick `--format text`.
#[must_use]
pub fn to_text(trace: &TraceResult) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Trace: {}\nLanguage: {}\nPrecision: {:?}\nPaths explored: {}\nTruncated paths: {}\n",
        trace
            .query
            .entry_symbol
            .as_deref()
            .or(trace.query.target_symbol.as_deref())
            .unwrap_or("<unknown>"),
        trace.summary.language,
        trace.summary.precision,
        trace.summary.explored_paths,
        trace.summary.truncated_paths,
    );
    if !trace.summary.analysis_complete {
        let mut reasons = trace.summary.truncation_reasons.clone();
        reasons.extend(trace.summary.analysis_incomplete_reasons.iter().cloned());
        reasons.sort();
        reasons.dedup();
        let reasons = if reasons.is_empty() {
            "unknown".to_string()
        } else {
            reasons.join(", ")
        };
        let _ = writeln!(out, "Analysis incomplete: {reasons}\n");
    }
    for path in &trace.paths {
        let _ = writeln!(out, "Path {}", path.path_id);
        for step in trace.steps.iter().filter(|s| s.path_id == path.path_id) {
            write_step(&mut out, step);
        }
        let _ = writeln!(out, "  terminated_by: {:?}", path.terminated_by);
        let _ = writeln!(out);
    }
    out
}

fn write_step(out: &mut String, step: &TraceStep) {
    use std::fmt::Write as _;
    let label = if step.precision.is_semantic() {
        human_label(step.kind, &step.message, &step.function)
    } else {
        "Suppressed diagnostic-precision trace step".to_string()
    };
    let _ = writeln!(out, "  [{}] {}", step.order, label);
    let _ = writeln!(
        out,
        "      at {}:{}:{}-{}:{}",
        step.span.file, step.span.start_line, step.span.start_col, step.span.end_line, step.span.end_col,
    );
    if !step.notes.is_empty() {
        let _ = writeln!(out, "      notes: {}", step.notes.join("; "));
    }
}

fn human_label(kind: TraceStepKind, message: &str, function: &str) -> String {
    if !message.is_empty() {
        return message.to_string();
    }
    match kind {
        TraceStepKind::EnterFunction => format!("Enter function {function}"),
        TraceStepKind::ExitFunction => format!("Exit function {function}"),
        TraceStepKind::Return => format!("Return from {function}"),
        TraceStepKind::BranchSplit => "Branch split".to_string(),
        other => format!("{other:?}"),
    }
}

/// Graphviz DOT rendering of the trace as a sequence graph.
#[must_use]
pub fn to_dot(trace: &TraceResult) -> String {
    use std::fmt::Write as _;
    let mut out =
        String::from("digraph trace {\n  rankdir=LR;\n  node [shape=box, fontname=\"Helvetica\"];\n");
    for step in &trace.steps {
        let label = format!("[{}] {:?}\\n{}", step.order, step.kind, step.function);
        let _ = writeln!(out, "  s{} [label=\"{}\"];", step.id, label.replace('"', "\\\""));
    }
    for edge in &trace.edges {
        let style = match edge.kind {
            TraceEdgeKind::BranchTrue => "color=green",
            TraceEdgeKind::BranchFalse => "color=red",
            TraceEdgeKind::CallEnter => "color=blue",
            TraceEdgeKind::ReturnToCaller => "color=navy",
            TraceEdgeKind::ThrowToHandler => "color=purple,style=dashed",
            TraceEdgeKind::Merge => "color=gray",
            TraceEdgeKind::Next => "color=black",
        };
        let _ = writeln!(out, "  s{} -> s{} [{}];", edge.from_step, edge.to_step, style);
    }
    out.push_str("}\n");
    out
}

/// Canonical pretty JSON.
pub fn to_json(trace: &TraceResult) -> serde_json::Result<String> {
    serde_json::to_string_pretty(trace)
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;
