//! Public trace output schema (spec §17, refined).
//!
//! The primary artifact is a serde-friendly [`TraceResult`]. Everything else
//! — CLI text, IDE step views, DOT graphs — is a renderer on top of that
//! single JSON-stable shape. See `docs/contributing/architecture.mdx` for the layering.

pub mod render;

use bonsai_abstract_interp::{RawStep, RawTrace, StepKind, TraceLimits};
use bonsai_common::{FuncId, Precision, Span, SpanMap};
use bonsai_vfs::Vfs;
use serde::{Deserialize, Serialize};

/// Top-level trace artifact. Stable across CLI / API / IDE / test goldens.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceResult {
    pub trace_id: String,
    pub query: TraceQuery,
    pub summary: TraceSummary,
    pub paths: Vec<PathSummary>,
    pub steps: Vec<TraceStep>,
    pub edges: Vec<TraceEdge>,
    pub states: Vec<StateSnapshot>,
    pub diagnostics: Vec<TraceDiagnostic>,
    pub metadata: TraceMetadata,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceQuery {
    pub kind: TraceQueryKind,
    pub target_symbol: Option<String>,
    pub entry_symbol: Option<String>,
    pub sink_symbol: Option<String>,
    pub file_filter: Option<Vec<String>>,
    pub max_depth: u32,
    pub max_paths: u32,
    pub follow_calls: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TraceQueryKind {
    FunctionEntry,
    SourceToSink,
    AllReturns,
    ReachableFromEntry,
}

impl Default for TraceQueryKind {
    fn default() -> Self {
        Self::FunctionEntry
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceSummary {
    pub language: String,
    pub workspace_root: String,
    pub entrypoints: Vec<String>,
    pub total_steps: usize,
    pub total_paths: usize,
    pub explored_paths: usize,
    pub truncated_paths: usize,
    pub precision: Precision,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SourceSpan {
    pub file: String,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub start_byte: u64,
    pub end_byte: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceStep {
    /// Step ordinal in the linear trace. `u64` so very large traces
    /// (>4B steps) can't silently collapse onto a single id.
    pub id: u64,
    /// Symbolic-execution path id. `0` is a valid id — adapters that
    /// don't model branching emit every step on path `0`.
    pub path_id: u64,
    /// One-based linearisation of `id` for human readers (`1`, `2`, …).
    /// Widened to `u64` to track `id` without wrapping.
    pub order: u64,
    pub kind: TraceStepKind,
    pub message: String,
    pub function: String,
    pub module: String,
    pub file: String,
    pub span: SourceSpan,
    pub state_before: Option<u32>,
    pub state_after: Option<u32>,
    pub precision: Precision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TraceStepKind {
    EnterFunction,
    ExitFunction,
    EvalExpr,
    Assign,
    LoadVariable,
    StoreVariable,
    BranchSplit,
    BranchTaken,
    LoopEnter,
    LoopIterate,
    LoopExit,
    Call,
    Return,
    Throw,
    Catch,
    Await,
    Yield,
    Merge,
    Diagnostic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceEdge {
    pub from_step: u64,
    pub to_step: u64,
    pub kind: TraceEdgeKind,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TraceEdgeKind {
    Next,
    BranchTrue,
    BranchFalse,
    CallEnter,
    ReturnToCaller,
    ThrowToHandler,
    Merge,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub id: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locals: Vec<LocalBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_constraints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heap_objects: Vec<HeapObjectSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalBinding {
    pub name: String,
    pub value: String,
    pub ty: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeapObjectSummary {
    pub id: u32,
    pub ty: String,
    pub fields: Vec<LocalBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathSummary {
    pub path_id: u64,
    pub first_step: u64,
    pub last_step: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_constraints: Vec<String>,
    pub terminated_by: PathTermination,
    pub precision: Precision,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PathTermination {
    Return,
    Throw,
    DepthLimit,
    LoopLimit,
    UnknownCall,
    UserStop,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceDiagnostic {
    pub severity: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceMetadata {
    pub engine_version: String,
    pub analysis_limits: AnalysisLimits,
}

#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnalysisLimits {
    pub max_depth: u32,
    pub max_paths: u32,
    pub loop_unroll_limit: u32,
}

/// Inputs required to finalize a raw trace. The finalizer needs enough
/// context to fill file paths, line/col spans, and metadata.
pub struct FinalizeCtx<'a> {
    pub trace_id: String,
    pub query: TraceQuery,
    pub language: &'a str,
    pub workspace_root: &'a str,
    pub entry_symbol: Option<&'a str>,
    pub entry_funcs: Vec<(FuncId, String)>,
    /// Resolve `FuncId` to its qualified name; used to annotate each step.
    pub func_name: &'a dyn Fn(FuncId) -> Option<String>,
    pub func_module: &'a dyn Fn(FuncId) -> Option<String>,
    pub limits: TraceLimits,
}

impl std::fmt::Debug for FinalizeCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizeCtx")
            .field("trace_id", &self.trace_id)
            .field("language", &self.language)
            .field("entry_funcs", &self.entry_funcs)
            .finish()
    }
}

/// Convert a raw interpreter trace into the rich public schema, resolving
/// spans to file paths / line-columns via the VFS.
pub fn finalize(raw: RawTrace, ctx: FinalizeCtx<'_>, vfs: &Vfs) -> TraceResult {
    let mut steps: Vec<TraceStep> = Vec::with_capacity(raw.steps.len());
    let mut edges: Vec<TraceEdge> = Vec::new();
    let mut precision = Precision::Exact;
    let mut span_caches: ahash::AHashMap<bonsai_common::FileId, SpanMap> = ahash::AHashMap::new();

    for (idx, raw_step) in raw.steps.iter().enumerate() {
        let source_span = span_to_source(&raw_step.span, vfs, &mut span_caches);
        let func_name = (ctx.func_name)(raw_step.func).unwrap_or_else(|| format!("func#{}", raw_step.func));
        let module = (ctx.func_module)(raw_step.func).unwrap_or_default();
        precision = precision.meet(raw_step.precision);
        // u64 ids prevent the wrap-to-zero / collapse-to-MAX hazards
        // that u32 step counters had on very large traces.
        let id = idx as u64;
        steps.push(TraceStep {
            id,
            // Path id passes through verbatim. A previous version
            // remapped 0 → 1 silently which conflated unknown/sentinel
            // paths with real path 1. Per docs/contributing/specification.mdx the trace
            // surface is "lossless"; we don't mutate path identity.
            path_id: u64::from(raw_step.path_id),
            order: id.saturating_add(1),
            kind: map_step_kind(raw_step.kind),
            message: raw_step.message.clone(),
            function: func_name,
            module,
            file: source_span.file.clone(),
            span: source_span,
            state_before: None,
            state_after: None,
            precision: raw_step.precision,
            notes: notes_for(raw_step),
        });
    }

    for win in steps.windows(2) {
        if win[0].path_id != win[1].path_id {
            continue;
        }
        edges.push(TraceEdge {
            from_step: win[0].id,
            to_step: win[1].id,
            kind: edge_kind(&win[0], &win[1]),
        });
    }

    let paths = path_summaries(&steps, raw.truncated);

    let summary = TraceSummary {
        language: ctx.language.to_string(),
        workspace_root: ctx.workspace_root.to_string(),
        entrypoints: ctx.entry_funcs.iter().map(|(_, name)| name.clone()).collect(),
        total_steps: steps.len(),
        total_paths: paths.len(),
        explored_paths: paths.len(),
        truncated_paths: paths
            .iter()
            .filter(|p| {
                matches!(
                    p.terminated_by,
                    PathTermination::DepthLimit | PathTermination::LoopLimit
                )
            })
            .count(),
        precision,
    };

    TraceResult {
        trace_id: if ctx.trace_id.is_empty() {
            format!("trace-{}", steps.len())
        } else {
            ctx.trace_id
        },
        query: ctx.query,
        summary,
        paths,
        steps,
        edges,
        states: Vec::new(),
        diagnostics: Vec::new(),
        metadata: TraceMetadata {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            analysis_limits: AnalysisLimits {
                max_depth: u32::from(ctx.limits.max_call_depth),
                max_paths: ctx.limits.max_branches,
                loop_unroll_limit: u32::from(ctx.limits.max_loop_iters),
            },
        },
    }
}

/// Group the linear `steps` into per-path summaries. Each summary
/// records first/last step ids, accumulated precision, and the
/// reason the path terminated (Throw / Return / DepthLimit when the
/// trace was budget-truncated).
fn path_summaries(steps: &[TraceStep], truncated: bool) -> Vec<PathSummary> {
    let mut by_path: ahash::AHashMap<u64, Vec<&TraceStep>> = ahash::AHashMap::new();
    for step in steps {
        by_path.entry(step.path_id).or_default().push(step);
    }
    let mut paths: Vec<PathSummary> = by_path
        .into_iter()
        .filter_map(|(path_id, mut path_steps)| {
            path_steps.sort_by_key(|step| step.id);
            let first = path_steps.first()?;
            let last = path_steps.last()?;
            let precision = path_steps
                .iter()
                .fold(Precision::Exact, |acc, step| acc.meet(step.precision));
            Some(PathSummary {
                path_id,
                first_step: first.id,
                last_step: last.id,
                path_constraints: Vec::new(),
                terminated_by: if truncated {
                    PathTermination::DepthLimit
                } else if path_steps.iter().any(|step| step.kind == TraceStepKind::Throw) {
                    PathTermination::Throw
                } else if path_steps.iter().any(|step| step.kind == TraceStepKind::Return) {
                    PathTermination::Return
                } else {
                    PathTermination::Unknown
                },
                precision,
            })
        })
        .collect();
    paths.sort_by_key(|path| path.path_id);
    paths
}

/// Lift the interpreter's [`StepKind`] vocabulary to the
/// schema-stable [`TraceStepKind`] surface.
fn map_step_kind(kind: StepKind) -> TraceStepKind {
    match kind {
        StepKind::EnterFunction => TraceStepKind::EnterFunction,
        StepKind::EvalExpr => TraceStepKind::EvalExpr,
        StepKind::Assign => TraceStepKind::Assign,
        StepKind::BranchSplit => TraceStepKind::BranchSplit,
        StepKind::BranchTaken => TraceStepKind::BranchTaken,
        StepKind::Call => TraceStepKind::Call,
        StepKind::Return => TraceStepKind::Return,
        StepKind::Throw => TraceStepKind::Throw,
        StepKind::Await => TraceStepKind::Await,
        StepKind::Yield => TraceStepKind::Yield,
        StepKind::Merge => TraceStepKind::Merge,
        StepKind::Diagnostic => TraceStepKind::Diagnostic,
    }
}

/// Classify the edge between two consecutive steps. Driven entirely
/// by the source step's kind — the destination is only carried for
/// future use.
fn edge_kind(from: &TraceStep, _to: &TraceStep) -> TraceEdgeKind {
    match from.kind {
        TraceStepKind::BranchSplit => TraceEdgeKind::BranchTrue,
        TraceStepKind::Call => TraceEdgeKind::CallEnter,
        TraceStepKind::Return => TraceEdgeKind::ReturnToCaller,
        TraceStepKind::Throw => TraceEdgeKind::ThrowToHandler,
        TraceStepKind::Merge => TraceEdgeKind::Merge,
        _ => TraceEdgeKind::Next,
    }
}

/// Renderer-facing notes attached to a single step. Currently only
/// surfaces non-Exact precision so a CLI consumer can flag it.
fn notes_for(step: &RawStep) -> Vec<String> {
    let mut notes = Vec::new();
    if step.precision != Precision::Exact {
        notes.push(format!("precision: {:?}", step.precision));
    }
    notes
}

/// Resolve a byte-range [`Span`] to a [`SourceSpan`] with line/col
/// coordinates. The `cache` is per-finalize so each file's `SpanMap`
/// is built once even when many steps share a file.
fn span_to_source(
    span: &Span,
    vfs: &Vfs,
    cache: &mut ahash::AHashMap<bonsai_common::FileId, SpanMap>,
) -> SourceSpan {
    let Ok(snapshot) = vfs.snapshot(span.file) else {
        return SourceSpan {
            file: String::from("<unknown>"),
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 0,
            start_byte: span.start,
            end_byte: span.end,
        };
    };
    let map = cache
        .entry(span.file)
        .or_insert_with(|| SpanMap::new(snapshot.text.as_ref()));
    let start = map.line_col(span.start);
    let end = map.line_col(span.end);
    SourceSpan {
        file: snapshot.path.display().to_string(),
        start_line: start.line,
        start_col: start.column,
        end_line: end.line,
        end_col: end.column,
        start_byte: span.start,
        end_byte: span.end,
    }
}
