//! Abstract interpretation / symbolic trace engine (spec §17).
//!
//! The engine walks a [`Cfg`] over abstract values, splitting on branches
//! and expanding calls interprocedurally on demand. It is bounded by
//! [`TraceLimits`] so unknown loops / recursion cannot blow up the host.

// Internal submodules; the public surface is the re-exports below.
pub(crate) mod state;
pub(crate) mod value;

pub use state::{Constraint, ExecState, Frame};
pub use value::AbstractValue;

use bonsai_cfg::{Cfg, Terminator};
use bonsai_common::{BasicBlockId, FuncId, Precision, Span, TraceStepId};
use bonsai_lang_api::FlowEvent;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Per-trace budget. Bounds `run_entry` so unknown loops or recursion
/// can't blow up the host.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceLimits {
    pub max_steps: u32,
    pub max_call_depth: u16,
    pub max_loop_iters: u16,
    pub max_branches: u32,
}

impl Default for TraceLimits {
    fn default() -> Self {
        Self {
            max_steps: 4096,
            max_call_depth: 32,
            max_loop_iters: 16,
            max_branches: 256,
        }
    }
}

/// Categorical tag for a single trace step. The interpreter assigns one of
/// these per emitted step so renderers don't have to re-classify events.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    EnterFunction,
    EvalExpr,
    Assign,
    BranchSplit,
    BranchTaken,
    Call,
    Return,
    Throw,
    Await,
    Yield,
    Merge,
    Diagnostic,
}

/// One row in a [`RawTrace`]. The "raw" prefix marks this as the
/// pre-finalisation shape — `bonsai_trace::finalize` lifts it to a
/// schema-stable [`bonsai_trace::TraceStep`] with line/col spans and
/// resolved function names.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawStep {
    pub id: TraceStepId,
    pub path_id: u32,
    pub kind: StepKind,
    pub span: Span,
    pub func: FuncId,
    pub precision: Precision,
    pub message: String,
}

/// Linear list of interpreter steps plus a `truncated` flag set when any
/// budget in [`TraceLimits`] was exhausted.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawTrace {
    pub steps: Vec<RawStep>,
    pub truncated: bool,
}

/// Enqueue every successor of a branch / try-fork onto the DFS worklist
/// and return whether enqueueing succeeded.
///
/// The first successor (`idx == 0`) inherits the caller's path id; the
/// rest get fresh ids minted from `next_path`. On `u32` saturation we
/// mark the trace truncated and bail rather than `saturating_add`-ing
/// — colliding two distinct paths on `u32::MAX` would silently merge
/// them in the rendered trace, which violates the "lossless trace"
/// contract in `docs/contributing/specification.mdx`.
fn push_branch_successors(
    successors: &[BasicBlockId],
    parent_path: u32,
    next_path: &mut u32,
    worklist: &mut SmallVec<[(BasicBlockId, u32); 8]>,
    trace: &mut RawTrace,
) -> bool {
    for (idx, successor) in successors.iter().enumerate() {
        let successor_path = if idx == 0 {
            parent_path
        } else {
            let Some(new_id) = next_path.checked_add(1) else {
                trace.truncated = true;
                return false;
            };
            *next_path = new_id;
            new_id
        };
        worklist.push((*successor, successor_path));
    }
    true
}

/// Run the abstract interpreter from the entry of `cfg` for `func`.
///
/// Emits a linear trace — sufficient for the spec's "trace from function
/// entry" query. Path splitting is handled by enqueueing unvisited
/// successors onto a worklist; interprocedural expansion is the
/// workspace-level [`bonsai_workspace::cross_module`] tracer's job.
pub fn run_entry(func: FuncId, cfg: &Cfg, limits: TraceLimits) -> RawTrace {
    let mut trace = RawTrace::default();
    let mut state = ExecState::new(func, cfg.entry);
    let mut next_step: u32 = 0;
    let mut next_path: u32 = 1;

    let emit = |kind: StepKind,
                path_id: u32,
                span: Span,
                precision: Precision,
                message: String,
                trace: &mut RawTrace,
                next_step: &mut u32| {
        if *next_step >= limits.max_steps {
            trace.truncated = true;
            return false;
        }
        trace.steps.push(RawStep {
            id: TraceStepId::new(*next_step),
            path_id,
            kind,
            span,
            func,
            precision,
            message,
        });
        *next_step += 1;
        true
    };

    if !emit(
        StepKind::EnterFunction,
        1,
        cfg.block(cfg.entry)
            .map_or(Span::new(bonsai_common::FileId::INVALID, 0, 0), |b| b.span),
        Precision::Exact,
        format!("enter {}", func),
        &mut trace,
        &mut next_step,
    ) {
        return trace;
    }

    let mut worklist: SmallVec<[(BasicBlockId, u32); 8]> = SmallVec::from_slice(&[(cfg.entry, 1)]);
    let mut visited: ahash::AHashSet<BasicBlockId> = ahash::AHashSet::new();
    let mut branches_emitted: u32 = 0;

    while let Some((block_id, path_id)) = worklist.pop() {
        if !visited.insert(block_id) {
            continue;
        }
        let Some(block) = cfg.block(block_id) else {
            continue;
        };
        state.current_bb = block_id;

        for event in &block.events {
            let (kind, precision, message) = classify_event(event);
            if !emit(
                kind,
                path_id,
                flow_event_span(event),
                precision,
                message,
                &mut trace,
                &mut next_step,
            ) {
                return trace;
            }
            // No interprocedural recursion here — `FlowEvent::Call` is
            // recorded as a step but expansion belongs to the
            // workspace-level cross-module tracer per
            // `docs/contributing/taint-engine-spec.mdx`.
        }

        match block.terminator {
            Terminator::Fallthrough | Terminator::LoopHeader => {
                for successor in &block.successors {
                    worklist.push((*successor, path_id));
                }
            }
            Terminator::TryFork => {
                branches_emitted += 1;
                if branches_emitted > limits.max_branches {
                    trace.truncated = true;
                    break;
                }
                // Try/catch counts against the same branch budget as
                // explicit control flow so exceptional paths can't
                // explode silently.
                if !push_branch_successors(
                    &block.successors,
                    path_id,
                    &mut next_path,
                    &mut worklist,
                    &mut trace,
                ) {
                    break;
                }
            }
            Terminator::Branch => {
                branches_emitted += 1;
                if branches_emitted > limits.max_branches {
                    trace.truncated = true;
                    break;
                }
                if !emit(
                    StepKind::BranchSplit,
                    path_id,
                    block.span,
                    Precision::OverApproximate,
                    "branch".into(),
                    &mut trace,
                    &mut next_step,
                ) {
                    return trace;
                }
                if !push_branch_successors(
                    &block.successors,
                    path_id,
                    &mut next_path,
                    &mut worklist,
                    &mut trace,
                ) {
                    break;
                }
            }
            // Return / Throw events were already emitted in the event
            // loop above. A plain return has no successors, but a return
            // inside `try` may route through synthetic finally cleanup
            // before the path reaches function exit.
            Terminator::Return | Terminator::Throw => {
                for successor in &block.successors {
                    worklist.push((*successor, path_id));
                }
            }
            Terminator::Break | Terminator::Continue => {
                for successor in &block.successors {
                    worklist.push((*successor, path_id));
                }
            }
            Terminator::Unreachable => {}
        }
    }

    trace
}

/// Map a [`FlowEvent`] variant onto the interpreter's step vocabulary.
///
/// Precision defaults to `Exact` for concrete facts and
/// `OverApproximate` for events that represent non-determinism.
/// Branch / Loop / Try events are handled by the CFG builder and
/// never appear in a block's `events`; the catch-all renders them as
/// a `Diagnostic` so the interpreter still advances if one slips
/// through.
fn classify_event(event: &FlowEvent) -> (StepKind, Precision, String) {
    match event {
        FlowEvent::Call { name, .. } => (StepKind::Call, Precision::Exact, format!("call {name}")),
        FlowEvent::Assign { target, .. } => (StepKind::Assign, Precision::Exact, format!("assign {target}")),
        FlowEvent::Return { .. } => (StepKind::Return, Precision::Exact, "return".into()),
        FlowEvent::Throw { .. } => (StepKind::Throw, Precision::OverApproximate, "throw".into()),
        FlowEvent::Await { .. } => (StepKind::Await, Precision::Exact, "await".into()),
        FlowEvent::Yield { value_text, .. } => (
            StepKind::Yield,
            Precision::Exact,
            match value_text {
                Some(text) => format!("yield {text}"),
                None => "yield".to_string(),
            },
        ),
        FlowEvent::Break { .. } => (StepKind::Diagnostic, Precision::Exact, "break".into()),
        FlowEvent::Continue { .. } => (StepKind::Diagnostic, Precision::Exact, "continue".into()),
        other => (StepKind::Diagnostic, Precision::Exact, format!("{other:?}")),
    }
}

/// Surface the span carried by any [`FlowEvent`] variant.
fn flow_event_span(event: &FlowEvent) -> Span {
    match event {
        FlowEvent::Call { span, .. }
        | FlowEvent::Branch { span, .. }
        | FlowEvent::Loop { span, .. }
        | FlowEvent::Assign { span, .. }
        | FlowEvent::Return { span, .. }
        | FlowEvent::Throw { span, .. }
        | FlowEvent::Try { span, .. }
        | FlowEvent::Break { span, .. }
        | FlowEvent::Continue { span, .. }
        | FlowEvent::Yield { span, .. }
        | FlowEvent::Await { span, .. }
        | FlowEvent::Defer { span, .. }
        | FlowEvent::Using { span, .. }
        | FlowEvent::Lifecycle { span, .. } => *span,
    }
}
