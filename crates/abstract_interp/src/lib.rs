//! Abstract interpretation / symbolic trace engine (spec §17).
//!
//! The engine walks a [`Cfg`] over abstract values, splitting on branches
//! and expanding calls interprocedurally on demand. It is bounded by
//! [`TraceLimits`] so unknown loops / recursion cannot blow up the host.

// Internal submodules; the public surface is the re-exports below.
pub(crate) mod state;
pub(crate) mod value;

pub use state::{Constraint, ExecState, Frame, RelationOp, RelationTerm, ValueRelation};
pub use value::{AbstractValue, BoolDomain, IntRange, Nullness};

use bonsai_cfg::{Cfg, Terminator};
use bonsai_common::{BasicBlockId, FuncId, Precision, Span, TraceStepId};
use bonsai_lang_api::{assignment_trace_message, FlowEvent};
use serde::{Deserialize, Serialize};

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
    Lifecycle,
    Merge,
    Diagnostic,
}

/// One row in a [`RawTrace`]. The "raw" prefix marks this as the
/// pre-finalisation shape — `bonsai_trace::finalize` lifts it to a
/// schema-stable `bonsai_trace::TraceStep` with line/col spans and
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

/// Linear list of interpreter steps plus explicit completion metadata.
/// `truncated` is reserved for exhausted [`TraceLimits`] budgets;
/// `incomplete_reasons` records semantic gaps such as unresolved calls.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RawTrace {
    pub steps: Vec<RawStep>,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncation_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete_reasons: Vec<String>,
}

impl RawTrace {
    pub fn mark_truncated(&mut self, reason: &'static str) {
        self.truncated = true;
        if !self.truncation_reasons.iter().any(|existing| existing == reason) {
            self.truncation_reasons.push(reason.to_string());
        }
    }

    pub fn mark_incomplete(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if reason.is_empty() {
            return;
        }
        if !self.incomplete_reasons.iter().any(|existing| existing == &reason) {
            self.incomplete_reasons.push(reason);
        }
    }
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
    parent_state: &ExecState,
    next_path: &mut u32,
    worklist: &mut Vec<(BasicBlockId, u32, ExecState)>,
    trace: &mut RawTrace,
) -> bool {
    for (idx, successor) in successors.iter().enumerate() {
        let successor_path = if idx == 0 {
            parent_path
        } else {
            let Some(new_id) = next_path.checked_add(1) else {
                trace.mark_truncated("path-id-overflow");
                return false;
            };
            *next_path = new_id;
            new_id
        };
        let mut successor_state = parent_state.clone();
        successor_state.current_bb = *successor;
        successor_state.path_constraints.push(Constraint {
            text: format!("branch successor {idx}"),
        });
        worklist.push((*successor, successor_path, successor_state));
    }
    true
}

/// Run the abstract interpreter from the entry of `cfg` for `func`.
///
/// Emits a linear trace — sufficient for the spec's "trace from function
/// entry" query. Path splitting is handled by enqueueing unvisited
/// successors onto a worklist; interprocedural expansion is the
/// workspace-level `bonsai_workspace::cross_module` tracer's job.
pub fn run_entry(func: FuncId, cfg: &Cfg, limits: TraceLimits) -> RawTrace {
    let mut trace = RawTrace::default();
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
            trace.mark_truncated("max-steps");
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

    let mut worklist: Vec<(BasicBlockId, u32, ExecState)> =
        vec![(cfg.entry, 1, ExecState::new(func, cfg.entry))];
    let mut visits: ahash::AHashMap<(BasicBlockId, u32), u16> = ahash::AHashMap::new();
    let mut incoming_states: ahash::AHashMap<BasicBlockId, ExecState> = ahash::AHashMap::new();
    let mut branches_emitted: u32 = 0;

    while let Some((block_id, path_id, mut state)) = worklist.pop() {
        let visit_count = visits.entry((block_id, path_id)).or_insert(0);
        if *visit_count >= limits.max_loop_iters {
            trace.mark_truncated("max-loop-iters");
            continue;
        }
        *visit_count += 1;
        let Some(block) = cfg.block(block_id) else {
            continue;
        };
        state.current_bb = block_id;
        if let Some(existing) = incoming_states.get_mut(&block_id) {
            if existing.merge_from(&state) {
                state = existing.clone();
                if !emit(
                    StepKind::Merge,
                    path_id,
                    block.span,
                    Precision::Narrowed,
                    "merge abstract state".into(),
                    &mut trace,
                    &mut next_step,
                ) {
                    return trace;
                }
            }
        } else {
            incoming_states.insert(block_id, state.clone());
        }

        for event in &block.events {
            apply_event(&mut state, event);
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
                    let mut successor_state = state.clone();
                    successor_state.current_bb = *successor;
                    worklist.push((*successor, path_id, successor_state));
                }
            }
            Terminator::TryFork => {
                branches_emitted += 1;
                if branches_emitted > limits.max_branches {
                    trace.mark_truncated("max-branches");
                    break;
                }
                // Try/catch counts against the same branch budget as
                // explicit control flow so exceptional paths can't
                // explode silently.
                if !push_branch_successors(
                    &block.successors,
                    path_id,
                    &state,
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
                    trace.mark_truncated("max-branches");
                    break;
                }
                if !emit(
                    StepKind::BranchSplit,
                    path_id,
                    block.span,
                    Precision::Exact,
                    "branch".into(),
                    &mut trace,
                    &mut next_step,
                ) {
                    return trace;
                }
                if !push_branch_successors(
                    &block.successors,
                    path_id,
                    &state,
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
                    let mut successor_state = state.clone();
                    successor_state.current_bb = *successor;
                    worklist.push((*successor, path_id, successor_state));
                }
            }
            Terminator::Break | Terminator::Continue => {
                for successor in &block.successors {
                    let mut successor_state = state.clone();
                    successor_state.current_bb = *successor;
                    worklist.push((*successor, path_id, successor_state));
                }
            }
            Terminator::Unreachable => {}
        }
    }

    trace
}

fn apply_event(state: &mut ExecState, event: &FlowEvent) {
    match event {
        FlowEvent::Assign {
            target,
            source_name,
            source_call,
            source_call_args,
            source_names,
            ..
        } => {
            let value = assignment_value(
                state,
                source_name.as_deref(),
                source_call.as_deref(),
                source_call_args,
                source_names,
            );
            state.locals.insert(target.clone(), value);
        }
        FlowEvent::Throw {
            value_name: Some(name),
            ..
        }
        | FlowEvent::Return {
            value_name: Some(name),
            ..
        }
        | FlowEvent::Await {
            value_name: Some(name),
            ..
        } => {
            let value = value_from_text(state, name);
            state.locals.insert(name.clone(), value);
        }
        _ => {}
    }
}

fn assignment_value(
    state: &ExecState,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
) -> AbstractValue {
    if let Some(name) = source_name {
        return value_from_text(state, name);
    }
    if !source_names.is_empty() {
        return join_values(source_names.iter().map(|name| value_from_text(state, name)));
    }
    if !source_call_args.is_empty() {
        return join_values(source_call_args.iter().map(|arg| value_from_text(state, arg)));
    }
    if let Some(call) = source_call {
        return AbstractValue::Unknown.join(value_from_text(state, call));
    }
    AbstractValue::Unknown
}

fn join_values(values: impl IntoIterator<Item = AbstractValue>) -> AbstractValue {
    values
        .into_iter()
        .reduce(AbstractValue::join)
        .unwrap_or(AbstractValue::Unknown)
}

fn value_from_text(state: &ExecState, raw: &str) -> AbstractValue {
    let text = raw.trim();
    if text.is_empty() {
        return AbstractValue::Unknown;
    }
    if let Some(value) = state.locals.get(text) {
        return value.clone();
    }
    match text {
        "true" | "True" => return AbstractValue::ConstBool(true),
        "false" | "False" => return AbstractValue::ConstBool(false),
        "null" | "nil" | "None" => return AbstractValue::Null,
        _ => {}
    }
    if let Ok(value) = text.parse::<i64>() {
        return AbstractValue::ConstInt(value);
    }
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0] as char;
        let last = bytes[bytes.len() - 1] as char;
        if matches!(first, '"' | '\'' | '`') && first == last {
            return AbstractValue::ConstString(text[1..text.len() - 1].to_string());
        }
    }
    AbstractValue::Unknown
}

/// Map a [`FlowEvent`] variant onto the interpreter's step vocabulary.
///
/// Precision defaults to semantic facts only. Concrete events are
/// `Exact`; CFG-level joins that merge multiple feasible states are
/// `Narrowed`.
/// Branch / Loop / Try events are handled by the CFG builder and
/// never appear in a block's `events`; the catch-all renders them as
/// a `Diagnostic` so the interpreter still advances if one slips
/// through.
fn classify_event(event: &FlowEvent) -> (StepKind, Precision, String) {
    match event {
        FlowEvent::Call { name, .. } => (StepKind::Call, Precision::Exact, format!("call {name}")),
        FlowEvent::Assign {
            target,
            source_name,
            source_call,
            source_call_args,
            source_names,
            ..
        } => (
            StepKind::Assign,
            Precision::Exact,
            assignment_trace_message(
                "assign",
                target,
                source_name.as_deref(),
                source_call.as_deref(),
                source_call_args,
                source_names,
            ),
        ),
        FlowEvent::Return { .. } => (StepKind::Return, Precision::Exact, "return".into()),
        FlowEvent::Throw { .. } => (StepKind::Throw, Precision::Exact, "throw".into()),
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
        FlowEvent::Lifecycle { name, transition, .. } => (
            StepKind::Lifecycle,
            Precision::Exact,
            format!("lifecycle {name} -> {transition}"),
        ),
        other => (StepKind::Diagnostic, Precision::Exact, format!("{other:?}")),
    }
}

/// Surface the span carried by any [`FlowEvent`] variant.
fn flow_event_span(event: &FlowEvent) -> Span {
    event.span()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
