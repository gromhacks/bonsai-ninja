//! Build a [`Cfg`] from a function's `FlowEvent` tree.
//!
//! The walker emits one block per contiguous run of sequential events,
//! a fresh block per branch / loop / try region, and dead `unreachable`
//! placeholders after early terminators. Orphan placeholders (no
//! events + no incoming edges) are dropped before the final CFG is
//! returned so the output stays dense.

use crate::{BasicBlock, BasicBlockId, Cfg, SyntheticBlockKind, Terminator};
use bonsai_common::Span;
use bonsai_lang_api::FlowEvent;

#[derive(Clone, Copy)]
struct FinallyFrame<'a> {
    span: Span,
    events: &'a [FlowEvent],
}

/// Build a CFG from a function's flow events. `function_name` is
/// carried through to [`Cfg::function`] for rendering.
#[must_use]
pub fn build_cfg_from_flow(function_name: &str, events: &[FlowEvent]) -> Cfg {
    let inferred_span = event_envelope(events);
    build_cfg_from_flow_in_span(function_name, inferred_span, events)
}

/// Build a CFG while retaining the exact owning declaration span for empty
/// synthetic shape blocks. Callers that own a [`Decl`](bonsai_lang_api::Decl)
/// should use this form; the compatibility wrapper infers the narrowest span
/// available from the event tree.
#[must_use]
pub fn build_cfg_from_flow_in_span(
    function_name: &str,
    function_span: Option<Span>,
    events: &[FlowEvent],
) -> Cfg {
    let normalized_events = normalize_deferred_scopes(events);
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let exit = new_block(&mut blocks, "exit".into(), Some(SyntheticBlockKind::Exit));
    let entry = new_block(&mut blocks, "entry".into(), Some(SyntheticBlockKind::Entry));

    let tail = walk(&normalized_events, entry, exit, &mut blocks, None);
    // Implicit fallthrough from the last real block into exit when
    // the function doesn't already end in a Return / Throw.
    link(&mut blocks, tail, exit);

    if let Some(span) = function_span.filter(|span| span.file != bonsai_common::FileId::INVALID) {
        for block in &mut blocks {
            if block.span.file == bonsai_common::FileId::INVALID {
                block.span = span;
            }
        }
    }

    let (entry_remapped, exit_remapped, compacted) = compact_ids(blocks, entry, exit);

    Cfg {
        // CFG construction is exact for the adapter-emitted HIR events
        // supplied to this function. Synthetic/default CFGs stay incomplete.
        analysis_complete: true,
        analysis_incomplete_reasons: Vec::new(),
        function: function_name.to_string(),
        entry: entry_remapped,
        exit: exit_remapped,
        blocks: compacted,
    }
}

/// Rewrite lexical `defer` declarations into the same structured
/// try/finally form the CFG builder already uses for exact exit routing.
/// Multiple declarations nest in source order so cleanup executes LIFO.
/// Normalize lexical `defer` declarations into structured `try/finally`
/// regions. This is the canonical compiler lowering shared by CFG and IDG
/// consumers; keeping it here prevents independent analyses from assigning
/// different execution points to the same cleanup body.
#[must_use]
pub fn normalize_deferred_scopes(events: &[FlowEvent]) -> Vec<FlowEvent> {
    let mut lowered = Vec::new();
    for (index, event) in events.iter().enumerate() {
        match event {
            FlowEvent::Defer { span, body } => {
                lowered.push(FlowEvent::Try {
                    span: *span,
                    body: normalize_deferred_scopes(&events[index + 1..]),
                    catch_events: Vec::new(),
                    finally_events: normalize_deferred_scopes(body),
                    catch_param: None,
                    catch_types: Vec::new(),
                    catch_arms: Vec::new(),
                });
                return lowered;
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => lowered.push(FlowEvent::Branch {
                span: *span,
                condition: condition.clone(),
                then_events: normalize_deferred_scopes(then_events),
                else_events: normalize_deferred_scopes(else_events),
            }),
            FlowEvent::Loop {
                span,
                loop_kind,
                body,
            } => lowered.push(FlowEvent::Loop {
                span: *span,
                loop_kind: *loop_kind,
                body: normalize_deferred_scopes(body),
            }),
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_types,
                catch_arms,
            } => lowered.push(FlowEvent::Try {
                span: *span,
                body: normalize_deferred_scopes(body),
                catch_events: normalize_deferred_scopes(catch_events),
                finally_events: normalize_deferred_scopes(finally_events),
                catch_param: catch_param.clone(),
                catch_types: catch_types.clone(),
                catch_arms: catch_arms.clone(),
            }),
            FlowEvent::Using { span, body } => lowered.push(FlowEvent::Using {
                span: *span,
                body: normalize_deferred_scopes(body),
            }),
            other => lowered.push(other.clone()),
        }
    }
    lowered
}

/// Produce the executable structured event tree consumed by semantic passes.
///
/// Adapters deliberately retain statements after an abrupt terminator so
/// `dump-cfg` can show their unreachable source blocks. Dataflow consumers
/// must not lower those statements as live facts. This pass shares the CFG's
/// structured control semantics, lowers lexical cleanup first, and removes
/// only events proven unreachable on every path. It never caps work or guesses
/// about runtime call behavior.
#[must_use]
pub fn normalize_executable_flow(events: &[FlowEvent]) -> Vec<FlowEvent> {
    let deferred = normalize_deferred_scopes(events);
    prune_unreachable_sequence(&deferred).0
}

fn prune_unreachable_sequence(events: &[FlowEvent]) -> (Vec<FlowEvent>, bool) {
    let mut executable = Vec::with_capacity(events.len());
    let mut falls_through = true;
    let mut index = 0usize;
    while index < events.len() {
        if !falls_through {
            break;
        }
        let event = &events[index];

        // Some adapter walkers emit an enclosing Return/Throw before the
        // nested call expressions that evaluate its value. Exact byte-span
        // containment proves those calls belong to the abrupt expression,
        // so preserve their runtime order before pruning the later source
        // tail. This is structural compiler IR normalization: unrelated
        // statements and callback bodies outside the terminal span remain
        // excluded, and no callee/API spelling participates.
        if matches!(event, FlowEvent::Return { .. } | FlowEvent::Throw { .. }) {
            let terminal_span = event.span();
            let mut nested_index = index + 1;
            while let Some(nested) = events.get(nested_index) {
                let nested_span = nested.span();
                let strictly_contained = nested_span.file == terminal_span.file
                    && terminal_span.start <= nested_span.start
                    && nested_span.end <= terminal_span.end
                    && nested_span != terminal_span;
                if !strictly_contained {
                    break;
                }
                if matches!(nested, FlowEvent::Call { .. }) {
                    let (nested, _) = prune_event(nested);
                    executable.push(nested);
                }
                nested_index += 1;
            }
            let (terminal, _) = prune_event(event);
            executable.push(terminal);
            falls_through = false;
            index = nested_index;
            continue;
        }
        let (event, event_falls_through) = prune_event(event);
        executable.push(event);
        falls_through = event_falls_through;
        index += 1;
    }
    (executable, falls_through)
}

fn prune_event(event: &FlowEvent) -> (FlowEvent, bool) {
    match event {
        FlowEvent::Branch {
            span,
            condition,
            then_events,
            else_events,
        } => {
            let (then_events, then_falls_through) = prune_unreachable_sequence(then_events);
            let (else_events, else_falls_through) = prune_unreachable_sequence(else_events);
            (
                FlowEvent::Branch {
                    span: *span,
                    condition: condition.clone(),
                    then_events,
                    else_events,
                },
                then_falls_through || else_falls_through,
            )
        }
        FlowEvent::Loop {
            span,
            loop_kind,
            body,
        } => {
            let (body, _) = prune_unreachable_sequence(body);
            (
                FlowEvent::Loop {
                    span: *span,
                    loop_kind: *loop_kind,
                    body,
                },
                // Without an adapter-emitted proof that a loop is infinite,
                // its zero-iteration/condition-false exit remains reachable.
                true,
            )
        }
        FlowEvent::Try {
            span,
            body,
            catch_events,
            finally_events,
            catch_param,
            catch_types,
            catch_arms,
        } => {
            let (body, body_falls_through) = prune_unreachable_sequence(body);
            let (catch_events, catch_falls_through) = prune_unreachable_sequence(catch_events);
            let (finally_events, finally_falls_through) = prune_unreachable_sequence(finally_events);
            let has_catch = catch_param.is_some() || !catch_types.is_empty() || !catch_events.is_empty();
            (
                FlowEvent::Try {
                    span: *span,
                    body,
                    catch_events,
                    finally_events,
                    catch_param: catch_param.clone(),
                    catch_types: catch_types.clone(),
                    catch_arms: catch_arms.clone(),
                },
                finally_falls_through && (body_falls_through || (has_catch && catch_falls_through)),
            )
        }
        FlowEvent::Using { span, body } => {
            let (body, falls_through) = prune_unreachable_sequence(body);
            (FlowEvent::Using { span: *span, body }, falls_through)
        }
        FlowEvent::Defer { .. } => unreachable!("defer is normalized before reachability pruning"),
        FlowEvent::Return { .. }
        | FlowEvent::Throw { .. }
        | FlowEvent::Break { .. }
        | FlowEvent::Continue { .. } => (event.clone(), false),
        _ => (event.clone(), true),
    }
}

fn event_envelope(events: &[FlowEvent]) -> Option<Span> {
    let first = events.first()?.span();
    let mut start = first.start;
    let mut end = first.end;
    for event in &events[1..] {
        let span = event.span();
        if span.file != first.file {
            return None;
        }
        start = start.min(span.start);
        end = end.max(span.end);
    }
    Some(Span::new(first.file, start, end))
}

/// Append a fresh, empty block and return its index. The id is set
/// to match the index so later `compact_ids` can verify density.
fn new_block(
    blocks: &mut Vec<BasicBlock>,
    label: String,
    synthetic_kind: Option<SyntheticBlockKind>,
) -> usize {
    let id = blocks.len();
    blocks.push(BasicBlock {
        id: BasicBlockId::new(id as u32),
        label,
        synthetic_kind,
        events: Vec::new(),
        successors: Vec::new(),
        terminator: Terminator::Fallthrough,
        span: Span::new(bonsai_common::FileId::INVALID, 0, 0),
    });
    id
}

/// Add a successor edge `from -> to` if not already present.
fn link(blocks: &mut [BasicBlock], from: usize, to: usize) {
    let to_id = BasicBlockId::new(to as u32);
    if !blocks[from].successors.contains(&to_id) {
        blocks[from].successors.push(to_id);
    }
}

/// Per-loop targets for `break` / `continue` inside the body. Set by
/// `walk` whenever it descends into a loop and consulted when the
/// walker hits an early terminator.

#[derive(Copy, Clone, Debug)]
struct LoopTargets {
    break_to: usize,
    continue_to: usize,
}

/// Walk `events` appending to `current`. Returns the id of the final
/// block in the sequence so the caller can thread subsequent events
/// onto it.
///
/// `pending_finally` is a stack of surrounding finally blocks that
/// early exits inside a try body / catch arm must route through before
/// reaching the exit or loop target. Without it, a `Return` / `Throw`
/// inside `try` would bypass cleanup; with a single shared finally block,
/// those early exits would incorrectly resume normal fallthrough after
/// cleanup. The stack lets each early-exit path get its own finally copy
/// and preserve its original destination.
fn walk(
    events: &[FlowEvent],
    current: usize,
    exit: usize,
    blocks: &mut Vec<BasicBlock>,
    loop_targets: Option<LoopTargets>,
) -> usize {
    walk_with_finally(events, current, exit, blocks, loop_targets, &[])
}

fn walk_with_finally<'a>(
    events: &'a [FlowEvent],
    current: usize,
    exit: usize,
    blocks: &mut Vec<BasicBlock>,
    loop_targets: Option<LoopTargets>,
    pending_finally: &[FinallyFrame<'a>],
) -> usize {
    let mut cur = current;
    for event in events {
        match event.clone() {
            FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } => {
                record_span(blocks, cur, span);
                blocks[cur].terminator = Terminator::Branch;
                let join = new_block(
                    blocks,
                    format!("join@{}", span.start),
                    Some(SyntheticBlockKind::BranchJoin),
                );
                let then_id = new_block(
                    blocks,
                    format!("then@{}", span.start),
                    Some(SyntheticBlockKind::BranchThen),
                );
                let else_id = new_block(
                    blocks,
                    format!("else@{}", span.start),
                    Some(SyntheticBlockKind::BranchElse),
                );
                link(blocks, cur, then_id);
                link(blocks, cur, else_id);
                let then_tail =
                    walk_with_finally(&then_events, then_id, exit, blocks, loop_targets, pending_finally);
                let else_tail =
                    walk_with_finally(&else_events, else_id, exit, blocks, loop_targets, pending_finally);
                link(blocks, then_tail, join);
                link(blocks, else_tail, join);
                cur = join;
            }
            FlowEvent::Loop { span, body, .. } => {
                record_span(blocks, cur, span);
                let header = new_block(
                    blocks,
                    format!("loop-header@{}", span.start),
                    Some(SyntheticBlockKind::LoopHeader),
                );
                let body_id = new_block(
                    blocks,
                    format!("loop-body@{}", span.start),
                    Some(SyntheticBlockKind::LoopBody),
                );
                let after = new_block(
                    blocks,
                    format!("loop-after@{}", span.start),
                    Some(SyntheticBlockKind::LoopAfter),
                );
                blocks[header].terminator = Terminator::LoopHeader;
                link(blocks, cur, header);
                link(blocks, header, body_id);
                link(blocks, header, after);
                let body_tail = walk_with_finally(
                    &body,
                    body_id,
                    exit,
                    blocks,
                    Some(LoopTargets {
                        break_to: after,
                        continue_to: header,
                    }),
                    pending_finally,
                );
                link(blocks, body_tail, header);
                cur = after;
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                ..
            } => {
                record_span(blocks, cur, span);
                // Anchor block sits BETWEEN the predecessor's
                // straight-line events and the try/catch fork.
                // Without it, marking `cur.terminator = TryFork`
                // would structurally imply that any event already
                // recorded into `cur` (assignments, calls before
                // the try) could divert to catch — which isn't
                // true. The anchor isolates the fork to events
                // INSIDE the try body.
                let anchor = new_block(
                    blocks,
                    format!("try_fork@{}", span.start),
                    Some(SyntheticBlockKind::TryFork),
                );
                link(blocks, cur, anchor);
                // Seed the anchor's span from the parent Try so
                // `dump-cfg` doesn't render a `FileId::INVALID@0:0`
                // row for the anchor — the anchor has no events of
                // its own for `record_span` to fire on.
                record_span(blocks, anchor, span);
                let try_id = new_block(
                    blocks,
                    format!("try@{}", span.start),
                    Some(SyntheticBlockKind::TryBody),
                );
                let catch_id = new_block(
                    blocks,
                    format!("catch@{}", span.start),
                    Some(SyntheticBlockKind::Catch),
                );
                link(blocks, anchor, try_id);
                link(blocks, anchor, catch_id);
                blocks[anchor].terminator = Terminator::TryFork;
                let mut inner_finally = pending_finally.to_vec();
                inner_finally.push(FinallyFrame {
                    span,
                    events: &finally_events,
                });
                // Inside the try body and catch arm, early terminators get
                // their own finally path so they can continue to exit / loop
                // target after cleanup instead of falling through normally.
                let try_tail = walk_with_finally(&body, try_id, exit, blocks, loop_targets, &inner_finally);
                let catch_tail = walk_with_finally(
                    &catch_events,
                    catch_id,
                    exit,
                    blocks,
                    loop_targets,
                    &inner_finally,
                );
                let finally_id = new_block(
                    blocks,
                    format!("finally@{}", span.start),
                    Some(SyntheticBlockKind::Finally),
                );
                link(blocks, try_tail, finally_id);
                link(blocks, catch_tail, finally_id);
                cur = walk_with_finally(
                    &finally_events,
                    finally_id,
                    exit,
                    blocks,
                    loop_targets,
                    pending_finally,
                );
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                cur = walk_with_finally(&body, cur, exit, blocks, loop_targets, pending_finally);
            }
            terminal @ (FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. }) => {
                let span = flow_event_span(&terminal);
                record_span(blocks, cur, span);
                blocks[cur].terminator = match &terminal {
                    FlowEvent::Return { .. } => Terminator::Return,
                    FlowEvent::Throw { .. } => Terminator::Throw,
                    FlowEvent::Break { .. } => Terminator::Break,
                    FlowEvent::Continue { .. } => Terminator::Continue,
                    _ => unreachable!(),
                };
                blocks[cur].events.push(terminal);
                // When a finally is in flight, route every early
                // exit through it so cleanup work runs before the
                // edge to exit / loop target.
                let final_target = match blocks[cur].terminator {
                    Terminator::Break => loop_targets.map_or(exit, |t| t.break_to),
                    Terminator::Continue => loop_targets.map_or(exit, |t| t.continue_to),
                    Terminator::Return | Terminator::Throw => exit,
                    _ => unreachable!(),
                };
                if pending_finally.is_empty() {
                    match blocks[cur].terminator {
                        Terminator::Break | Terminator::Continue => link(blocks, cur, final_target),
                        Terminator::Return | Terminator::Throw => {}
                        _ => unreachable!(),
                    }
                } else {
                    append_finally_path(cur, final_target, exit, blocks, loop_targets, pending_finally);
                }
                // Events after an early terminator live in a fresh
                // `unreachable` block — common in structured flow.
                let dead = new_block(
                    blocks,
                    "unreachable".into(),
                    Some(SyntheticBlockKind::Unreachable),
                );
                blocks[dead].terminator = Terminator::Unreachable;
                cur = dead;
            }
            other => {
                let span = flow_event_span(&other);
                record_span(blocks, cur, span);
                blocks[cur].events.push(other);
            }
        }
    }
    cur
}

fn append_finally_path<'a>(
    from: usize,
    final_target: usize,
    exit: usize,
    blocks: &mut Vec<BasicBlock>,
    loop_targets: Option<LoopTargets>,
    pending_finally: &[FinallyFrame<'a>],
) {
    let mut cur = from;
    for idx in (0..pending_finally.len()).rev() {
        let frame = pending_finally[idx];
        let finally_id = new_block(
            blocks,
            format!("finally@{}", frame.span.start),
            Some(SyntheticBlockKind::Finally),
        );
        link(blocks, cur, finally_id);
        record_span(blocks, finally_id, frame.span);
        cur = walk_with_finally(
            frame.events,
            finally_id,
            exit,
            blocks,
            loop_targets,
            &pending_finally[..idx],
        );
    }
    link(blocks, cur, final_target);
}

/// Every `FlowEvent` carries a span; surface it so the builder can
/// set `BasicBlock::span` on the first event landing in a block.
fn flow_event_span(event: &FlowEvent) -> Span {
    event.span()
}

/// Set a block's `span` to its first real event. Later events don't
/// overwrite so the span marks the block's first statement.
fn record_span(blocks: &mut [BasicBlock], block_idx: usize, span: Span) {
    if blocks[block_idx].span.file == bonsai_common::FileId::INVALID {
        blocks[block_idx].span = span;
    }
}

/// Drop synthetic `unreachable` placeholders that carry no events and
/// have no incoming edges (byproduct of the walker emitting one after
/// every early terminator). Returns the remapped entry/exit ids plus
/// a dense block list — `successors` are rewritten in lockstep so
/// indices remain consistent.
fn compact_ids(
    blocks: Vec<BasicBlock>,
    entry: usize,
    exit: usize,
) -> (BasicBlockId, BasicBlockId, Vec<BasicBlock>) {
    let mut incoming = vec![0usize; blocks.len()];
    for block in &blocks {
        for successor in &block.successors {
            let idx = successor.raw() as usize;
            if idx < incoming.len() {
                incoming[idx] += 1;
            }
        }
    }
    let keep: Vec<bool> = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| {
            if idx == entry || idx == exit || !block.events.is_empty() {
                return true;
            }
            // Synthetic shape blocks stay even when empty — they
            // reveal the CFG's structure. The `Unreachable`
            // placeholder is pruned aggressively when nothing points
            // at it.
            if block
                .synthetic_kind
                .is_some_and(|kind| kind != SyntheticBlockKind::Unreachable)
            {
                return true;
            }
            incoming[idx] > 0
        })
        .collect();
    let mut remap = vec![usize::MAX; blocks.len()];
    let mut next = 0usize;
    for (idx, k) in keep.iter().enumerate() {
        if *k {
            remap[idx] = next;
            next += 1;
        }
    }
    let filtered: Vec<BasicBlock> = blocks
        .into_iter()
        .enumerate()
        .filter_map(|(idx, mut block)| {
            if !keep[idx] {
                return None;
            }
            block.id = BasicBlockId::new(remap[idx] as u32);
            block.successors = block
                .successors
                .into_iter()
                .filter_map(|successor| {
                    let new_idx = remap.get(successor.raw() as usize).copied()?;
                    if new_idx == usize::MAX {
                        None
                    } else {
                        Some(BasicBlockId::new(new_idx as u32))
                    }
                })
                .collect();
            Some(block)
        })
        .collect();
    (
        BasicBlockId::new(remap[entry] as u32),
        BasicBlockId::new(remap[exit] as u32),
        filtered,
    )
}

#[cfg(test)]
#[path = "builder_tests.rs"]
mod tests;
