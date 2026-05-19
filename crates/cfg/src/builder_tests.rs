use super::*;
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{CallKind, LoopKind};

fn span(start: u32) -> Span {
    Span::new(FileId::new(0), u64::from(start), u64::from(start + 1))
}

fn return_event(start: u32) -> FlowEvent {
    FlowEvent::Return {
        span: span(start),
        value_text: None,
        value_name: None,
    }
}

fn throw_event(start: u32) -> FlowEvent {
    FlowEvent::Throw {
        span: span(start),
        value_name: None,
        thrown_type: None,
    }
}

fn call_event(start: u32, name: &str) -> FlowEvent {
    FlowEvent::Call {
        span: span(start),
        name: name.to_string(),
        receiver: None,
        call_kind: CallKind::Function,
        args: Vec::new(),
        receiver_types: Vec::new(),
    }
}

fn try_finally(start: u32, body: Vec<FlowEvent>, finally_events: Vec<FlowEvent>) -> FlowEvent {
    FlowEvent::Try {
        span: span(start),
        body,
        catch_events: Vec::new(),
        finally_events,
        catch_param: None,
        catch_types: Vec::new(),
    }
}

fn block_has_call(block: &BasicBlock, name: &str) -> bool {
    block.events.iter().any(|event| {
        matches!(
            event,
            FlowEvent::Call {
                name: call_name,
                ..
            } if call_name == name
        )
    })
}

#[test]
fn return_block_has_no_successors() {
    let cfg = build_cfg_from_flow("f", &[return_event(1)]);
    let return_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Return)
        .unwrap();

    assert!(return_block.successors.is_empty());
}

#[test]
fn synthetic_shape_blocks_are_structural_not_label_parsed() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Branch {
            span: span(10),
            condition: None,
            then_events: Vec::new(),
            else_events: Vec::new(),
        }],
    );
    assert!(
        cfg.blocks
            .iter()
            .any(|block| block.synthetic_kind == Some(SyntheticBlockKind::BranchJoin)),
        "branch join must be retained by structured synthetic kind, not label prefix"
    );
}

#[test]
fn loop_break_targets_after_block_and_continue_targets_header() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::While,
            body: vec![
                FlowEvent::Break {
                    span: span(11),
                    label: None,
                },
                FlowEvent::Continue {
                    span: span(12),
                    label: None,
                },
            ],
        }],
    );
    let header = cfg
        .blocks
        .iter()
        .find(|block| block.label.starts_with("loop-header@"))
        .unwrap()
        .id;
    let after = cfg
        .blocks
        .iter()
        .find(|block| block.label.starts_with("loop-after@"))
        .unwrap()
        .id;
    let break_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Break)
        .unwrap();
    let continue_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Continue)
        .unwrap();

    assert_eq!(break_block.successors, vec![after]);
    assert_eq!(continue_block.successors, vec![header]);
}

#[test]
fn return_inside_try_finally_runs_cleanup_then_exits() {
    let cfg = build_cfg_from_flow(
        "f",
        &[
            try_finally(10, vec![return_event(11)], vec![call_event(12, "cleanup")]),
            call_event(13, "after"),
        ],
    );
    let return_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Return)
        .unwrap();
    assert_eq!(return_block.successors.len(), 1);

    let cleanup = cfg.block(return_block.successors[0]).unwrap();
    assert_eq!(cleanup.synthetic_kind, Some(SyntheticBlockKind::Finally));
    assert!(block_has_call(cleanup, "cleanup"));
    assert_eq!(cleanup.successors, vec![cfg.exit]);
}

#[test]
fn throw_inside_try_finally_runs_cleanup_then_exits() {
    let cfg = build_cfg_from_flow(
        "f",
        &[
            try_finally(10, vec![throw_event(11)], vec![call_event(12, "cleanup")]),
            call_event(13, "after"),
        ],
    );
    let throw_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Throw)
        .unwrap();
    assert_eq!(throw_block.successors.len(), 1);

    let cleanup = cfg.block(throw_block.successors[0]).unwrap();
    assert_eq!(cleanup.synthetic_kind, Some(SyntheticBlockKind::Finally));
    assert!(block_has_call(cleanup, "cleanup"));
    assert_eq!(cleanup.successors, vec![cfg.exit]);
}

#[test]
fn break_inside_try_finally_runs_cleanup_then_loop_after() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::While,
            body: vec![try_finally(
                11,
                vec![FlowEvent::Break {
                    span: span(12),
                    label: None,
                }],
                vec![call_event(13, "cleanup")],
            )],
        }],
    );
    let after = cfg
        .blocks
        .iter()
        .find(|block| block.label.starts_with("loop-after@"))
        .unwrap()
        .id;
    let break_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Break)
        .unwrap();
    assert_eq!(break_block.successors.len(), 1);

    let cleanup = cfg.block(break_block.successors[0]).unwrap();
    assert_eq!(cleanup.synthetic_kind, Some(SyntheticBlockKind::Finally));
    assert!(block_has_call(cleanup, "cleanup"));
    assert_eq!(cleanup.successors, vec![after]);
}

#[test]
fn continue_inside_try_finally_runs_cleanup_then_loop_header() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::While,
            body: vec![try_finally(
                11,
                vec![FlowEvent::Continue {
                    span: span(12),
                    label: None,
                }],
                vec![call_event(13, "cleanup")],
            )],
        }],
    );
    let header = cfg
        .blocks
        .iter()
        .find(|block| block.label.starts_with("loop-header@"))
        .unwrap()
        .id;
    let continue_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Continue)
        .unwrap();
    assert_eq!(continue_block.successors.len(), 1);

    let cleanup = cfg.block(continue_block.successors[0]).unwrap();
    assert_eq!(cleanup.synthetic_kind, Some(SyntheticBlockKind::Finally));
    assert!(block_has_call(cleanup, "cleanup"));
    assert_eq!(cleanup.successors, vec![header]);
}
