use super::*;
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{CallKind, LoopControlTarget, LoopKind};

fn span(start: u32) -> Span {
    Span::new(FileId::new(0), u64::from(start), u64::from(start + 1))
}

fn return_event(start: u32) -> FlowEvent {
    FlowEvent::Return {
        span: span(start),
        value_text: None,
        value_name: None,
        value_kind: None,
        value_flow: Default::default(),
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
        catch_arms: Vec::new(),
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
            label: None,
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![
                FlowEvent::Break {
                    span: span(11),
                    target: None,
                },
                FlowEvent::Continue {
                    span: span(12),
                    target: None,
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
fn post_test_loop_enters_body_before_condition_header() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::DoWhile,
            label: None,
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![call_event(11, "body")],
        }],
    );
    let entry = cfg.block(cfg.entry).expect("entry block");
    let header = cfg
        .blocks
        .iter()
        .find(|block| block.synthetic_kind == Some(SyntheticBlockKind::LoopHeader))
        .expect("loop header");
    let body = cfg
        .blocks
        .iter()
        .find(|block| block.synthetic_kind == Some(SyntheticBlockKind::LoopBody))
        .expect("loop body");

    assert_eq!(entry.successors, vec![body.id]);
    assert!(!entry.successors.contains(&header.id));
    assert!(body.successors.contains(&header.id));
}

#[test]
fn unconditional_loop_has_no_implicit_after_edge() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::Loop,
            label: None,
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![call_event(11, "body")],
        }],
    );
    let header = cfg
        .blocks
        .iter()
        .find(|block| block.synthetic_kind == Some(SyntheticBlockKind::LoopHeader))
        .expect("loop header");
    let body = cfg
        .blocks
        .iter()
        .find(|block| block.synthetic_kind == Some(SyntheticBlockKind::LoopBody))
        .expect("loop body");
    let after = cfg
        .blocks
        .iter()
        .find(|block| block.synthetic_kind == Some(SyntheticBlockKind::LoopAfter))
        .expect("loop after");

    assert_eq!(header.successors, vec![body.id]);
    assert!(!header.successors.contains(&after.id));
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
            label: None,
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![try_finally(
                11,
                vec![FlowEvent::Break {
                    span: span(12),
                    target: None,
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
            label: None,
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![try_finally(
                11,
                vec![FlowEvent::Continue {
                    span: span(12),
                    target: None,
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

#[test]
fn labeled_break_targets_the_named_outer_loop() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::While,
            label: Some("outer".to_string()),
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![FlowEvent::Loop {
                span: span(20),
                loop_kind: LoopKind::While,
                label: Some("inner".to_string()),
                condition_events: Vec::new(),
                update_events: Vec::new(),
                body: vec![FlowEvent::Break {
                    span: span(30),
                    target: Some(LoopControlTarget::Label("outer".to_string())),
                }],
            }],
        }],
    );
    let outer_after = cfg
        .blocks
        .iter()
        .find(|block| block.label == "loop-after@10")
        .expect("outer after block")
        .id;
    let break_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Break)
        .expect("labeled break block");
    assert_eq!(break_block.successors, vec![outer_after]);
}

#[test]
fn labeled_continue_targets_the_named_outer_loop_header() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::While,
            label: Some("outer".to_string()),
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![FlowEvent::Loop {
                span: span(20),
                loop_kind: LoopKind::While,
                label: Some("inner".to_string()),
                condition_events: Vec::new(),
                update_events: Vec::new(),
                body: vec![FlowEvent::Continue {
                    span: span(30),
                    target: Some(LoopControlTarget::Label("outer".to_string())),
                }],
            }],
        }],
    );
    let outer_header = cfg
        .blocks
        .iter()
        .find(|block| block.label == "loop-header@10")
        .expect("outer header block")
        .id;
    let continue_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Continue)
        .expect("labeled continue block");
    assert_eq!(continue_block.successors, vec![outer_header]);
}

#[test]
fn lexical_level_break_targets_the_second_enclosing_loop() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::While,
            label: None,
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![FlowEvent::Loop {
                span: span(20),
                loop_kind: LoopKind::While,
                label: None,
                condition_events: Vec::new(),
                update_events: Vec::new(),
                body: vec![FlowEvent::Break {
                    span: span(30),
                    target: Some(LoopControlTarget::Levels(2)),
                }],
            }],
        }],
    );
    let outer_after = cfg
        .blocks
        .iter()
        .find(|block| block.label == "loop-after@10")
        .expect("outer after block")
        .id;
    let break_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Break)
        .expect("level break block");
    assert_eq!(break_block.successors, vec![outer_after]);
}

#[test]
fn lexical_level_continue_targets_the_second_enclosing_loop_header() {
    let cfg = build_cfg_from_flow(
        "f",
        &[FlowEvent::Loop {
            span: span(10),
            loop_kind: LoopKind::While,
            label: None,
            condition_events: Vec::new(),
            update_events: Vec::new(),
            body: vec![FlowEvent::Loop {
                span: span(20),
                loop_kind: LoopKind::While,
                label: None,
                condition_events: Vec::new(),
                update_events: Vec::new(),
                body: vec![FlowEvent::Continue {
                    span: span(30),
                    target: Some(LoopControlTarget::Levels(2)),
                }],
            }],
        }],
    );
    let outer_header = cfg
        .blocks
        .iter()
        .find(|block| block.label == "loop-header@10")
        .expect("outer header block")
        .id;
    let continue_block = cfg
        .blocks
        .iter()
        .find(|block| block.terminator == Terminator::Continue)
        .expect("level continue block");
    assert_eq!(continue_block.successors, vec![outer_header]);
}

#[test]
fn executable_flow_prunes_only_proven_dead_tail_events() {
    let flow = normalize_executable_flow(&[call_event(1, "before"), return_event(2), call_event(3, "dead")]);
    assert_eq!(flow, vec![call_event(1, "before"), return_event(2)]);
}

#[test]
fn executable_flow_orders_nested_throw_call_before_the_abrupt_event() {
    let outer = Span::new(FileId::new(0), 10, 45);
    let inner = Span::new(FileId::new(0), 20, 40);
    let dead = Span::new(FileId::new(0), 50, 60);
    let throw = FlowEvent::Throw {
        span: outer,
        value_name: None,
        thrown_type: Some("RuntimeException".to_string()),
    };
    let constructor = FlowEvent::Call {
        span: inner,
        name: "RuntimeException".to_string(),
        receiver: None,
        call_kind: CallKind::Constructor,
        args: Vec::new(),
        receiver_types: Vec::new(),
    };
    let unreachable = FlowEvent::Call {
        span: dead,
        name: "after".to_string(),
        receiver: None,
        call_kind: CallKind::Function,
        args: Vec::new(),
        receiver_types: Vec::new(),
    };

    assert_eq!(
        normalize_executable_flow(&[throw.clone(), constructor.clone(), unreachable]),
        vec![constructor, throw]
    );
}

#[test]
fn executable_flow_places_multiple_defers_at_scope_exit_in_lifo_order() {
    let flow = normalize_executable_flow(&[
        FlowEvent::Defer {
            span: span(1),
            body: vec![call_event(10, "first_cleanup")],
        },
        FlowEvent::Defer {
            span: span(2),
            body: vec![call_event(20, "second_cleanup")],
        },
        call_event(3, "body"),
        return_event(4),
        call_event(5, "dead"),
    ]);

    fn call_names(events: &[FlowEvent], out: &mut Vec<String>) {
        for event in events {
            match event {
                FlowEvent::Call { name, .. } => out.push(name.clone()),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    call_names(then_events, out);
                    call_names(else_events, out);
                }
                FlowEvent::Loop { body, .. } | FlowEvent::Using { body, .. } => {
                    call_names(body, out);
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    call_names(body, out);
                    call_names(catch_events, out);
                    call_names(finally_events, out);
                }
                FlowEvent::Defer { .. } => panic!("defer survived canonical normalization"),
                _ => {}
            }
        }
    }

    let mut names = Vec::new();
    call_names(&flow, &mut names);
    assert_eq!(names, ["body", "second_cleanup", "first_cleanup"]);
}
