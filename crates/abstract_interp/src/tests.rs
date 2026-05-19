use super::*;
use bonsai_cfg::{BasicBlock, Cfg, Terminator};
use bonsai_common::{BasicBlockId, FileId};

fn span(start: u64, end: u64) -> Span {
    Span::new(FileId::new(1), start, end)
}

fn assign(span: Span, target: &str, source_name: &str) -> FlowEvent {
    FlowEvent::Assign {
        span,
        target: target.to_string(),
        source_name: Some(source_name.to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }
}

fn block(
    id: u32,
    label: &str,
    events: Vec<FlowEvent>,
    successors: Vec<u32>,
    terminator: Terminator,
) -> BasicBlock {
    BasicBlock {
        id: BasicBlockId::new(id),
        label: label.to_string(),
        synthetic_kind: None,
        events,
        successors: successors.into_iter().map(BasicBlockId::new).collect(),
        terminator,
        span: span(u64::from(id), u64::from(id + 1)),
    }
}

#[test]
fn run_entry_merges_branch_states_at_join_blocks() {
    let cfg = Cfg {
        analysis_complete: true,
        analysis_incomplete_reasons: Vec::new(),
        function: "handle".to_string(),
        entry: BasicBlockId::new(0),
        exit: BasicBlockId::new(3),
        blocks: vec![
            block(0, "entry", Vec::new(), vec![1, 2], Terminator::Branch),
            block(
                1,
                "then",
                vec![assign(span(10, 11), "x", "1")],
                vec![3],
                Terminator::Fallthrough,
            ),
            block(
                2,
                "else",
                vec![assign(span(20, 21), "x", "2")],
                vec![3],
                Terminator::Fallthrough,
            ),
            block(
                3,
                "join",
                vec![assign(span(30, 31), "y", "x")],
                Vec::new(),
                Terminator::Fallthrough,
            ),
        ],
    };

    let trace = run_entry(FuncId::new(7), &cfg, TraceLimits::default());

    assert!(
        trace.steps.iter().any(|step| step.kind == StepKind::Merge),
        "abstract interpretation must join incoming branch states instead of dropping the second path"
    );
    assert!(
        trace
            .steps
            .iter()
            .filter(|step| step.kind == StepKind::Assign && step.message == "assign y")
            .count()
            >= 1,
        "join block should still execute after state merge"
    );
}

#[test]
fn exec_state_merge_uses_abstract_value_join() {
    let mut left = ExecState::new(FuncId::new(1), BasicBlockId::new(0));
    left.locals.insert("x".to_string(), AbstractValue::ConstInt(1));
    let mut right = ExecState::new(FuncId::new(1), BasicBlockId::new(0));
    right.locals.insert("x".to_string(), AbstractValue::ConstInt(2));

    assert!(left.merge_from(&right));
    assert_eq!(
        left.locals.get("x"),
        Some(&AbstractValue::Set(vec![
            AbstractValue::ConstInt(1),
            AbstractValue::ConstInt(2)
        ]))
    );
}
