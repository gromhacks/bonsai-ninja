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
            .filter(|step| step.kind == StepKind::Assign && step.message == "assign y = x")
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
        Some(&AbstractValue::IntRange(IntRange::new(Some(1), Some(2))))
    );
}

#[test]
fn abstract_value_join_promotes_numeric_constants_to_ranges() {
    let joined = AbstractValue::ConstInt(4).join(AbstractValue::ConstInt(9));
    assert_eq!(joined, AbstractValue::IntRange(IntRange::new(Some(4), Some(9))));
    let widened = joined.join(AbstractValue::ConstInt(-1));
    assert_eq!(widened.int_range(), Some(IntRange::new(Some(-1), Some(9))));
    assert!(widened.int_range().is_some_and(|range| range.contains(7)));
}

#[test]
fn abstract_value_tracks_boolean_and_nullness_facets() {
    let bools = AbstractValue::ConstBool(true).join(AbstractValue::ConstBool(false));
    assert_eq!(bools.bool_domain(), Some(BoolDomain::any()));

    let maybe_object = AbstractValue::Object(bonsai_common::TypeId::new(3)).join(AbstractValue::Null);
    assert_eq!(maybe_object.nullness(), Nullness::MaybeNull);
    assert_eq!(
        AbstractValue::ConstString("x".into()).nullness(),
        Nullness::NonNull
    );
}

#[test]
fn abstract_value_exposes_string_length_ranges() {
    let joined = AbstractValue::StringWithLength(IntRange::new(Some(2), Some(8)))
        .join(AbstractValue::ConstString("hello".into()));
    assert_eq!(
        joined.string_length_range(),
        Some(IntRange::new(Some(2), Some(8)))
    );
}

#[test]
fn exec_state_merge_keeps_only_relations_common_to_all_incoming_paths() {
    let common = ValueRelation {
        left: "idx".to_string(),
        op: RelationOp::Lt,
        right: RelationTerm::Var("len".to_string()),
    };
    let then_only = ValueRelation {
        left: "ptr".to_string(),
        op: RelationOp::NotEq,
        right: RelationTerm::Null,
    };
    let else_only = ValueRelation {
        left: "flag".to_string(),
        op: RelationOp::Eq,
        right: RelationTerm::Bool(true),
    };
    let mut left = ExecState::new(FuncId::new(1), BasicBlockId::new(0));
    left.assume_relation(common.clone());
    left.assume_relation(then_only);
    let mut right = ExecState::new(FuncId::new(1), BasicBlockId::new(0));
    right.assume_relation(common.clone());
    right.assume_relation(else_only);

    assert!(left.merge_from(&right));
    assert_eq!(
        left.relations,
        vec![common],
        "relations proven on only one predecessor must not be treated as true after a join"
    );
}

#[test]
fn run_entry_merges_branch_numeric_assignments_into_range() {
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
                vec![assign(span(10, 11), "x", "10")],
                vec![3],
                Terminator::Fallthrough,
            ),
            block(
                2,
                "else",
                vec![assign(span(20, 21), "x", "20")],
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
        "numeric range joins should still emit merge evidence"
    );
}
