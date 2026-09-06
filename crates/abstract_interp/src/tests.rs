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

fn scalar_fact(span: Span, target: &str, value: StaticScalarValue) -> AssignmentValueFact {
    AssignmentValueFact {
        assignment_span: span,
        target: Some(target.into()),
        target_is_immutable: false,
        target_owner: None,
        target_span: None,
        value_span: span,
        call_sites: Vec::new(),
        value_flow: Default::default(),
        static_value: Some(value),
        exact_callable_return: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        exact_static_call_args: None,
        direct_call_name: None,
        direct_call_span: None,
        direct_call_receiver: None,
        direct_call_receiver_span: None,
        direct_call_receiver_flow: None,
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

    let facts = [
        scalar_fact(span(10, 11), "x", StaticScalarValue::Integer(1)),
        scalar_fact(span(20, 21), "x", StaticScalarValue::Integer(2)),
    ];
    let trace = run_entry_with_assignment_values(FuncId::new(7), &cfg, TraceLimits::default(), &facts);

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
fn assignment_does_not_infer_values_from_identifier_spelling_or_call_arguments() {
    let mut state = ExecState::new(FuncId::new(1), BasicBlockId::new(0));
    for name in ["nil", "True", "123", "\"not a decoded literal\""] {
        apply_event(&mut state, &assign(span(1, 2), "out", name), &[]);
        assert_eq!(state.locals["out"], AbstractValue::Unknown, "{name}");
    }
    state.locals.insert("arg".into(), AbstractValue::ConstInt(7));
    for call in [false, true] {
        let event = FlowEvent::Assign {
            span: span(1, 2),
            target: "out".into(),
            source_name: None,
            source_call: call.then(|| "transform".into()),
            source_call_args: if call { vec!["arg".into()] } else { Vec::new() },
            source_names: if call { Vec::new() } else { vec!["arg".into()] },
            declares_new_binding: false,
            value_kind: None,
        };
        apply_event(&mut state, &event, &[]);
        assert_eq!(state.locals["out"], AbstractValue::Unknown);
    }
}

#[test]
fn exec_state_merge_does_not_claim_a_constant_missing_on_an_incoming_path() {
    for defined_first in [false, true] {
        let mut defined = ExecState::new(FuncId::new(1), BasicBlockId::new(0));
        defined.locals.insert("x".into(), AbstractValue::ConstInt(1));
        let missing = ExecState::new(FuncId::new(1), BasicBlockId::new(0));
        let (mut left, right) = if defined_first {
            (defined, missing)
        } else {
            (missing, defined)
        };
        assert!(left.merge_from(&right));
        assert_eq!(left.locals.get("x"), Some(&AbstractValue::Unknown));
        assert!(!left.merge_from(&right), "join must stabilize");
    }
}

#[test]
fn run_entry_preserves_cfg_incompleteness() {
    let trace = run_entry(FuncId::new(7), &Cfg::default(), TraceLimits::default());
    assert!(
        !trace.incomplete_reasons.is_empty(),
        "a missing function cannot yield a complete trace"
    );
    assert!(trace.steps.is_empty(), "there is no entry body to claim");
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
fn assignment_uses_exact_typed_scalars_and_bare_name_copies_only() {
    let mut state = ExecState::new(FuncId::new(1), BasicBlockId::new(0));
    for (scalar, expected) in [
        (StaticScalarValue::Integer(10), AbstractValue::ConstInt(10)),
        (StaticScalarValue::Boolean(true), AbstractValue::ConstBool(true)),
        (
            StaticScalarValue::String("decoded\ntext".into()),
            AbstractValue::ConstString("decoded\ntext".into()),
        ),
        (StaticScalarValue::Null, AbstractValue::Null),
    ] {
        let fact = scalar_fact(span(10, 11), "x", scalar);
        apply_event(
            &mut state,
            &assign(span(10, 11), "x", "unknown"),
            std::slice::from_ref(&fact),
        );
        assert_eq!(state.locals["x"], expected);
        apply_event(&mut state, &assign(span(20, 21), "y", "x"), &[]);
        assert_eq!(state.locals["y"], expected);
        apply_event(
            &mut state,
            &assign(span(10, 11), "other_target", "unknown"),
            &[fact],
        );
        assert_eq!(state.locals["other_target"], AbstractValue::Unknown);
    }
}
