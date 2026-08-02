use super::trace_page_rows;
use bonsai_common::Precision;
use bonsai_sdk::{PathSummary, PathTermination, TraceResult, TraceStep, TraceStepKind};

fn step(id: u64, path_id: u64, code: &str) -> TraceStep {
    TraceStep {
        id,
        path_id,
        order: id + 1,
        kind: TraceStepKind::Call,
        message: "call target".to_string(),
        function: "target".to_string(),
        module: "fixture".to_string(),
        file: "fixture.py".to_string(),
        span: Default::default(),
        code: code.to_string(),
        state_before: None,
        state_after: None,
        precision: Precision::Exact,
        notes: Vec::new(),
    }
}

#[test]
fn programmatic_trace_pages_retain_the_steps_for_each_path() {
    let trace = TraceResult {
        paths: vec![
            PathSummary {
                path_id: 7,
                first_step: 0,
                last_step: 1,
                path_constraints: Vec::new(),
                terminated_by: PathTermination::Return,
                precision: Precision::Exact,
            },
            PathSummary {
                path_id: 9,
                first_step: 2,
                last_step: 2,
                path_constraints: Vec::new(),
                terminated_by: PathTermination::Throw,
                precision: Precision::Exact,
            },
        ],
        steps: vec![
            step(0, 7, "first()"),
            step(1, 7, "second()"),
            step(2, 9, "other()"),
        ],
        ..TraceResult::default()
    };

    let rows = trace_page_rows(&trace);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].path.path_id, 7);
    assert_eq!(rows[0].steps[0].id, 0);
    assert_eq!(rows[1].steps[0].id, 1);
    assert_eq!(rows[2].path.path_id, 9);
    assert_eq!(rows[2].steps[0].id, 2);
    assert!(rows.iter().all(|row| row.cost > 384));
}
