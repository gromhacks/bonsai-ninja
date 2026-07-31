use super::*;
use bonsai_common::FileId;

#[test]
fn drops_assignment_args_shadowed_by_real_call_args() {
    let mut facts = vec![
        fact("eval", 0, "py_expr", 10, ArgOrigin::RealCall),
        fact("eval", 1, "{\"attributes\": attributes}", 19, ArgOrigin::RealCall),
        fact("eval", 0, "py_expr", 5, ArgOrigin::AssignmentSourceCall),
        fact(
            "eval",
            1,
            "{\"attributes\": attributes}",
            5,
            ArgOrigin::AssignmentSourceCall,
        ),
        fact("other", 0, "py_expr", 5, ArgOrigin::AssignmentSourceCall),
    ];

    drop_shadowed_assignment_args(&mut facts);

    assert_eq!(facts.len(), 3);
    assert_eq!(
        facts
            .iter()
            .map(|fact| (fact.out.callee.as_str(), fact.out.position, fact.origin))
            .collect::<Vec<_>>(),
        vec![
            ("eval", 0, ArgOrigin::RealCall),
            ("eval", 1, ArgOrigin::RealCall),
            ("other", 0, ArgOrigin::AssignmentSourceCall),
        ]
    );
}

#[test]
fn drops_multiline_assignment_args_by_span_containment() {
    let mut real = fact("client.execute", 0, "request.payload", 17, ArgOrigin::RealCall);
    real.out.line = 43;
    real.source_span = Span::new(FileId::new(0), 140, 155);
    let mut assignment = fact(
        "client.execute",
        0,
        "request.payload",
        5,
        ArgOrigin::AssignmentSourceCall,
    );
    assignment.out.line = 42;
    assignment.source_span = Span::new(FileId::new(0), 100, 180);
    let mut facts = vec![assignment, real];

    drop_shadowed_assignment_args(&mut facts);

    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].origin, ArgOrigin::RealCall);
    assert_eq!(facts[0].out.line, 43);
}

fn fact(callee: &str, position: usize, value: &str, column: u32, origin: ArgOrigin) -> ArgFact {
    let source_span = match origin {
        ArgOrigin::RealCall => Span::new(FileId::new(0), u64::from(column), u64::from(column + 1)),
        ArgOrigin::AssignmentSourceCall => Span::new(FileId::new(0), 0, 100),
    };
    ArgFact {
        out: ArgOut {
            resolution_scope: ARG_RESOLUTION_SCOPE,
            callee: callee.to_string(),
            position,
            keyword: None,
            value: value.to_string(),
            file: "app.py".to_string(),
            line: 42,
            column,
        },
        origin,
        source_span,
    }
}
