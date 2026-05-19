use super::*;

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

fn fact(callee: &str, position: usize, value: &str, column: u32, origin: ArgOrigin) -> ArgFact {
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
    }
}
