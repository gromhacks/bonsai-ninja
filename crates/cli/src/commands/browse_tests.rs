use super::{collect_callees, truncate};
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{CallKind, FlowEvent};

fn span() -> Span {
    Span {
        file: FileId(0),
        start: 0,
        end: 1,
    }
}

#[test]
fn truncate_zero_chars_keeps_only_ellipsis() {
    assert_eq!(truncate("abcdef", 0), "…");
    assert_eq!(truncate("éclair", 0), "…");
}

#[test]
fn collect_callees_includes_assignment_source_calls() {
    let events = vec![
        FlowEvent::Assign {
            target: "x".to_string(),
            source_name: None,
            source_names: Vec::new(),
            source_call: Some("read_user".to_string()),
            source_call_args: vec!["request".to_string()],
            span: span(),
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            name: "sink".to_string(),
            receiver: None,
            args: Vec::new(),
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            span: span(),
        },
    ];
    let mut out = Vec::new();
    collect_callees(&events, &mut out);
    assert_eq!(out, vec!["read_user", "sink"]);
}
