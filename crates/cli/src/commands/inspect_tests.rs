use super::{walk_flow_hits, HitOut, InspectFilters, Matcher};
use crate::args::FactKindFilter;
use bonsai_common::{FileId, FuncId, Span};
use bonsai_lang_api::FlowEvent;
use bonsai_sdk::find_call_span_by_name;

fn span(start: u32) -> Span {
    Span {
        file: FileId(0),
        start: u64::from(start),
        end: u64::from(start + 1),
    }
}

fn assign_event() -> FlowEvent {
    FlowEvent::Assign {
        target: "user".to_string(),
        source_name: None,
        source_names: vec!["request".to_string()],
        source_call: Some("read_user".to_string()),
        source_call_args: vec!["request".to_string()],
        span: span(10),
        declares_new_binding: false,
        value_kind: None,
    }
}

#[test]
fn walk_flow_hits_surfaces_assignment_source_calls() {
    let matcher = Matcher::build(Some("read_user"), false).expect("matcher");
    let kinds = ahash::AHashSet::from_iter(["call".to_string()]);
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut out: Vec<HitOut> = Vec::new();
    let mut push = |kind: &str,
                    text: String,
                    _span: Span,
                    _containing: Option<(FuncId, String)>,
                    _exact: bool,
                    _out: &mut Vec<HitOut>| {
        seen.push((kind.to_string(), text));
    };

    walk_flow_hits(
        &[assign_event()],
        FuncId::new(1),
        "handler",
        &matcher,
        &kinds,
        &mut out,
        &mut push,
    );

    assert_eq!(seen, vec![("call".to_string(), "read_user".to_string())]);
}

#[test]
fn walk_flow_hits_surfaces_assignment_source_call_args() {
    let matcher = Matcher::build(Some("request"), false).expect("matcher");
    let kinds = ahash::AHashSet::from_iter(["arg".to_string()]);
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut out: Vec<HitOut> = Vec::new();
    let mut push = |kind: &str,
                    text: String,
                    _span: Span,
                    _containing: Option<(FuncId, String)>,
                    _exact: bool,
                    _out: &mut Vec<HitOut>| {
        seen.push((kind.to_string(), text));
    };

    walk_flow_hits(
        &[assign_event()],
        FuncId::new(1),
        "handler",
        &matcher,
        &kinds,
        &mut out,
        &mut push,
    );

    assert_eq!(seen, vec![("arg".to_string(), "request".to_string())]);
}

#[test]
fn find_call_span_matches_assignment_source_call() {
    assert_eq!(
        find_call_span_by_name(&[assign_event()], "read_user"),
        Some(span(10))
    );
}

#[test]
fn inspect_cli_filters_map_one_to_one_to_sdk_filters() {
    let cli = InspectFilters {
        from: Some("request"),
        from_kind: Some(FactKindFilter::Read),
        to: Some("os.system"),
        to_kind: Some(FactKindFilter::Call),
        file: Some("gateway.py"),
        in_fn: Some("handle_request"),
    };
    let sdk = cli.to_sdk();
    assert_eq!(sdk.from, Some("request"));
    assert_eq!(sdk.from_kind, Some(bonsai_sdk::FactKindFilter::Read));
    assert_eq!(sdk.to, Some("os.system"));
    assert_eq!(sdk.to_kind, Some(bonsai_sdk::FactKindFilter::Call));
    assert_eq!(sdk.file, Some("gateway.py"));
    assert_eq!(sdk.in_fn, Some("handle_request"));

    let all_kinds = [
        (FactKindFilter::Decl, bonsai_sdk::FactKindFilter::Decl),
        (FactKindFilter::Call, bonsai_sdk::FactKindFilter::Call),
        (FactKindFilter::Read, bonsai_sdk::FactKindFilter::Read),
        (FactKindFilter::Write, bonsai_sdk::FactKindFilter::Write),
        (FactKindFilter::Arg, bonsai_sdk::FactKindFilter::Arg),
        (FactKindFilter::StringLit, bonsai_sdk::FactKindFilter::StringLit),
        (FactKindFilter::Import, bonsai_sdk::FactKindFilter::Import),
        (FactKindFilter::Class, bonsai_sdk::FactKindFilter::Class),
    ];
    for (cli_kind, sdk_kind) in all_kinds {
        assert_eq!(cli_kind.to_sdk(), sdk_kind);
    }
}
