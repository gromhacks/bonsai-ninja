use super::*;
use bonsai_common::{FileId, Span};

/// Build an `Assign` event. Span is a throwaway — assign-chain
/// doesn't use it — but the types require one.
fn assign(target: &str, source: Option<&str>) -> FlowEvent {
    FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 0, 0),
        target: target.to_string(),
        source_name: source.map(str::to_string),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }
}

fn call(name: &str) -> FlowEvent {
    FlowEvent::Call {
        span: Span::new(FileId::INVALID, 0, 0),
        name: name.to_string(),
        receiver: None,
        call_kind: bonsai_lang_api::CallKind::Function,
        args: Vec::new(),
        receiver_types: Vec::new(),
    }
}

fn assign_call_args(target: &str, callee: &str, args: &[&str]) -> FlowEvent {
    FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 0, 0),
        target: target.to_string(),
        source_name: None,
        source_call: Some(callee.to_string()),
        source_call_args: args.iter().map(|arg| (*arg).to_string()).collect(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }
}

fn branch(then_events: Vec<FlowEvent>, else_events: Vec<FlowEvent>) -> FlowEvent {
    FlowEvent::Branch {
        span: Span::new(FileId::INVALID, 0, 0),
        condition: None,
        then_events,
        else_events,
    }
}

fn loop_body(body: Vec<FlowEvent>) -> FlowEvent {
    FlowEvent::Loop {
        span: Span::new(FileId::INVALID, 0, 0),
        loop_kind: bonsai_lang_api::LoopKind::While,
        body,
    }
}

fn try_event(
    body: Vec<FlowEvent>,
    catch_events: Vec<FlowEvent>,
    finally_events: Vec<FlowEvent>,
) -> FlowEvent {
    FlowEvent::Try {
        span: Span::new(FileId::INVALID, 0, 0),
        body,
        catch_events,
        finally_events,
        catch_param: None,
        catch_types: Vec::new(),
    }
}

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

#[test]
fn seed_alone_is_returned_unchanged_for_empty_events() {
    let out = assign_chain_taints(&seed(&["recv"]), &[]);
    assert!(out.contains("recv"));
    assert_eq!(out.len(), 1);
}

#[test]
fn direct_assignment_propagates_taint() {
    // `x = recv()` — if recv is tainted, x becomes tainted.
    let events = vec![assign("x", Some("recv"))];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("x"), "x should be tainted from recv");
}

#[test]
fn two_hop_assignment_chain_propagates() {
    // x = recv(); y = x; z = y; — all three derived names tainted.
    let events = vec![
        assign("x", Some("recv")),
        assign("y", Some("x")),
        assign("z", Some("y")),
    ];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("x"));
    assert!(out.contains("y"));
    assert!(out.contains("z"));
}

#[test]
fn call_argument_expression_tokens_propagate_to_target() {
    let events = vec![
        assign("routed", Some("envelope")),
        assign_call_args(
            "valid",
            "Try",
            &["envelope.copy(cmd = routed, user = user, length = routed.length)"],
        ),
    ];
    let out = assign_chain_taints(&seed(&["envelope"]), &events);
    assert!(out.contains("routed"));
    assert!(out.contains("valid"));
}

#[test]
fn call_callee_expression_tokens_propagate_to_target() {
    let events = vec![
        assign("routed", Some("envelope")),
        FlowEvent::Assign {
            span: Span::new(FileId::INVALID, 0, 0),
            target: "valid".to_string(),
            source_name: None,
            source_call: Some(
                "(|| -> Result<Envelope, &str> { Ok(Envelope { cmd: routed.clone() }) })().unwrap_or_else"
                    .to_string(),
            ),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
    ];
    let out = assign_chain_taints(&seed(&["envelope"]), &events);
    assert!(out.contains("routed"));
    assert!(out.contains("valid"));
}

#[test]
fn multiline_closure_argument_tokens_propagate_to_target() {
    let events = vec![
        assign("routed", Some("envelope")),
        assign_call_args(
            "valid",
            "(|| -> Result<Envelope, &str> { Ok(Envelope { cmd: routed.clone() }) })().unwrap_or_else",
            &["|_| Envelope {\n        kind: envelope.kind.clone(),\n        cmd: routed.clone(),\n        user: user.clone(),\n        length: routed.len(),\n        extras: envelope.extras.clone(),\n    }"],
        ),
    ];
    let out = assign_chain_taints(&seed(&["envelope"]), &events);
    assert!(out.contains("routed"));
    assert!(out.contains("valid"));
}

#[test]
fn chain_breaks_when_source_is_not_tainted() {
    // x = recv(); y = other; z = y; — x tainted, y/z not.
    let events = vec![
        assign("x", Some("recv")),
        assign("y", Some("other")),
        assign("z", Some("y")),
    ];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("x"));
    assert!(!out.contains("y"));
    assert!(!out.contains("z"));
}

#[test]
fn source_name_none_does_not_taint_target() {
    // Compound RHS expressions (`x + 1`, `f(y)`) leave
    // source_name = None in most adapters — assign-chain
    // conservatively skips them. The intraprocedural pass can
    // enrich with expression-level flow.
    let events = vec![assign("x", None)];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(!out.contains("x"));
}

#[test]
fn assignment_from_seed_into_empty_target_is_ignored() {
    // Malformed adapter output — empty target. Assign-chain
    // just skips.
    let events = vec![assign("", Some("recv"))];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert_eq!(out.len(), 1, "only the seed should be present");
}

#[test]
fn monotonic_reassignment_does_not_clear_taint() {
    // x = recv(); x = 5; — assign-chain keeps x tainted. The
    // intraprocedural pass's CFG-ordered propagation is what
    // clears taint on reassignment-from-clean; assign-chain is
    // monotonic.
    let events = vec![
        assign("x", Some("recv")),
        assign("x", None), // reassign from compound expression / literal
    ];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("x"), "assign-chain is monotonic — x stays tainted");
}

#[test]
fn branch_joins_taint_from_both_arms() {
    // if c: y = x else: y = q — y tainted in at least the `then`
    // arm, so the join contains y.
    let events = vec![
        assign("x", Some("recv")),
        branch(vec![assign("y", Some("x"))], vec![assign("y", Some("q"))]),
    ];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("y"), "branch join must union taint");
}

#[test]
fn branch_taint_from_one_arm_doesnt_require_both() {
    // Only the then-arm taints — still propagates because the
    // branch join is a union. Security semantics: if ANY path
    // taints a name, treat it as tainted.
    let events = vec![
        assign("x", Some("recv")),
        branch(vec![assign("y", Some("x"))], vec![]),
    ];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("y"));
}

#[test]
fn loop_body_taints_propagate_out() {
    // for i in items: x = recv(); y = x; — y tainted after the
    // loop because the body runs at least once (conservatively).
    let events = vec![loop_body(vec![assign("x", Some("recv")), assign("y", Some("x"))])];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("x"));
    assert!(out.contains("y"));
}

#[test]
fn try_catch_finally_all_contribute_taint() {
    // Each region walked; any assignment in any region
    // contributes to the union.
    let events = vec![try_event(
        vec![assign("a", Some("recv"))],
        vec![assign("b", Some("recv"))],
        vec![assign("c", Some("recv"))],
    )];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("a"));
    assert!(out.contains("b"));
    assert!(out.contains("c"));
}

#[test]
fn target_is_tainted_predicate_matches_full_set() {
    let events = vec![assign("x", Some("recv")), assign("y", Some("x"))];
    let seed_set = seed(&["recv"]);
    assert!(target_is_tainted(&seed_set, "x", &events));
    assert!(target_is_tainted(&seed_set, "y", &events));
    assert!(!target_is_tainted(&seed_set, "z", &events));
}

#[test]
fn call_events_do_not_taint_caller_scope() {
    // A tainted-argument call is the interprocedural pass's
    // territory. Assign-chain on its own shouldn't infer
    // cross-function taint.
    let events = vec![call("sink"), assign("x", Some("recv"))];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("x"));
    assert_eq!(
        out.len(),
        2,
        "only seed + x should be tainted; call doesn't add anything"
    );
}

#[test]
fn multiple_seeds_all_propagate_independently() {
    // Two sources, two derived names — each chain taints its own
    // target without cross-contaminating the other.
    let events = vec![
        assign("a", Some("src1")),
        assign("b", Some("src2")),
        assign("c", Some("unrelated")),
    ];
    let out = assign_chain_taints(&seed(&["src1", "src2"]), &events);
    assert!(out.contains("a"));
    assert!(out.contains("b"));
    assert!(!out.contains("c"));
}

#[test]
fn nested_branches_preserve_ordering_within_arms() {
    // Outer branch whose then-arm contains an inner branch;
    // taint should propagate through the inner structure.
    let events = vec![
        assign("x", Some("recv")),
        branch(vec![branch(vec![assign("y", Some("x"))], vec![])], vec![]),
    ];
    let out = assign_chain_taints(&seed(&["recv"]), &events);
    assert!(out.contains("y"));
}
