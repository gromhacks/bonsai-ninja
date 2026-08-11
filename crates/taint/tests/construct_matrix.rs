//! Exhaustive flow-construct coverage for the assign-chain +
//! intraprocedural + interprocedural passes.
//!
//! Every [`FlowEvent`] variant gets a positive test (taint should
//! propagate through the construct) and a false-path test (taint
//! should NOT propagate where a naive walk might let it).
//!
//! Tests are organized by **pass**, then by **construct**:
//! `<pass>_<construct>_<positive|false_path>`. Each test is a few
//! lines using the shared builders at the top so the matrix is easy
//! to audit at a glance.

use bonsai_common::{FileId, Span};
use bonsai_lang_api::{CallArg, CallKind, FlowEvent, LoopKind};
use bonsai_taint::{assign_chain_taints, intraprocedural_taint, IntraTaintResult, TaintConfig, TokenSet};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn span() -> Span {
    Span::new(FileId::INVALID, 0, 0)
}

fn assign(target: &str, source: Option<&str>) -> FlowEvent {
    FlowEvent::Assign {
        span: span(),
        target: target.to_string(),
        source_name: source.map(str::to_string),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }
}

fn assign_sources(target: &str, sources: &[&str]) -> FlowEvent {
    FlowEvent::Assign {
        span: span(),
        target: target.to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: sources.iter().map(|source| (*source).to_string()).collect(),
        declares_new_binding: false,
        value_kind: None,
    }
}

fn call(name: &str, args: &[&str]) -> FlowEvent {
    FlowEvent::Call {
        span: span(),
        name: name.to_string(),
        receiver: None,
        call_kind: CallKind::Function,
        args: args
            .iter()
            .map(|text| CallArg {
                passing_mode: Default::default(),
                span: span(),
                name: None,
                place: None,
                source_names: Vec::new(),
                value_text: (*text).to_string(),
            })
            .collect(),
        receiver_types: Vec::new(),
    }
}

fn branch(then_events: Vec<FlowEvent>, else_events: Vec<FlowEvent>) -> FlowEvent {
    FlowEvent::Branch {
        span: span(),
        condition: None,
        then_events,
        else_events,
    }
}

fn loop_body(body: Vec<FlowEvent>) -> FlowEvent {
    FlowEvent::Loop {
        span: span(),
        loop_kind: LoopKind::While,
        body,
    }
}

fn try_event(
    body: Vec<FlowEvent>,
    catch_events: Vec<FlowEvent>,
    finally_events: Vec<FlowEvent>,
) -> FlowEvent {
    FlowEvent::Try {
        span: span(),
        body,
        catch_events,
        finally_events,
        catch_param: None,
        catch_types: Vec::new(),
    }
}

fn defer(body: Vec<FlowEvent>) -> FlowEvent {
    FlowEvent::Defer { span: span(), body }
}

fn using(body: Vec<FlowEvent>) -> FlowEvent {
    FlowEvent::Using { span: span(), body }
}

fn flow_return() -> FlowEvent {
    FlowEvent::Return {
        span: span(),
        value_kind: None,
        value_text: None,
        value_name: None,
        value_flow: Default::default(),
    }
}

fn throw() -> FlowEvent {
    FlowEvent::Throw {
        span: span(),
        value_name: None,
        thrown_type: None,
    }
}

fn yield_event(value: Option<&str>) -> FlowEvent {
    FlowEvent::Yield {
        span: span(),
        value_text: value.map(str::to_string),
        value_flow: value.map_or_else(Default::default, bonsai_lang_api::ExpressionFlow::from_place),
    }
}

fn await_event() -> FlowEvent {
    FlowEvent::Await {
        span: span(),
        value_name: None,
    }
}

fn break_event() -> FlowEvent {
    FlowEvent::Break {
        span: span(),
        label: None,
    }
}

fn continue_event() -> FlowEvent {
    FlowEvent::Continue {
        span: span(),
        label: None,
    }
}

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

// ---------------------------------------------------------------------------
// assign-chain
// ---------------------------------------------------------------------------

#[test]
fn assign_chain_assign_positive() {
    let out = assign_chain_taints(&seed(&["src"]), &[assign("x", Some("src"))]);
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_assign_false_path_unrelated_source() {
    // x = other — other is not tainted, so x shouldn't taint.
    let out = assign_chain_taints(&seed(&["src"]), &[assign("x", Some("other"))]);
    assert!(!out.contains("x"), "unrelated source must not taint target");
}

#[test]
fn assign_chain_call_positive_does_not_taint_caller() {
    // call() has no direct taint-propagation rule in assign-chain.
    let out = assign_chain_taints(&seed(&["src"]), &[call("sink", &["src"])]);
    assert_eq!(
        out.len(),
        1,
        "assign-chain must not taint caller scope from a call event",
    );
}

#[test]
fn assign_chain_branch_positive_then_arm() {
    let out = assign_chain_taints(&seed(&["src"]), &[branch(vec![assign("x", Some("src"))], vec![])]);
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_branch_positive_else_arm() {
    let out = assign_chain_taints(&seed(&["src"]), &[branch(vec![], vec![assign("x", Some("src"))])]);
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_branch_false_path_no_assignment() {
    // Branch that touches nothing tainted shouldn't manufacture taint.
    let out = assign_chain_taints(
        &seed(&["src"]),
        &[branch(vec![assign("y", Some("q"))], vec![assign("z", Some("r"))])],
    );
    assert!(!out.contains("y"));
    assert!(!out.contains("z"));
}

#[test]
fn assign_chain_loop_positive() {
    let out = assign_chain_taints(&seed(&["src"]), &[loop_body(vec![assign("x", Some("src"))])]);
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_loop_false_path_unrelated_body() {
    let out = assign_chain_taints(&seed(&["src"]), &[loop_body(vec![assign("x", Some("other"))])]);
    assert!(!out.contains("x"));
}

#[test]
fn assign_chain_try_positive_body_taints() {
    let out = assign_chain_taints(
        &seed(&["src"]),
        &[try_event(vec![assign("x", Some("src"))], vec![], vec![])],
    );
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_try_positive_catch_taints() {
    let out = assign_chain_taints(
        &seed(&["src"]),
        &[try_event(vec![], vec![assign("x", Some("src"))], vec![])],
    );
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_try_positive_finally_taints() {
    let out = assign_chain_taints(
        &seed(&["src"]),
        &[try_event(vec![], vec![], vec![assign("x", Some("src"))])],
    );
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_try_false_path_unrelated_bodies() {
    let out = assign_chain_taints(
        &seed(&["src"]),
        &[try_event(
            vec![assign("a", Some("x"))],
            vec![assign("b", Some("y"))],
            vec![assign("c", Some("z"))],
        )],
    );
    assert!(!out.contains("a") && !out.contains("b") && !out.contains("c"));
}

#[test]
fn assign_chain_defer_positive_propagates() {
    let out = assign_chain_taints(&seed(&["src"]), &[defer(vec![assign("x", Some("src"))])]);
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_using_positive_propagates() {
    let out = assign_chain_taints(&seed(&["src"]), &[using(vec![assign("x", Some("src"))])]);
    assert!(out.contains("x"));
}

#[test]
fn assign_chain_return_false_path() {
    // Return alone shouldn't taint anything.
    let out = assign_chain_taints(&seed(&["src"]), &[flow_return()]);
    assert_eq!(out.len(), 1);
}

#[test]
fn assign_chain_throw_false_path() {
    let out = assign_chain_taints(&seed(&["src"]), &[throw()]);
    assert_eq!(out.len(), 1);
}

#[test]
fn assign_chain_yield_false_path() {
    let out = assign_chain_taints(&seed(&["src"]), &[yield_event(Some("src"))]);
    assert_eq!(out.len(), 1, "yield doesn't taint caller scope in assign-chain");
}

#[test]
fn assign_chain_await_false_path() {
    let out = assign_chain_taints(&seed(&["src"]), &[await_event()]);
    assert_eq!(out.len(), 1);
}

#[test]
fn assign_chain_break_false_path() {
    let out = assign_chain_taints(&seed(&["src"]), &[break_event()]);
    assert_eq!(out.len(), 1);
}

#[test]
fn assign_chain_continue_false_path() {
    let out = assign_chain_taints(&seed(&["src"]), &[continue_event()]);
    assert_eq!(out.len(), 1);
}

// ---------------------------------------------------------------------------
// intraprocedural compiler dataflow
// ---------------------------------------------------------------------------

fn intra_run(events: &[FlowEvent], sources: &[&str]) -> IntraTaintResult {
    let cfg = bonsai_cfg::build_cfg_from_flow("test_fn", events);
    let config = TaintConfig {
        sources: seed(sources),
    };
    intraprocedural_taint(&cfg, &config)
}

fn exit_contains(result: &IntraTaintResult, cfg: &bonsai_cfg::Cfg, name: &str) -> bool {
    result.is_tainted_at_exit(cfg.exit, name)
}

#[test]
fn intra_assign_positive_taints_target() {
    let events = vec![assign("x", Some("src"))];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(exit_contains(&result, &cfg, "x"));
}

#[test]
fn intra_assign_descendant_source_seed_taints_qualified_rhs() {
    let events = vec![assign_sources("x", &["args.query"])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["args.*"]);
    assert!(
        exit_contains(&result, &cfg, "x"),
        "explicit descendant source seed should taint qualified RHS reads"
    );
}

#[test]
fn intra_assign_compound_target_taints_descendant_read() {
    let events = vec![
        assign_sources("env", &["raw", "user"]),
        assign_sources("cmd", &["env.cmd"]),
    ];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["raw"]);
    assert!(
        exit_contains(&result, &cfg, "cmd"),
        "aggregate/container assignments should seed explicit descendant taint for later field reads"
    );
}

#[test]
fn intra_assign_receiver_method_projection_preserves_value_taint() {
    let events = vec![
        assign_sources("query", &["token"]),
        assign_sources("arg", &["query.c_str()"]),
    ];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["token"]);
    assert!(
        exit_contains(&result, &cfg, "arg"),
        "value-preserving receiver method projections should remain tainted"
    );
}

#[test]
fn intra_assign_bare_object_still_does_not_taint_field_read() {
    let events = vec![assign_sources("n", &["client.capacity"])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["client"]);
    assert!(
        !exit_contains(&result, &cfg, "n"),
        "bare carrier taint must not promote to arbitrary field reads"
    );
}

#[test]
fn intra_assign_clean_source_clears_taint() {
    // x = recv; x = clean — the second assignment overwrites x with
    // a value that has no tainted RHS operand, so stale taint must be
    // killed before any later sink(x).
    let events = vec![assign("x", Some("src")), assign("x", Some("clean"))];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(
        !exit_contains(&result, &cfg, "x"),
        "clean reassignment must overwrite and clear target taint"
    );
}

#[test]
fn intra_generic_call_does_not_clean() {
    let events = vec![assign("x", Some("src")), call("observe", &["x"])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(
        exit_contains(&result, &cfg, "x"),
        "a generic call must not alter propagation",
    );
}

#[test]
fn intra_second_generic_call_leaves_taint() {
    let events = vec![assign("x", Some("src")), call("logger", &["x"])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(exit_contains(&result, &cfg, "x"), "generic call must leave taint",);
}

#[test]
fn intra_branch_positive_one_arm_taints() {
    let events = vec![
        assign("x", Some("src")),
        branch(vec![assign("y", Some("x"))], vec![]),
    ];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(exit_contains(&result, &cfg, "y"));
}

#[test]
fn intra_branch_calls_do_not_clean() {
    let events = vec![
        assign("x", Some("src")),
        branch(vec![call("validate", &["x"])], vec![call("validate", &["x"])]),
    ];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(
        exit_contains(&result, &cfg, "x"),
        "calls in both branch arms must not clear taint",
    );
}

#[test]
fn intra_loop_positive_converges_with_taint() {
    let events = vec![loop_body(vec![assign("x", Some("src"))])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(exit_contains(&result, &cfg, "x"));
}

#[test]
fn intra_loop_call_inside_body_preserves_taint() {
    let events = vec![loop_body(vec![
        assign("x", Some("src")),
        call("validate", &["x"]),
    ])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(
        exit_contains(&result, &cfg, "x"),
        "calls inside loops must not clear taint",
    );
}

#[test]
fn intra_try_positive_any_region_taints() {
    let events = vec![try_event(
        vec![assign("a", Some("src"))],
        vec![assign("b", Some("src"))],
        vec![assign("c", Some("src"))],
    )];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(exit_contains(&result, &cfg, "a"));
    assert!(exit_contains(&result, &cfg, "b"));
    assert!(exit_contains(&result, &cfg, "c"));
}

#[test]
fn intra_try_calls_do_not_clean_regions() {
    let events = vec![
        assign("x", Some("src")),
        try_event(
            vec![call("validate", &["x"])],
            vec![call("validate", &["x"])],
            vec![call("validate", &["x"])],
        ),
    ];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(
        exit_contains(&result, &cfg, "x"),
        "calls across try regions must not clear taint",
    );
}

#[test]
fn intra_return_false_path_doesnt_taint() {
    let events = vec![flow_return()];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(!exit_contains(&result, &cfg, "anything"));
}

#[test]
fn intra_throw_false_path_doesnt_taint() {
    let events = vec![throw()];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(!exit_contains(&result, &cfg, "anything"));
}

#[test]
fn intra_break_false_path() {
    // Loop with break — break itself doesn't alter taint state.
    let events = vec![loop_body(vec![
        assign("x", Some("src")),
        break_event(),
        assign("y", Some("src")),
    ])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(exit_contains(&result, &cfg, "x"));
    // y assigned after break lives in an unreachable block and
    // shouldn't flow to the exit.
    assert!(!exit_contains(&result, &cfg, "y"));
}

#[test]
fn intra_defer_positive_body_taints() {
    let events = vec![defer(vec![assign("x", Some("src"))])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(exit_contains(&result, &cfg, "x"));
}

#[test]
fn intra_using_positive_body_taints() {
    let events = vec![using(vec![assign("x", Some("src"))])];
    let cfg = bonsai_cfg::build_cfg_from_flow("f", &events);
    let result = intra_run(&events, &["src"]);
    assert!(exit_contains(&result, &cfg, "x"));
}

// ---------------------------------------------------------------------------
// assign-chain false-path guardrails — extra coverage for the classic
// "looks-like-it-should-taint-but-doesn't" cases.
// ---------------------------------------------------------------------------

#[test]
fn assign_chain_shadowing_does_not_cross_chain() {
    // Two independent assign chains — taint on `src1` shouldn't
    // leak into `b` which comes from `src2`.
    let events = vec![assign("a", Some("src1")), assign("b", Some("src2"))];
    let out = assign_chain_taints(&seed(&["src1"]), &events);
    assert!(out.contains("a"));
    assert!(
        !out.contains("b"),
        "false path: src2 chain must not taint from src1"
    );
}

#[test]
fn assign_chain_nested_branch_with_clean_path_still_leaks_via_union() {
    // Branch join is union, so if ANY arm taints, the name stays
    // tainted at exit. Documenting this intentional behavior so
    // future changes don't accidentally make it stricter without
    // updating the tests.
    let events = vec![
        assign("x", Some("src")),
        branch(vec![assign("y", Some("x"))], vec![assign("y", Some("clean"))]),
    ];
    let out = assign_chain_taints(&seed(&["src"]), &events);
    assert!(
        out.contains("y"),
        "assign-chain branch union intentionally keeps taint from any arm",
    );
}
