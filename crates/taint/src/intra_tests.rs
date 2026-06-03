use super::*;
use bonsai_cfg::build_cfg_from_flow;
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{CallArg, CallKind, LoopKind};

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

fn assign_call(target: &str, callee: &str, args: &[&str]) -> FlowEvent {
    FlowEvent::Assign {
        span: span(),
        target: target.to_string(),
        source_name: None,
        source_call: Some(callee.to_string()),
        source_call_args: args.iter().map(|a| (*a).to_string()).collect(),
        source_names: Vec::new(),
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

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn config(sources: &[&str], sanitizers: &[&str]) -> TaintConfig {
    TaintConfig {
        sources: seed(sources),
        sanitizers: seed(sanitizers),
        worklist_cap: None,
    }
}

fn run(events: Vec<FlowEvent>, cfg: &TaintConfig) -> (IntraTaintResult, Cfg) {
    let cfg_built = build_cfg_from_flow("test_fn", &events);
    let result = intraprocedural_taint(&cfg_built, cfg);
    (result, cfg_built)
}

#[test]
fn simple_source_to_sink_taints_target() {
    // x = recv(); sink(x) — at the exit block x is tainted.
    let events = vec![assign("x", Some("recv"))];
    let (result, cfg) = run(events, &config(&["recv"], &[]));
    assert!(!result.saturated);
    assert!(result.diagnostics.is_empty());
    assert!(result.is_tainted_at_exit(cfg.exit, "x"));
}

#[test]
fn entry_predecessor_edge_emits_diagnostic() {
    let entry = BasicBlockId::new(0);
    let body = BasicBlockId::new(1);
    let exit = BasicBlockId::new(2);
    let span = Span::new(bonsai_common::FileId::new(1), 0, 1);
    let cfg = Cfg {
        analysis_complete: true,
        analysis_incomplete_reasons: Vec::new(),
        function: "entry_back_edge".to_string(),
        entry,
        exit,
        blocks: vec![
            bonsai_cfg::BasicBlock {
                id: entry,
                label: "entry".to_string(),
                synthetic_kind: Some(bonsai_cfg::SyntheticBlockKind::Entry),
                events: Vec::new(),
                successors: vec![body, exit],
                terminator: bonsai_cfg::Terminator::Fallthrough,
                span,
            },
            bonsai_cfg::BasicBlock {
                id: body,
                label: "body".to_string(),
                synthetic_kind: None,
                events: vec![assign("x", Some("recv"))],
                successors: vec![entry],
                terminator: bonsai_cfg::Terminator::Fallthrough,
                span,
            },
            bonsai_cfg::BasicBlock {
                id: exit,
                label: "exit".to_string(),
                synthetic_kind: Some(bonsai_cfg::SyntheticBlockKind::Exit),
                events: Vec::new(),
                successors: Vec::new(),
                terminator: bonsai_cfg::Terminator::Fallthrough,
                span,
            },
        ],
    };
    let result = intraprocedural_taint(&cfg, &config(&["recv"], &[]));

    assert_eq!(result.diagnostics.len(), 1);
    let diagnostic = &result.diagnostics[0];
    assert_eq!(diagnostic.code.as_deref(), Some("taint-entry-predecessor"));
    assert_eq!(diagnostic.severity, bonsai_diagnostics::Severity::Warning);
    assert!(diagnostic.message.contains("entry block"));
}

#[test]
fn tainted_carrier_field_read_taints_target() {
    let events = vec![assign("cmd", Some("env->cmd"))];
    let (result, cfg) = run(events, &config(&["env.*"], &[]));
    assert!(
        result.is_tainted_at_exit(cfg.exit, "cmd"),
        "field reads from an explicitly tainted descendant object must be tainted"
    );
}

#[test]
fn tainted_carrier_subscript_read_taints_target() {
    let events = vec![assign("cmd", Some("env['cmd']"))];
    let (result, cfg) = run(events, &config(&["env.*"], &[]));
    assert!(result.is_tainted_at_exit(cfg.exit, "cmd"));
}

#[test]
fn source_unavailable_call_does_not_invent_destination_taint() {
    let events = vec![call("strncpy", &["env.cmd", "raw", "sizeof(env.cmd) - 1"])];
    let (result, cfg) = run(events, &config(&["raw"], &[]));
    assert!(
        !result.is_tainted_at_exit(cfg.exit, "env.cmd"),
        "opaque external calls must not create hidden arg-to-arg propagation"
    );
    assert!(!result.is_tainted_at_exit(cfg.exit, "env"));
}

#[test]
fn pointer_declarator_target_aliases_to_identifier() {
    let events = vec![assign("*raw", Some("argv"))];
    let (result, cfg) = run(events, &config(&["argv"], &[]));
    assert!(result.is_tainted_at_exit(cfg.exit, "raw"));
}

#[test]
fn seed_itself_is_tainted_at_entry() {
    let (result, cfg) = run(vec![], &config(&["recv"], &[]));
    assert!(result.is_tainted_at_entry(cfg.entry, "recv"));
}

#[test]
fn receiver_seed_does_not_taint_unrelated_assignment() {
    let events = vec![assign("tag", Some("constant_name"))];
    let (result, cfg) = run(events, &config(&["recv"], &[]));
    assert!(
        !result.is_tainted_at_exit(cfg.exit, "tag"),
        "receiver taint must not contaminate arbitrary clean assignments"
    );
}

#[test]
fn receiver_seed_does_not_taint_zero_arg_static_helper_return() {
    let events = vec![assign_call("runner", "Repository._new_runner", &[])];
    let (result, cfg) = run(events, &config(&["recv"], &[]));
    assert!(
        !result.is_tainted_at_exit(cfg.exit, "runner"),
        "zero-arg class/static helper returns are not tainted object data"
    );
}

#[test]
fn receiver_seed_taints_explicit_receiver_field_read() {
    let events = vec![assign("cmd", Some("recv.data['cmd']"))];
    let (result, cfg) = run(events, &config(&["recv.*"], &[]));
    assert!(result.is_tainted_at_exit(cfg.exit, "cmd"));
}

#[test]
fn reassignment_from_clean_source_clears_taint() {
    // x = recv(); x = unrelated. A semantic overwrite with a
    // clean RHS must clear x; otherwise a later sink(x) reports a
    // stale value that no longer exists at runtime.
    let events = vec![assign("x", Some("recv")), assign("x", Some("unrelated"))];
    let (result, cfg) = run(events, &config(&["recv"], &[]));
    assert!(
        !result.is_tainted_at_exit(cfg.exit, "x"),
        "clean reassignment must overwrite and clear target taint"
    );
}

#[test]
fn reassignment_from_none_rhs_clears_taint() {
    // x = recv(); x = literal/opaque. Without any surfaced
    // tainted RHS operand, the assignment is an overwrite and x
    // becomes clean.
    let events = vec![assign("x", Some("recv")), assign("x", None)];
    let (result, cfg) = run(events, &config(&["recv"], &[]));
    assert!(!result.is_tainted_at_exit(cfg.exit, "x"));
}

#[test]
fn configured_sanitizer_call_return_still_propagates_taint() {
    // y = shlex_quote(x) where x is tainted. The configured
    // sanitizer name is metadata only; propagation still reaches y.
    let events = vec![assign("x", Some("recv")), assign_call("y", "shlex_quote", &["x"])];
    let (result, cfg) = run(events, &config(&["recv"], &["shlex_quote"]));
    assert!(result.is_tainted_at_exit(cfg.exit, "x"));
    assert!(result.is_tainted_at_exit(cfg.exit, "y"));
}

#[test]
fn configured_sanitizer_call_does_not_clear_arg_taint() {
    // validate(x) where validate is listed as a sanitizer. The
    // end user decides what that means; taint still propagates.
    let events = vec![assign("x", Some("recv")), call("validate", &["x"])];
    let (result, cfg) = run(events, &config(&["recv"], &["validate"]));
    assert!(result.is_tainted_at_exit(cfg.exit, "x"));
}

#[test]
fn configured_sanitizer_after_sink_does_not_change_propagation() {
    let events = vec![
        assign("x", Some("recv")),
        call("sink", &["x"]),
        call("validate", &["x"]),
    ];
    let (result, cfg) = run(events, &config(&["recv"], &["validate"]));
    assert!(result.is_tainted_at_exit(cfg.exit, "x"));
}

#[test]
fn configured_sanitizer_in_one_branch_arm_preserves_taint_at_join() {
    // x = recv(); if c: validate(x); else: (nothing). Sanitizer
    // calls are evidence only, so the join preserves x's taint.
    let events = vec![
        assign("x", Some("recv")),
        branch(vec![call("validate", &["x"])], vec![]),
    ];
    let (result, cfg) = run(events, &config(&["recv"], &["validate"]));
    assert!(
        result.is_tainted_at_exit(cfg.exit, "x"),
        "union of then/else must preserve taint"
    );
}

#[test]
fn configured_sanitizer_in_both_branch_arms_preserves_taint_at_join() {
    // x = recv(); if c: validate(x); else: validate(x). Sanitizer
    // calls are evidence only, so both arms preserve x's taint.
    let events = vec![
        assign("x", Some("recv")),
        branch(vec![call("validate", &["x"])], vec![call("validate", &["x"])]),
    ];
    let (result, cfg) = run(events, &config(&["recv"], &["validate"]));
    assert!(result.is_tainted_at_exit(cfg.exit, "x"));
}

#[test]
fn loop_body_taint_propagates_after_fixed_point() {
    // for i in items: x = recv() — x tainted after the loop.
    let events = vec![loop_body(vec![assign("x", Some("recv"))])];
    let (result, cfg) = run(events, &config(&["recv"], &[]));
    assert!(result.is_tainted_at_exit(cfg.exit, "x"));
}

#[test]
fn configured_sanitizer_inside_loop_preserves_taint() {
    // for i: x = recv(); validate(x). The call does not kill
    // taint, so the fixed point keeps x tainted after the loop.
    let events = vec![loop_body(vec![
        assign("x", Some("recv")),
        call("validate", &["x"]),
    ])];
    let (result, cfg) = run(events, &config(&["recv"], &["validate"]));
    assert!(result.is_tainted_at_exit(cfg.exit, "x"));
}

#[test]
fn convergence_is_bounded_by_safety_cap() {
    // Large CFG should converge in a reasonable number of
    // worklist iterations, never hit the safety cap.
    let mut events = Vec::new();
    for i in 0..50 {
        let target = format!("v{i}");
        let source = if i == 0 {
            "recv".to_string()
        } else {
            format!("v{}", i - 1)
        };
        events.push(assign(&target, Some(&source)));
    }
    let (result, _) = run(events, &config(&["recv"], &[]));
    assert!(!result.saturated, "50 sequential assigns must converge");
}

#[test]
fn multiple_independent_sources_propagate_separately() {
    let events = vec![
        assign("a", Some("src1")),
        assign("b", Some("src2")),
        assign("c", Some("unrelated")),
    ];
    let (result, cfg) = run(events, &config(&["src1", "src2"], &[]));
    assert!(result.is_tainted_at_exit(cfg.exit, "a"));
    assert!(result.is_tainted_at_exit(cfg.exit, "b"));
    assert!(!result.is_tainted_at_exit(cfg.exit, "c"));
}

#[test]
fn configured_sanitizer_inside_loop_then_reassigned_in_body_keeps_taint() {
    // for i: validate(x); x = recv() — at loop exit, x is tainted.
    let events = vec![loop_body(vec![
        call("validate", &["x"]),
        assign("x", Some("recv")),
    ])];
    let (result, cfg) = run(events, &config(&["recv"], &["validate"]));
    assert!(result.is_tainted_at_exit(cfg.exit, "x"));
}

#[test]
fn receiver_method_projection_handles_unicode_boundaries() {
    let state = seed(&["schema"]);
    assert!(
        !crate::tokens::receiver_method_projection_is_tainted(
            r#"expect(result.error.issues[0].message).toBe("קטן מדי: הקבוצה")"#,
            &state,
            false,
        ),
        "unicode string text before a call must not panic or invent receiver taint"
    );
    assert!(
        !crate::tokens::receiver_method_projection_is_tainted(
            r#"requests.Request("PUT", data="ööö".encode())"#,
            &state,
            false,
        ),
        "multibyte text inside call expressions must keep byte slicing on char boundaries"
    );
}

// audit re-apply: M5: direct unit test of `text_is_tainted` (private fn, visib

#[test]
fn qualified_seed_base_matches_but_tail_does_not_promote_bare_local() {
    // Seed is the qualified access `obj.password`. The base `obj`
    // and the seed itself remain tainted, but an UNRELATED bare
    // local that merely shares the tail name (`password`) must not
    // be promoted to tainted. Mirrors the inter pass (base-only)
    // and the OT_01 sibling-field precision boundary. (M5)
    let state = seed(&["obj.password"]);
    assert!(
        text_is_tainted("obj.password", &state),
        "the tracked qualified seed itself stays tainted"
    );
    assert!(
        text_is_tainted("obj", &state),
        "the qualified seed's base remains tainted, matching the inter helper"
    );
    assert!(
        !text_is_tainted("password", &state),
        "a qualified seed must not promote an unrelated bare local sharing only the tail name"
    );
}

// audit M5: the intra pass must match a qualified seed by its BASE only,
// never its tail field name (mirroring the inter pass). Seed `args`;
// `obj.x = args` taints `obj.x`. A later call arg `x` (the bare tail of the
// qualified seed) must NOT be treated as tainted, so `y` stays clean.
// Probing the full qualified `obj.x` still propagates, so `z` is tainted.
#[test]
fn qualified_seed_tail_does_not_taint_unrelated_bare_identifier() {
    let events = vec![
        assign("obj.x", Some("args")),
        assign_call("y", "sanitize", &["x"]),
        assign_call("z", "sanitize", &["obj.x"]),
    ];
    let (result, cfg) = run(events, &config(&["args"], &[]));
    assert!(
        result.is_tainted_at_exit(cfg.exit, "obj.x"),
        "the qualified seed itself must be tainted"
    );
    assert!(
        !result.is_tainted_at_exit(cfg.exit, "y"),
        "a bare ident matching only the tail field of a qualified seed must not be tainted"
    );
    assert!(
        result.is_tainted_at_exit(cfg.exit, "z"),
        "probing the full qualified access must still propagate taint"
    );
}
