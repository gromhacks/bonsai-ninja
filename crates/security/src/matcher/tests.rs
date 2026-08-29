//! Tests for the rulepack matcher's call-site, regex, and constraint
//! evaluators. Extracted from `matcher/mod.rs` so the matcher's
//! production code is reviewable in one read without scrolling past
//! the test fixtures.

use super::*;

fn span() -> Span {
    Span {
        file: FileId::new(0),
        start: 7,
        end: 15,
    }
}

fn rule_from_yaml(yaml: &str, kind: crate::rule::RuleKind) -> Rule {
    let mut rule: Rule = serde_yaml::from_str(yaml).expect("rule yaml parses");
    rule.kind = kind;
    let metadata: crate::loader::RulepackMetadata =
        serde_yaml::from_str(include_str!("../../../../security-patterns/metadata.yml"))
            .expect("checked-in rulepack metadata parses");
    metadata.apply_rule_defaults(&mut rule);
    rule
}

#[test]
fn reference_fallback_keeps_outer_callable_after_local_type_ends() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "amalgamation.c",
        r#"int process(int value) {
    struct LocalState { int mode; };
    consume(0, 0, value);
    return value;
}
"#,
    );
    let sink = rule_from_yaml(
        r#"
id: c.test.consume
enabled: true
language: c
tag: test-sink
severity: high
description: Neutral compiler ownership fixture.
match:
  kind: call
  callee: { name: consume }
constraints:
  - arg_tainted: { index: 2 }
"#,
        crate::rule::RuleKind::Sink,
    );
    let factory = build_rulepack_typing(&[&sink]);
    let hits = match_rules_against_facts_for_sink_inventory_with_progress_on_files(
        &ws,
        &[&sink],
        &ws.vfs().all_files(),
        &factory,
        || {},
    );
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].enclosing_fn.as_deref(), Some("process"), "{hits:#?}");
}

#[test]
fn streamed_compiler_objects_preserve_c_recovery_call_ownership() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "recovered.c",
        r#"int process(int first, int second, int tail, int value) {
    switch (value) {
    case 0:
#ifdef FIRST_CONFIGURATION
        if (first ||
#else
        if (second ||
#endif
            tail) {
            consume(value);
        }
        break;
    default:
        break;
    }
    return value;
}
int unrelated(
"#,
    );
    ws.vfs().write(
        "peer.c",
        "int peer(int value) { consume(value); return value; }\n",
    );
    let sink = rule_from_yaml(
        r#"
id: c.test.consume
enabled: true
language: c
tag: test-sink
severity: high
description: Neutral compiler ownership fixture.
match:
  kind: call
  callee: { name: consume }
"#,
        crate::rule::RuleKind::Sink,
    );
    let factory = build_rulepack_typing(&[&sink]);
    let files = ws.vfs().all_files();
    let hits = match_rules_against_facts_for_sink_inventory_with_progress_on_files(
        &ws,
        &[&sink],
        &files,
        &factory,
        || {},
    );
    let recovered = hits
        .iter()
        .find(|hit| hit.file.ends_with("recovered.c"))
        .expect("recovered call match");
    assert_eq!(
        recovered.enclosing_fn.as_deref(),
        Some("process"),
        "streamed compiler objects must retain the recovered declaration that owns the call: {hits:#?}"
    );
}

#[test]
fn weighted_matcher_cache_eviction_only_recomputes() {
    let cache = MatcherFactCache::<u8, usize>::new(1);
    let builds = std::sync::atomic::AtomicUsize::new(0);
    let first = cache.get_or_insert_with(
        0,
        || {
            builds.fetch_add(1, Ordering::Relaxed);
            Arc::new(7)
        },
        |_| 1,
    );
    let reused = cache.get_or_insert_with(
        0,
        || {
            builds.fetch_add(1, Ordering::Relaxed);
            Arc::new(7)
        },
        |_| 1,
    );
    assert!(Arc::ptr_eq(&first, &reused));
    let _ = cache.get_or_insert_with(1, || Arc::new(9), |_| 1);
    let rebuilt = cache.get_or_insert_with(
        0,
        || {
            builds.fetch_add(1, Ordering::Relaxed);
            Arc::new(7)
        },
        |_| 1,
    );
    assert!(!Arc::ptr_eq(&first, &rebuilt));
    assert_eq!(builds.load(Ordering::Relaxed), 2);
}

#[test]
fn inline_callback_constraint_uses_callback_syntax_not_named_parameter_count() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "callbacks.rs",
        r#"
fn fallback(_: ()) -> String { String::new() }
fn run(value: Result<String, ()>) {
    consume(value, |_| String::new());
    consume(value, fallback);
}
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: rust.test.inline-callback
enabled: true
language: rust
tag: test-sink
severity: high
description: Neutral inline-callback syntax fixture.
match:
  kind: call
  callee: { name: consume }
constraints:
  - arg_is_inline_callback: 1
"#,
        crate::rule::RuleKind::Sink,
    );

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(
        matches.len(),
        1,
        "only the parsed closure is inline: {matches:#?}"
    );
    assert_eq!(
        matches[0].line, 4,
        "the named callback must fail closed: {matches:#?}"
    );
}

#[test]
fn matcher_cache_phase_release_only_forces_exact_recomputation() {
    let cache = MatcherFactCache::<u8, usize>::new(1);
    let builds = std::sync::atomic::AtomicUsize::new(0);
    let build = || {
        builds.fetch_add(1, Ordering::Relaxed);
        Arc::new(7)
    };
    let first = cache.get_or_insert_with(0, build, |_| 1);
    cache.clear_retained();
    let rebuilt = cache.get_or_insert_with(0, build, |_| 1);

    assert!(!Arc::ptr_eq(&first, &rebuilt));
    assert_eq!(builds.load(Ordering::Relaxed), 2);
}

#[test]
fn matcher_cache_phase_budget_can_shrink_and_restore_without_changing_values() {
    let cache = MatcherFactCache::<u8, usize>::new(4);
    let builds = std::sync::atomic::AtomicUsize::new(0);
    let build = || {
        builds.fetch_add(1, Ordering::Relaxed);
        Arc::new(7)
    };
    let first = cache.get_or_insert_with(0, build, |_| 2);
    cache.set_retained_budget(1);
    let rebuilt = cache.get_or_insert_with(0, build, |_| 2);
    assert!(!Arc::ptr_eq(&first, &rebuilt));

    cache.set_retained_budget(4);
    let retained = cache.get_or_insert_with(0, build, |_| 2);
    let reused = cache.get_or_insert_with(0, build, |_| 2);
    assert!(Arc::ptr_eq(&retained, &reused));
    assert_eq!(*reused, 7);
    assert_eq!(builds.load(Ordering::Relaxed), 3);
}

#[test]
fn matcher_cache_can_retain_one_required_oversize_compiler_projection() {
    let cache = MatcherFactCache::<u8, usize>::new_with_oversized_singleton(1, true);
    let builds = std::sync::atomic::AtomicUsize::new(0);
    let build = || {
        builds.fetch_add(1, Ordering::Relaxed);
        Arc::new(7)
    };
    let first = cache.get_or_insert_with(0, build, |_| 8);
    cache.set_retained_budget(1);
    let reused = cache.get_or_insert_with(0, build, |_| 8);

    assert!(Arc::ptr_eq(&first, &reused));
    assert_eq!(builds.load(Ordering::Relaxed), 1);

    let second = cache.get_or_insert_with(1, || Arc::new(9), |_| 8);
    let second_reused = cache.get_or_insert_with(1, || Arc::new(11), |_| 8);
    assert!(Arc::ptr_eq(&second, &second_reused));
    assert_eq!(*second_reused, 9);
    assert!(
        cache.state.lock().entries.len() <= 1,
        "oversize retention must stay bounded to one LRU value"
    );
}

#[test]
fn demanded_import_projection_matches_exhaustive_prefix_intersection() {
    let modules = [
        "org.apache.velocity.app.VelocityEngine",
        "poco/URI.h",
        "DBI::db",
        "unrelated.deep.module",
    ];
    let demanded = [
        "org.apache.velocity".to_string(),
        "poco".to_string(),
        "DBI".to_string(),
        "absent".to_string(),
    ];
    let demanded_set = demanded.iter().cloned().collect::<AHashSet<_>>();
    let mut exhaustive = AHashSet::new();
    let mut projected = AHashSet::new();
    for module in modules {
        insert_import_target_prefixes(&mut exhaustive, module);
        insert_demanded_import_target_prefixes(&mut projected, module, &demanded_set);
    }
    exhaustive.retain(|package| demanded_set.contains(package));

    assert_eq!(projected, exhaustive);
}

#[test]
fn broad_matcher_cache_reserves_low_memory_semantic_headroom() {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    assert_eq!(
        broad_matcher_fact_cache_total_budget_bytes_for_limit(Some(3 * GIB)),
        128 * MIB
    );
    assert_eq!(
        broad_matcher_fact_cache_total_budget_bytes_for_limit(None),
        256 * MIB
    );
}

#[test]
fn workspace_package_cache_fingerprint_preserves_component_identity() {
    assert_eq!(
        combined_workspace_package_fingerprint(7, 11),
        combined_workspace_package_fingerprint(7, 11)
    );
    assert_ne!(
        combined_workspace_package_fingerprint(7, 11),
        combined_workspace_package_fingerprint(11, 7),
        "manifest and compiler-import fingerprints are distinct cache-key components"
    );
}

#[test]
fn endpoint_taint_constraints_reuse_the_initial_static_syntax_proof() {
    let rule = rule_from_yaml(
        r#"
id: java.test.execute
enabled: true
language: java
tag: sql-injection
severity: high
match:
  kind: call
  callee:
    name: execute
constraints:
  - arg_count: 2
  - arg_tainted:
      index: 1
description: Endpoint proof fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let call_span = Span::new(FileId::new(3), 10, 20);
    let expected = RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: rule.id.clone(),
        language: rule.language.clone(),
        file: "Example.java".to_string(),
        line: 1,
        column: 1,
        span: call_span,
        match_text: "execute".to_string(),
        enclosing_fn: Some("run".to_string()),
    };
    let call = TaintedCall {
        parent_trace_id: None,
        caller: bonsai_common::FuncId::new(7),
        name: "execute".to_string(),
        call_span,
        tainted_args: vec![bonsai_taint::TaintedArgAtCall {
            index: 1,
            value_text: "query".to_string(),
            place: Some("query".to_string()),
            source_names: vec!["query".to_string()],
        }],
        tainted_receiver: None,
        tainted_receiver_source_names: Vec::new(),
        kind: TaintedCallKind::Call,
    };
    let calls = [call];
    let view = InterTaintView::new(&calls);

    assert_eq!(
        endpoint_taint_constraints_pass_without_syntax(&rule, &expected, &view, true),
        Some(true),
        "the endpoint scan already proved static arg/package constraints"
    );
    assert_eq!(
        endpoint_taint_constraints_pass_without_syntax(&rule, &expected, &view, false),
        None,
        "ambiguous overlapping call identities must retain exact AST verification"
    );

    let wrong_slot_call = TaintedCall {
        tainted_args: vec![bonsai_taint::TaintedArgAtCall {
            index: 0,
            value_text: "safe".to_string(),
            place: Some("safe".to_string()),
            source_names: vec!["safe".to_string()],
        }],
        ..calls[0].clone()
    };
    let wrong_slot_calls = [wrong_slot_call];
    assert_eq!(
        endpoint_taint_constraints_pass_without_syntax(
            &rule,
            &expected,
            &InterTaintView::new(&wrong_slot_calls),
            true,
        ),
        Some(false),
        "positional taint predicates must remain argument-sensitive"
    );
}

#[test]
fn endpoint_taint_constraint_fast_path_falls_back_when_ast_identity_is_required() {
    let rule = rule_from_yaml(
        r#"
id: python.test.run
enabled: true
language: python
tag: command-injection
severity: high
match:
  kind: call
  callee:
    name: run
constraints:
  - arg_tainted:
      kw: command
description: Keyword endpoint fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let call_span = Span::new(FileId::new(4), 30, 40);
    let expected = RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: rule.id.clone(),
        language: rule.language.clone(),
        file: "app.py".to_string(),
        line: 1,
        column: 1,
        span: call_span,
        match_text: "run".to_string(),
        enclosing_fn: Some("handler".to_string()),
    };
    let call = TaintedCall {
        parent_trace_id: None,
        caller: bonsai_common::FuncId::new(8),
        name: "run".to_string(),
        call_span,
        tainted_args: vec![bonsai_taint::TaintedArgAtCall {
            index: 0,
            value_text: "payload".to_string(),
            place: Some("payload".to_string()),
            source_names: vec!["payload".to_string()],
        }],
        tainted_receiver: None,
        tainted_receiver_source_names: Vec::new(),
        kind: TaintedCallKind::Call,
    };
    let calls = [call];
    let view = InterTaintView::new(&calls);

    assert_eq!(
        endpoint_taint_constraints_pass_without_syntax(&rule, &expected, &view, true),
        None,
        "keyword-to-position resolution remains adapter-owned AST work"
    );
}

#[test]
fn weighted_matcher_cache_single_flights_oversize_values() {
    const THREADS: usize = 8;
    let cache = Arc::new(MatcherFactCache::<u8, usize>::new(1));
    let builds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start = Arc::new(std::sync::Barrier::new(THREADS));
    let handles = (0..THREADS)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let builds = Arc::clone(&builds);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                cache.get_or_insert_with(
                    0,
                    || {
                        builds.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        Arc::new(7)
                    },
                    |_| 2,
                )
            })
        })
        .collect::<Vec<_>>();
    let values = handles
        .into_iter()
        .map(|handle| handle.join().expect("matcher cache request"))
        .collect::<Vec<_>>();
    assert!(values.iter().skip(1).all(|value| Arc::ptr_eq(&values[0], value)));
    assert_eq!(builds.load(Ordering::Relaxed), 1);

    let rebuilt = cache.get_or_insert_with(
        0,
        || {
            builds.fetch_add(1, Ordering::Relaxed);
            Arc::new(7)
        },
        |_| 2,
    );
    assert!(!Arc::ptr_eq(&values[0], &rebuilt));
    assert_eq!(builds.load(Ordering::Relaxed), 2);
}

#[test]
fn matcher_cache_release_does_not_retain_an_active_single_flight() {
    let cache = Arc::new(MatcherFactCache::<u8, usize>::new(1));
    let builds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();

    let builder_cache = Arc::clone(&cache);
    let builder_builds = Arc::clone(&builds);
    let builder = std::thread::spawn(move || {
        builder_cache.get_or_insert_with(
            0,
            || {
                builder_builds.fetch_add(1, Ordering::Relaxed);
                started_tx.send(()).expect("announce matcher build");
                release_rx.recv().expect("release matcher build");
                Arc::new(7)
            },
            |_| 1,
        )
    });

    started_rx.recv().expect("matcher build started");
    cache.clear_retained();
    let active_cell = {
        let state = cache.state.lock();
        Arc::clone(&state.in_flight.get(&0).expect("active matcher fact flight").cell)
    };

    let waiter_cache = Arc::clone(&cache);
    let waiter_builds = Arc::clone(&builds);
    let waiter = std::thread::spawn(move || {
        waiter_cache.get_or_insert_with(
            0,
            || {
                waiter_builds.fetch_add(1, Ordering::Relaxed);
                Arc::new(7)
            },
            |_| 1,
        )
    });

    let wait_started = std::time::Instant::now();
    while Arc::strong_count(&active_cell) < 4 {
        assert!(
            wait_started.elapsed() < std::time::Duration::from_secs(5),
            "waiter did not join the active matcher fact flight"
        );
        std::thread::yield_now();
    }
    release_tx.send(()).expect("finish matcher build");
    let built = builder.join().expect("builder thread");
    let shared = waiter.join().expect("waiter thread");
    assert!(Arc::ptr_eq(&built, &shared));
    assert_eq!(builds.load(Ordering::Relaxed), 1);

    let rebuilt = cache.get_or_insert_with(
        0,
        || {
            builds.fetch_add(1, Ordering::Relaxed);
            Arc::new(7)
        },
        |_| 1,
    );
    assert!(
        !Arc::ptr_eq(&built, &rebuilt),
        "a matcher value completed after release must not repopulate the hot set"
    );
    assert_eq!(builds.load(Ordering::Relaxed), 2);
}

#[test]
fn transient_package_facts_survive_syntax_release() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "controllers/handler.js",
        "function handle(req, res) { return res.send(req.body); }\n",
    );

    let first =
        file_package_set_with_workspace_context_and_retention(&ws, file, false, FactRetention::Transient);
    ws.db().release_syntax(file);
    let second =
        file_package_set_with_workspace_context_and_retention(&ws, file, false, FactRetention::Transient);

    assert!(
        Arc::ptr_eq(&first, &second),
        "exact lowered package facts should be reused after the transient syntax tree is evicted"
    );
}

#[test]
fn package_fact_cache_invalidates_on_vfs_edit_version() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let path = "controllers/handler.js";
    let file = ws.vfs().write(
        path,
        "const express = require(\"express\");\nfunction handle(req, res) { return res.send(req.body); }\n",
    );
    let first =
        file_package_set_with_workspace_context_and_retention(&ws, file, false, FactRetention::Transient);
    assert!(first.contains("express"));

    let rewritten = ws
        .vfs()
        .write(path, "function handle(req, res) { return res.send(req.body); }\n");
    assert_eq!(rewritten, file);
    let second =
        file_package_set_with_workspace_context_and_retention(&ws, file, false, FactRetention::Transient);

    assert!(!Arc::ptr_eq(&first, &second));
    assert!(
        !second.contains("express"),
        "the VFS edit version must invalidate stale package facts"
    );
}

#[test]
fn compact_package_planning_evidence_reads_current_vfs_and_never_crosses_workspaces() {
    let path = "controllers/handler.js";
    let imported_ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let imported_file = imported_ws.vfs().write(
        path,
        "const express = require(\"express\");\nfunction handle(req, res) { return res.send(req.body); }\n",
    );
    let imported = file_package_planning_evidence(
        &imported_ws,
        imported_file,
        false,
        FactRetention::Transient,
        None,
        None,
    );
    assert!(imported.direct_file_packages.contains("express"));

    let rewritten = imported_ws
        .vfs()
        .write(path, "function handle(req, res) { return res.send(req.body); }\n");
    assert_eq!(rewritten, imported_file);
    let after_edit = file_package_planning_evidence(
        &imported_ws,
        imported_file,
        false,
        FactRetention::Transient,
        None,
        None,
    );
    assert!(
        !after_edit.direct_file_packages.contains("express"),
        "planning evidence must be derived from the current compiler import object after an edit"
    );

    let unrelated_ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let unrelated_file = unrelated_ws
        .vfs()
        .write(path, "function handle(req, res) { return res.send(req.body); }\n");
    assert_eq!(
        unrelated_file, imported_file,
        "fixture should reuse the same numeric FileId"
    );
    let unrelated = file_package_planning_evidence(
        &unrelated_ws,
        unrelated_file,
        false,
        FactRetention::Transient,
        None,
        None,
    );
    assert!(
        !unrelated.direct_file_packages.contains("express"),
        "compact planning state is request-owned and cannot leak across VFS instances"
    );
}

#[test]
fn transient_decl_match_facts_survive_syntax_release() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "controllers/handler.js",
        "function handle(req, res) { return res.send(req.body); }\n",
    );
    let factory = empty_rulepack_typing();

    let first = decl_match_facts_for_retention(
        &ws,
        file,
        None,
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements::default(),
            retention: FactRetention::Transient,
            compiler_imports: None,
            global_headers: None,
            call_result_type_decls: None,
        },
    );
    assert!(
        !first.by_decl_span.is_empty(),
        "adapter lowering should produce matcher facts"
    );
    ws.db().release_syntax(file);
    let second = decl_match_facts_for_retention(
        &ws,
        file,
        None,
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements::default(),
            retention: FactRetention::Transient,
            compiler_imports: None,
            global_headers: None,
            call_result_type_decls: None,
        },
    );

    assert!(
        Arc::ptr_eq(&first, &second),
        "exact lowered declaration facts should be reused after the transient syntax tree is evicted"
    );
}

#[test]
fn checked_in_warp_typing_reaches_an_uncapped_assigned_composition_fixed_point() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "routes.rs",
        r#"
use std::collections::HashMap;
use warp::Filter;
fn route() {
    let input = warp::query::<HashMap<String, String>>();
    let combined = input.and(warp::body::bytes());
    combined.and_then(|query, body| async move { consume(query, body) });
}
fn consume<T, U>(_: T, _: U) {}
"#,
    );
    let pack = crate::loader::load_rulepack(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("security-patterns"),
    )
    .expect("load bundled rulepack");
    let all_rules = pack.all_rules();
    let factory = build_rulepack_typing(&all_rules);
    let rust_specs = factory.specs_for("rust").expect("checked-in Rust typing specs");
    let composition_spec = rust_specs
        .iter()
        .find(|spec| {
            spec.method == "and" && spec.type_name == "WarpFilter" && spec.receiver_types == ["WarpFilter"]
        })
        .unwrap_or_else(|| panic!("missing exact checked-in Warp and typing spec: {rust_specs:#?}"));
    let mut typed_receiver = std::collections::HashMap::new();
    typed_receiver.insert(
        "input".to_string(),
        AliasTarget::Type {
            type_name: "WarpFilter".to_string(),
        },
    );
    assert!(factory_spec_matches_call(
        "input.and",
        Some("input"),
        composition_spec,
        &typed_receiver,
    ));
    let source_rule = all_rules
        .iter()
        .copied()
        .find(|rule| rule.id == "rust.warp.filter_callback_typed")
        .expect("checked-in Warp source rule");
    let prepared = PreparedRule::new(source_rule).expect("prepare Warp source rule");
    let requirements = DeclFactRequirements::for_rules([&prepared]);
    assert!(requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES));
    let index = ws.db().decl_index(file).expect("Rust declaration index");
    for (target, expected_call, expected_receiver) in [
        ("input", "warp::query", Some("warp")),
        ("combined", "input.and", Some("input")),
    ] {
        let value = index
            .assignment_values
            .iter()
            .find(|value| value.target.as_deref() == Some(target))
            .unwrap_or_else(|| {
                panic!(
                    "missing exact assignment-value fact for {target}: {:#?}",
                    index.assignment_values
                )
            });
        assert_eq!(value.direct_call_name.as_deref(), Some(expected_call));
        assert_eq!(value.direct_call_receiver.as_deref(), expected_receiver);
    }
    let route = index
        .defs
        .iter()
        .find(|decl| decl.name == "route")
        .expect("route declaration");
    assert!(
        route
            .flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Assign { target, .. } if target == "combined")),
        "Rust flow IR dropped the combined assignment: {:#?}",
        route.flow_events
    );
    let imports = ws.db().compiler_import_index_uncached(file);
    let from_pretyped_receiver = synth_factory_type_aliases(
        &route.flow_events,
        &index.assignment_values,
        factory.as_ref(),
        "rust",
        &typed_receiver,
        imports.as_ref(),
        None,
        None,
    );
    assert!(
        from_pretyped_receiver
            .iter()
            .any(|alias| alias.name == "combined" && alias.type_name == "WarpFilter"),
        "pretyped compiler receiver did not reach the assignment result: {from_pretyped_receiver:#?}"
    );
    let bundle = build_decl_match_facts_bundle(
        &ws,
        file,
        index.as_ref(),
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements,
            retention: FactRetention::Transient,
            compiler_imports: imports.as_ref(),
            global_headers: None,
            call_result_type_decls: None,
        },
    );
    let facts = bundle
        .by_decl_span
        .values()
        .find(|facts| facts.decl_name == "route")
        .expect("route matcher facts");
    for name in ["input", "combined"] {
        assert!(
            facts
                .derived_type_aliases
                .iter()
                .any(|alias| alias.name == name && alias.type_name == "WarpFilter"),
            "missing {name} -> WarpFilter from exact rulepack typing; aliases={:#?}; map={:#?}",
            facts.derived_type_aliases,
            facts.alias_map
        );
    }
    let callback = facts
        .calls
        .iter()
        .find(|call| call.callee.ends_with("and_then"))
        .expect("and_then compiler call");
    assert!(
        receiver_type_matches_any(&callback.receiver_types, &["WarpFilter".to_string()]),
        "terminal call did not inherit the exact factory type: {callback:#?}"
    );
}

#[test]
fn checked_in_lua_factory_typing_uses_import_and_call_structure_not_local_names() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "repo.lua",
        r#"
local mysql = require("resty.mysql")
local function query(input)
  local arbitrary_handle = mysql:new()
  return arbitrary_handle:query(input)
end
"#,
    );
    let pack = crate::loader::load_rulepack(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("security-patterns"),
    )
    .expect("load bundled rulepack");
    let rules = pack.all_rules();
    let factory = build_rulepack_typing(&rules);
    let lua_specs = factory.specs_for("lua").expect("checked-in Lua typing specs");
    assert!(
        lua_specs.iter().any(|spec| {
            spec.method == "new" && spec.receiver_path == ["mysql"] && spec.type_name == "RestyMysqlClient"
        }),
        "missing exact resty.mysql factory typing: {lua_specs:#?}"
    );

    let index = ws.db().decl_index(file).expect("Lua declaration index");
    let assignment = index
        .assignment_values
        .iter()
        .find(|value| value.target.as_deref() == Some("arbitrary_handle"))
        .expect("compiler assignment-value fact");
    assert_eq!(assignment.direct_call_name.as_deref(), Some("mysql:new"));
    assert_eq!(assignment.direct_call_receiver.as_deref(), Some("mysql"));

    let declaration = index
        .defs
        .iter()
        .find(|decl| decl.name == "query")
        .expect("query declaration");
    let imports = ws.db().compiler_import_index_uncached(file);
    let import_aliases = imports
        .as_ref()
        .map(bonsai_lang_api::alias_map_from_imports)
        .unwrap_or_default();
    let aliases = synth_factory_type_aliases(
        &declaration.flow_events,
        &index.assignment_values,
        factory.as_ref(),
        "lua",
        &import_aliases,
        imports.as_ref(),
        Some(declaration),
        None,
    );
    assert!(
        aliases
            .iter()
            .any(|alias| { alias.name == "arbitrary_handle" && alias.type_name == "RestyMysqlClient" }),
        "exact imported factory must type an arbitrarily named local: {aliases:#?}"
    );
}

#[test]
fn resolved_workspace_return_types_reach_assigned_receivers_without_name_guesses() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "service.py",
        r#"
class Connection:
    def execute(self, value):
        return value

class Provider:
    def open(self) -> Connection:
        return Connection()

provider = Provider()

def consume(value):
    arbitrary_handle = provider.open()
    return arbitrary_handle.execute(value)
"#,
    );
    let index = ws.db().decl_index(file).expect("Python declaration index");
    let global = ws.db().global_index();
    let factory = empty_rulepack_typing();
    let bundle = build_decl_match_facts_bundle(
        &ws,
        file,
        index.as_ref(),
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements(DeclFactRequirements::CALL_RESULT_TYPES),
            retention: FactRetention::Transient,
            compiler_imports: None,
            global_headers: Some(global.as_ref()),
            call_result_type_decls: None,
        },
    );
    let facts = bundle
        .by_decl_span
        .values()
        .find(|facts| facts.decl_name == "consume")
        .expect("consumer matcher facts");
    assert!(
        facts
            .derived_type_aliases
            .iter()
            .any(|alias| { alias.name == "arbitrary_handle" && alias.type_name == "Connection" }),
        "exact first-party return type was not attached: {:#?}",
        facts.derived_type_aliases
    );
    let call = facts
        .calls
        .iter()
        .find(|call| call.callee == "arbitrary_handle.execute")
        .expect("typed receiver call");
    assert_eq!(call.receiver_types, ["Connection"]);
}

#[test]
fn staged_receiver_typing_derives_only_the_selected_declaration() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "service.py",
        r#"
class Connection:
    def execute(self, value):
        return value

class Provider:
    def open(self) -> Connection:
        return Connection()

provider = Provider()

def selected(value):
    handle = provider.open()
    return handle.execute(value)

def unselected(value):
    handle = provider.open()
    return handle.execute(value)
"#,
    );
    let index = ws.db().decl_index(file).expect("Python declaration index");
    let selected = index
        .defs
        .iter()
        .find(|decl| decl.name == "selected")
        .expect("selected declaration")
        .span;
    let global = ws.db().global_index();
    let factory = empty_rulepack_typing();
    let bundle = build_decl_match_facts_bundle(
        &ws,
        file,
        index.as_ref(),
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements(DeclFactRequirements::CALL_RESULT_TYPES),
            retention: FactRetention::Transient,
            compiler_imports: None,
            global_headers: Some(global.as_ref()),
            call_result_type_decls: Some(Arc::from([selected])),
        },
    );

    let selected_facts = bundle
        .by_decl_span
        .get(&selected)
        .expect("selected matcher facts");
    assert!(selected_facts
        .derived_type_aliases
        .iter()
        .any(|alias| alias.name == "handle" && alias.type_name == "Connection"));
    let unselected_facts = bundle
        .by_decl_span
        .values()
        .find(|facts| facts.decl_name == "unselected")
        .expect("unselected matcher facts");
    assert!(
        unselected_facts.derived_type_aliases.is_empty(),
        "unselected declarations must not pay for or retain call-result typing"
    );
    let call = unselected_facts
        .calls
        .iter()
        .find(|call| call.callee == "handle.execute")
        .expect("unselected call remains in the exact compiler projection");
    assert!(call.receiver_types.is_empty());
}

#[test]
fn derived_receiver_demand_requires_a_compiler_proven_type_producer() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "service.py",
        r#"
def produced(value):
    handle = provider.open()
    return handle.execute(value)

def ordinary(logger, value):
    return logger.info(value)
"#,
    );
    let index = ws.db().decl_index(file).expect("Python declaration index");
    let receiver_base_map = AHashMap::new();
    let package_evidence = FilePackagePlanningEvidence {
        direct_file_packages: AHashSet::new(),
        component_packages: Arc::new(WorkspaceImportPackageContext::default()),
        manifest_packages: None,
        is_template: false,
    };
    let ctx = FileScanContext {
        ws: &ws,
        file,
        file_index: index.as_ref(),
        file_imports: None,
        package_evidence: &package_evidence,
        mode: ConstraintMode::Inventory,
        taint_view: None,
        retention: FactRetention::Transient,
        receiver_base_map: &receiver_base_map,
        global_headers: None,
        debug_timings: None,
    };
    let factory = empty_rulepack_typing();
    let candidates = DerivedReceiverCandidates::from_context(&ctx, factory.as_ref());

    let produced = index
        .defs
        .iter()
        .find(|decl| decl.name == "produced")
        .expect("produced declaration");
    let produced_call = collect_calls(&produced.flow_events)
        .into_iter()
        .find(|call| call.callee == "handle.execute")
        .expect("produced receiver call");
    assert!(candidates.call_can_gain_type(produced, &produced_call));

    let ordinary = index
        .defs
        .iter()
        .find(|decl| decl.name == "ordinary")
        .expect("ordinary declaration");
    let ordinary_call = collect_calls(&ordinary.flow_events)
        .into_iter()
        .find(|call| call.callee == "logger.info")
        .expect("ordinary receiver call");
    assert!(
        !candidates.call_can_gain_type(ordinary, &ordinary_call),
        "an unassigned ordinary parameter cannot acquire a call-result type"
    );
}

#[test]
fn module_factory_return_type_reaches_function_receiver_without_global_name_guess() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "service.py",
        r#"
shared_resource = provider.connect()

def consume(value):
    return shared_resource.execute(value)
"#,
    );
    let typing_rule = rule_from_yaml(
        r#"
id: python.test.module-factory
enabled: true
language: python
returns_type: ExternalConnection
description: Synthetic external factory typing.
match:
  kind: call
  callee: { attribute: [provider, connect] }
"#,
        crate::rule::RuleKind::Typing,
    );
    let rules = [&typing_rule];
    let factory = build_rulepack_typing(&rules);
    let index = ws.db().decl_index(file).expect("Python declaration index");
    let global = ws.db().global_index();
    let bundle = build_decl_match_facts_bundle(
        &ws,
        file,
        index.as_ref(),
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements(DeclFactRequirements::CALL_RESULT_TYPES),
            retention: FactRetention::Transient,
            compiler_imports: None,
            global_headers: Some(global.as_ref()),
            call_result_type_decls: None,
        },
    );
    let facts = bundle
        .by_decl_span
        .values()
        .find(|facts| facts.decl_name == "consume")
        .expect("consumer matcher facts");
    let call = facts
        .calls
        .iter()
        .find(|call| call.callee == "shared_resource.execute")
        .expect("module receiver call");
    assert_eq!(call.receiver_types, ["ExternalConnection"]);
}

#[test]
fn longest_exact_alias_prefix_wins_over_imported_namespace_prefix() {
    let aliases = std::collections::HashMap::from([
        (
            "backend".to_string(),
            AliasTarget::Namespace {
                module: "project.provider".to_string(),
            },
        ),
        (
            "backend.shared".to_string(),
            AliasTarget::Type {
                type_name: "project.provider.Factory".to_string(),
            },
        ),
    ]);
    assert_eq!(
        expand_callee_alias("backend.shared.open", &aliases).as_deref(),
        Some("project.provider.Factory.open")
    );
}

#[test]
fn imported_module_values_keep_exact_first_party_constructor_and_return_types() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let _file = ws.vfs().write(
        "project/provider.py",
        r#"
class Cursor:
    def execute(self, value):
        return value

class Session:
    def cursor(self) -> Cursor:
        return Cursor()

class Factory:
    def open(self) -> Session:
        return Session()

shared = Factory()
"#,
    );
    let consumer = ws.vfs().write(
        "consumer.py",
        r#"
from project import provider as backend

def consume(value):
    arbitrary_cursor = backend.shared.open().cursor()
    return arbitrary_cursor.execute(value)
"#,
    );
    let index = ws.db().decl_index(consumer).expect("Python consumer index");
    let imports = ws.db().compiler_import_index_uncached(consumer);
    let global = ws.db().global_index();
    let factory = empty_rulepack_typing();
    let bundle = build_decl_match_facts_bundle(
        &ws,
        consumer,
        index.as_ref(),
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements(DeclFactRequirements::CALL_RESULT_TYPES),
            retention: FactRetention::Transient,
            compiler_imports: imports.as_ref(),
            global_headers: Some(global.as_ref()),
            call_result_type_decls: None,
        },
    );
    let facts = bundle
        .by_decl_span
        .values()
        .find(|facts| facts.decl_name == "consume")
        .expect("consumer facts");
    assert!(
        facts.derived_type_aliases.iter().any(|alias| {
            alias.name == "arbitrary_cursor"
                && bonsai_common::short_qualified_tail(&alias.type_name) == "Cursor"
        }),
        "the exact imported module value chain lost its final return type: {:#?}",
        facts.derived_type_aliases
    );
    let terminal = facts
        .calls
        .iter()
        .find(|call| call.callee == "arbitrary_cursor.execute")
        .expect("terminal compiler call");
    assert!(
        terminal
            .receiver_types
            .iter()
            .any(|type_name| bonsai_common::short_qualified_tail(type_name) == "Cursor"),
        "terminal receiver was not enriched from exact compiler types: {terminal:#?}"
    );
}

#[test]
fn imported_module_method_return_types_feed_rule_declared_factory_types() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "project/provider.py",
        r#"
from wire_package.types import Connection as WireConnection

class Factory:
    def open(self) -> WireConnection:
        return make_connection()

shared = Factory()
"#,
    );
    let consumer = ws.vfs().write(
        "consumer.py",
        r#"
from project import provider as backend

def consume(value):
    arbitrary_cursor = backend.shared.open().cursor()
    return arbitrary_cursor.execute(value)
"#,
    );
    let typing_rule = rule_from_yaml(
        r#"
id: python.test.external-cursor
enabled: true
language: python
returns_type: ExternalCursor
description: Neutral rule-declared return type.
match:
  kind: call
  callee: { name: cursor }
constraints:
  - receiver_type_in: [wire_package.types.Connection]
"#,
        crate::rule::RuleKind::Typing,
    );
    let factory = build_rulepack_typing(&[&typing_rule]);
    let index = ws.db().decl_index(consumer).expect("Python consumer index");
    let imports = ws.db().compiler_import_index_uncached(consumer);
    let global = ws.db().global_index();
    let bundle = build_decl_match_facts_bundle(
        &ws,
        consumer,
        index.as_ref(),
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements(DeclFactRequirements::CALL_RESULT_TYPES),
            retention: FactRetention::Transient,
            compiler_imports: imports.as_ref(),
            global_headers: Some(global.as_ref()),
            call_result_type_decls: None,
        },
    );
    let facts = bundle
        .by_decl_span
        .values()
        .find(|facts| facts.decl_name == "consume")
        .expect("consumer facts");
    assert!(
        facts
            .derived_type_aliases
            .iter()
            .any(|alias| { alias.name == "arbitrary_cursor" && alias.type_name == "ExternalCursor" }),
        "the exact first-party return did not feed rule-declared typing: aliases={:#?}; calls={:#?}",
        facts.derived_type_aliases,
        facts.calls
    );
}

#[test]
fn broad_matcher_loads_exact_headers_for_imported_module_return_chains() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "project/provider.py",
        r#"
from wire_package.types import Connection as WireConnection

class Factory:
    def open(self) -> WireConnection:
        return make_connection()

shared = Factory()
"#,
    );
    ws.vfs().write(
        "consumer.py",
        r#"
from project import provider as backend

class LocalCursor:
    def execute(self, value):
        return value

def consume(value):
    selected_handle = backend.shared.open().cursor()
    return selected_handle.execute(value)

def local_decoy(value):
    return LocalCursor().execute(value)
"#,
    );
    let cursor_typing = rule_from_yaml(
        r#"
id: python.test.external-cursor
enabled: true
language: python
returns_type: ExternalCursor
description: Neutral rule-declared return type.
match:
  kind: call
  callee: { name: cursor }
constraints:
  - receiver_type_in: [wire_package.types.Connection]
"#,
        crate::rule::RuleKind::Typing,
    );
    let sink = rule_from_yaml(
        r#"
id: python.test.typed-execute
enabled: true
language: python
tag: injection
severity: high
description: Neutral typed receiver endpoint.
match:
  kind: call
  callee:
    name: execute
    receiver_type_in: [ExternalCursor]
"#,
        crate::rule::RuleKind::Sink,
    );
    let factory = build_rulepack_typing(&[&cursor_typing]);
    let matches = match_rules_against_facts_with_factory(&ws, &[&sink], &factory);

    assert_eq!(
        matches.len(),
        1,
        "only the compiler-proven imported chain may match"
    );
    assert_eq!(matches[0].enclosing_fn.as_deref(), Some("consume"));
}

#[test]
fn immutable_class_field_factory_types_reach_methods_without_overriding_parameters() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "positive.kt",
        r#"
import java.sql.DriverManager
class Positive {
  private val connection = DriverManager.getConnection("jdbc:sqlite:test.db")
  fun run(input: String) {
    val statement = connection.createStatement()
    statement.executeQuery(input)
  }
}
"#,
    );
    ws.vfs().write(
        "shadowed.kt",
        r#"
import java.sql.DriverManager
class LocalStatement { fun executeQuery(value: String) = value }
class LocalConnection { fun createStatement() = LocalStatement() }
class Shadowed {
  private val connection = DriverManager.getConnection("jdbc:sqlite:test.db")
  fun run(connection: LocalConnection, input: String) {
    val statement = connection.createStatement()
    statement.executeQuery(input)
  }
}
"#,
    );
    ws.vfs().write(
        "positive.scala",
        r#"
import java.sql.DriverManager
class PositiveScala {
  private val connection = DriverManager.getConnection("jdbc:sqlite:test.db")
  def run(input: String): Unit = {
    val statement = connection.createStatement()
    statement.executeQuery(input)
  }
}
"#,
    );
    ws.vfs().write(
        "shadowed.scala",
        r#"
import java.sql.DriverManager
class LocalStatement { def executeQuery(value: String): String = value }
class LocalConnection { def createStatement() = new LocalStatement }
class ShadowedScala {
  private val connection = DriverManager.getConnection("jdbc:sqlite:test.db")
  def run(connection: LocalConnection, input: String): Unit = {
    val statement = connection.createStatement()
    statement.executeQuery(input)
  }
}
"#,
    );

    let pack = crate::loader::load_rulepack(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("security-patterns"),
    )
    .expect("load bundled rulepack");
    let rules = pack.all_rules();
    let factory = build_rulepack_typing(&rules);
    let sinks = [
        rules
            .iter()
            .copied()
            .find(|rule| rule.id == "kotlin.sqli.local_statement_executequery")
            .expect("checked-in Kotlin typed JDBC sink"),
        rules
            .iter()
            .copied()
            .find(|rule| rule.id == "scala.sqli.jdbc_statement_execute_variable")
            .expect("checked-in Scala typed JDBC sink"),
    ];
    let matches = match_rules_against_facts_for_sink_inventory_with_progress_on_files(
        &ws,
        &sinks,
        &ws.vfs().all_files(),
        &factory,
        || {},
    );
    let mut files = matches
        .iter()
        .map(|matched| matched.file.as_str())
        .collect::<Vec<_>>();
    files.sort_unstable();
    assert_eq!(files, ["positive.kt", "positive.scala"], "{matches:#?}");
}

#[test]
fn locally_rebound_imported_module_value_fails_closed() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "project/provider.py",
        "class Factory:\n    pass\nshared = Factory()\n",
    );
    let consumer = ws.vfs().write(
        "consumer.py",
        r#"
from project import provider as backend

class Local:
    shared = None

def consume(value):
    backend = Local()
    return backend.shared.open(value)
"#,
    );
    let index = ws.db().decl_index(consumer).expect("Python consumer index");
    let imports = ws.db().compiler_import_index_uncached(consumer);
    let global = ws.db().global_index();
    let factory = empty_rulepack_typing();
    assert!(
        imported_module_value_type_aliases(
            &ws,
            global.as_ref(),
            index.as_ref(),
            factory.as_ref(),
            None,
            imports.as_ref(),
        )
        .is_empty(),
        "a local binding must not inherit an imported module value type"
    );
}

#[test]
fn absent_import_target_has_no_exact_module_file() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("present.py", "def present():\n    return 1\n");
    let global = ws.db().global_index();
    assert_eq!(
        exact_module_file_for_import_target(&ws, global.as_ref(), "missing.provider"),
        None
    );
}

#[test]
fn exact_module_lookup_uses_a_complete_leaf_candidate_directory() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "project/provider.py",
        "class Factory:\n    pass\nshared = Factory()\n",
    );
    for index in 0..128 {
        ws.vfs().write(
            format!("unrelated_{index}/module_{index}.py"),
            format!("def helper_{index}():\n    return {index}\n"),
        );
    }
    let global = ws.db().global_index();
    let candidates = exact_module_file_index(&ws, global.as_ref()).candidate_files("project.provider");

    assert_eq!(
        candidates.len(),
        1,
        "one exact import target must not retain every unrelated workspace file"
    );
    assert_eq!(
        exact_module_file_for_import_target(&ws, global.as_ref(), "project.provider"),
        candidates.first().copied()
    );
}

#[test]
fn decl_fact_requirements_follow_only_declared_rule_constraints() {
    let rule = rule_from_yaml(
        r#"
id: python.test.projected-facts
enabled: true
language: python
tag: test
severity: high
description: Exercises derived matcher fact projection.
match:
  kind: call
  callee: { name: sink }
constraints:
  - arg_matches_regex: { index: 0, regex: "unsafe" }
  - same_receiver_call_count_at_least: 2
  - enclosing_decorator_in: [route]
  - must_alias: { source_arg: 0, sink_arg: 1 }
  - requires_runtime_type: { index: 0, type: str }
  - requires_state: { index: 0, expected: closed }
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let requirements = DeclFactRequirements::for_rules(std::iter::once(&prepared));

    for required in [
        DeclFactRequirements::ASSIGNMENT_TEXTS,
        DeclFactRequirements::RECEIVER_COUNTS,
        DeclFactRequirements::DECORATORS,
        DeclFactRequirements::ALIAS_CHAINS,
        DeclFactRequirements::RUNTIME_TYPES,
        DeclFactRequirements::LIFECYCLE,
    ] {
        assert!(requirements.contains(required));
    }
    assert!(!requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES));
}

#[test]
fn decl_fact_projection_is_part_of_the_exact_cache_identity() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "controllers/handler.py",
        "@route\ndef handle(value):\n    alias = value\n    return sink(alias)\n",
    );
    let factory = empty_rulepack_typing();
    let minimal = decl_match_facts_for_retention(
        &ws,
        file,
        None,
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements::default(),
            retention: FactRetention::Transient,
            compiler_imports: None,
            global_headers: None,
            call_result_type_decls: None,
        },
    );
    let projected = decl_match_facts_for_retention(
        &ws,
        file,
        None,
        DeclMatchFactsRequest {
            factory: factory.as_ref(),
            requirements: DeclFactRequirements(
                DeclFactRequirements::ASSIGNMENT_TEXTS
                    | DeclFactRequirements::DECORATORS
                    | DeclFactRequirements::ALIAS_CHAINS,
            ),
            retention: FactRetention::Transient,
            compiler_imports: None,
            global_headers: None,
            call_result_type_decls: None,
        },
    );

    assert!(
        !Arc::ptr_eq(&minimal, &projected),
        "a smaller derived-fact projection must never satisfy a larger request"
    );
    assert!(minimal.by_decl_span.values().all(|facts| {
        facts.assignment_map.is_empty() && facts.decl_decorators.is_empty() && facts.alias_chains.is_empty()
    }));
    assert!(projected.by_decl_span.values().any(|facts| {
        !facts.assignment_map.is_empty()
            || !facts.decl_decorators.is_empty()
            || !facts.alias_chains.is_empty()
    }));
}

#[test]
fn package_facts_require_compiler_or_dependency_evidence() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let inferred_only = ws.vfs().write(
        "controllers/handler.js",
        "function handle(req, res) { return res.send(req.body); }\n",
    );
    let imported = ws.vfs().write(
        "routes/imported.js",
        "const express = require(\"express\");\nfunction handle(req, res) { return res.send(req.body); }\n",
    );

    let inferred_packages = file_package_set_with_workspace_context_and_retention(
        &ws,
        inferred_only,
        false,
        FactRetention::Transient,
    );
    assert!(
        !inferred_packages.contains("express"),
        "paths and conventional parameter names are not compiler evidence for a framework"
    );
    let imported_packages =
        file_package_set_with_workspace_context_and_retention(&ws, imported, false, FactRetention::Transient);
    assert!(
        imported_packages.contains("express"),
        "the adapter import index should provide exact package evidence"
    );
}

#[test]
fn ruby_template_package_facts_include_manifest_evidence() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "bonsai-ruby-template-package-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).expect("create Ruby template workspace");
    std::fs::write(root.join("Gemfile"), "gem \"actionview\"\n").expect("write Gemfile");
    std::fs::write(root.join("show.html.erb"), "<%= raw @comment %>\n").expect("write ERB template");

    // This is a matcher unit test, not an ingestion/cache integration test.
    // Populate the compiler VFS directly so the assertion cannot depend on
    // the host's external workspace-cache permissions.
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.db()
        .set_workspace_root(root.canonicalize().expect("canonical Ruby template root"));
    let file = ws
        .vfs()
        .write(root.join("show.html.erb"), "<%= raw @comment %>\n");
    let pack = crate::loader::load_rulepack(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("security-patterns"),
    )
    .expect("load bundled rulepack");
    let _snapshot =
        crate::deps::begin_workspace_dependency_package_snapshot(&root, ws.vfs().instance_id(), &pack);
    let packages =
        file_package_set_with_workspace_context_and_retention(&ws, file, true, FactRetention::Transient);
    assert!(
        packages.contains(&template_manifest_package_marker("actionview")),
        "Gemfile evidence must apply to adapter-declared template files: {packages:?}"
    );
    assert!(
        !packages.contains("actionview"),
        "manifest evidence must remain distinguishable from an exact in-file import: {packages:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn adapter_owned_source_package_facts_include_language_scoped_manifest_evidence() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "bonsai-ruby-source-package-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&root).expect("create Ruby source workspace");
    std::fs::write(root.join("Gemfile"), "gem \"actionpack\"\n").expect("write Gemfile");
    std::fs::write(
        root.join("users_controller.rb"),
        "class UsersController < ActionController::Base\n  def show\n    params[:id]\n  end\nend\n",
    )
    .expect("write Ruby controller");
    std::fs::write(root.join("unrelated.py"), "def params():\n    return 1\n").expect("write Python file");

    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.db()
        .set_workspace_root(root.canonicalize().expect("canonical Ruby source root"));
    let ruby_file = ws.vfs().write(
        root.join("users_controller.rb"),
        "class UsersController < ActionController::Base\n  def show\n    params[:id]\n  end\nend\n",
    );
    let python_file = ws
        .vfs()
        .write(root.join("unrelated.py"), "def params():\n    return 1\n");
    let pack = crate::loader::load_rulepack(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("security-patterns"),
    )
    .expect("load bundled rulepack");
    let _snapshot =
        crate::deps::begin_workspace_dependency_package_snapshot(&root, ws.vfs().instance_id(), &pack);
    let ruby_packages =
        file_package_set_with_workspace_context_and_retention(&ws, ruby_file, true, FactRetention::Transient);
    assert!(
        ruby_packages.contains(&manifest_package_marker("actionpack")),
        "a normal adapter-owned Ruby source file must see its Gemfile dependency: {ruby_packages:?}"
    );
    assert!(
        !ruby_packages.contains("actionpack"),
        "manifest evidence must not masquerade as an exact in-file import: {ruby_packages:?}"
    );
    let python_packages = file_package_set_with_workspace_context_and_retention(
        &ws,
        python_file,
        true,
        FactRetention::Transient,
    );
    assert!(
        !python_packages.contains(&manifest_package_marker("actionpack")),
        "Ruby manifest evidence must not cross the adapter language boundary: {python_packages:?}"
    );
    let ruby_planning =
        file_package_planning_evidence(&ws, ruby_file, true, FactRetention::Transient, None, None);
    assert!(
        ruby_planning
            .manifest_packages
            .as_ref()
            .is_some_and(|packages| packages.packages.contains("actionpack")),
        "compact header planning must observe the same cross-file Ruby manifest snapshot"
    );
    let python_planning =
        file_package_planning_evidence(&ws, python_file, true, FactRetention::Transient, None, None);
    assert!(
        python_planning
            .manifest_packages
            .as_ref()
            .is_none_or(|packages| !packages.packages.contains("actionpack")),
        "compact header planning must preserve language-scoped manifest isolation"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn flow_read_attribute_match_requires_actual_qualified_token() {
    let split_callback_tokens = vec!["req".to_string(), "err.path".to_string()];
    assert!(
        !tokens_contain_attribute(&split_callback_tokens, "req.path"),
        "separate `req` and `err.path` tokens must not synthesize `req.path`"
    );

    let query_tokens = vec!["req.query.wsdl".to_string(), "req.query".to_string()];
    assert!(
        tokens_contain_attribute(&query_tokens, "req.query"),
        "real qualified request reads should still match their source rule"
    );
}

#[test]
fn canonical_flow_read_uses_ast_rhs_span_instead_of_assignment_punctuation() {
    let file = FileId::new(0);
    let source = "req.query = sanitize(req.query)";
    let assignment_span = Span::new(file, 0, source.len() as u64);
    let value_start = source.find("sanitize").unwrap() as u64;
    let value_span = Span::new(file, value_start, source.len() as u64);
    let facts = [bonsai_lang_api::AssignmentValueFact {
        assignment_span,
        target: Some("req.query".to_string()),
        target_is_immutable: false,
        target_owner: None,
        target_span: Some(Span::new(file, 0, "req.query".len() as u64)),
        value_span,
        call_sites: Vec::new(),
        value_flow: Default::default(),
        static_value: None,
        exact_callable_return: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        exact_static_call_args: None,
        direct_call_name: None,
        direct_call_span: None,
        direct_call_receiver: None,
        direct_call_receiver_span: None,
        direct_call_receiver_flow: None,
    }];
    let values = AssignmentValueIndex::new(&facts);

    let matched =
        canonical_flow_read_match_span_in_source(file, assignment_span, "req.query", &values, source);

    assert_eq!(matched.start, source.rfind("req.query").unwrap() as u64);
    assert_eq!(matched.end - matched.start, "req.query".len() as u64);
}

#[test]
fn return_rule_assignment_resolution_is_control_flow_exact() {
    let file = FileId::new(0);
    let assign = |start, target: &str, declares_new_binding| FlowEvent::Assign {
        span: Span::new(file, start, start + 1),
        target: target.to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding,
        value_kind: None,
    };
    let ret = |start, name: &str| FlowEvent::Return {
        span: Span::new(file, start, start + 1),
        value_kind: None,
        value_text: Some(name.to_string()),
        value_name: Some(name.to_string()),
        value_flow: Default::default(),
    };
    let branch = |start, then_events, else_events| FlowEvent::Branch {
        span: Span::new(file, start, start + 1),
        condition: None,
        then_events,
        else_events,
    };

    let cases = [
        (
            "single predecessor",
            vec![assign(1, "page", true), ret(2, "page")],
            Some(Span::new(file, 1, 2)),
        ),
        (
            "unconditional reassignment",
            vec![assign(1, "page", true), assign(2, "page", false), ret(3, "page")],
            Some(Span::new(file, 2, 3)),
        ),
        (
            "branch ambiguity",
            vec![
                assign(1, "page", true),
                branch(2, vec![assign(3, "page", false)], Vec::new()),
                ret(4, "page"),
            ],
            None,
        ),
        (
            "nested lexical shadow",
            vec![
                assign(1, "page", true),
                branch(2, vec![assign(3, "page", true)], Vec::new()),
                ret(4, "page"),
            ],
            Some(Span::new(file, 1, 2)),
        ),
        (
            "unrelated binding collision",
            vec![assign(1, "content", true), ret(2, "page")],
            None,
        ),
    ];

    for (name, events, expected) in cases {
        let mut sites = Vec::new();
        collect_return_rule_sites(&events, &mut sites);
        assert_eq!(sites.len(), 1, "{name}");
        assert_eq!(sites[0].reaching_assignment, expected, "{name}");
    }
}

#[test]
fn collect_calls_includes_assignment_source_call_metadata() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "result".to_string(),
        source_name: None,
        source_call: Some("os.system".to_string()),
        source_call_args: vec!["cmd".to_string(), "env".to_string()],
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];

    let calls = collect_calls(&events);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].callee, "os.system");
    assert_eq!(calls[0].span, span());
    assert_eq!(calls[0].origin, CallFactOrigin::AssignmentSourceCall);
    assert_eq!(
        calls[0]
            .args
            .iter()
            .map(|arg| arg.value_text.as_str())
            .collect::<Vec<_>>(),
        vec!["cmd", "env"]
    );
}

#[test]
fn assignment_source_call_facts_inherit_receiver_type_aliases() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "value".to_string(),
        source_name: None,
        source_call: Some("cookie.getValue".to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];
    let mut calls = collect_calls(&events);
    enrich_call_fact_receiver_types(
        &mut calls,
        &[TypeAliasBinding {
            name: "cookie".to_string(),
            type_name: "jakarta.servlet.http.Cookie".to_string(),
        }],
    );

    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].receiver_types,
        vec!["jakarta.servlet.http.Cookie".to_string()],
        "matcher-synthesized assignment source calls must retain semantic receiver type evidence"
    );
}

#[test]
fn compiler_header_assignment_aliases_reach_an_unbounded_fixed_point() {
    let mut aliases = std::collections::HashMap::from([(
        "exec".to_string(),
        AliasTarget::Member {
            module: "child_process".to_string(),
            member: "exec".to_string(),
        },
    )]);
    let assignments = vec![
        CompilerAssignmentAlias {
            owner_span: span(),
            assignment_span: span(),
            target: "first".to_string(),
            source: "exec".to_string(),
        },
        CompilerAssignmentAlias {
            owner_span: span(),
            assignment_span: span(),
            target: "second".to_string(),
            source: "first".to_string(),
        },
        CompilerAssignmentAlias {
            owner_span: span(),
            assignment_span: span(),
            target: "third".to_string(),
            source: "second".to_string(),
        },
    ];

    extend_alias_map_with_compiler_assignment_aliases(&mut aliases, &assignments);

    assert_eq!(aliases.get("third"), aliases.get("exec"));
}

#[test]
fn compiler_syntax_header_filters_only_impossible_call_rules() {
    let matching_rule = rule_from_yaml(
        r#"
id: python.test.clean
enabled: true
language: python
tag: test
severity: info
match:
  kind: call
  callee:
    attribute: [client, clean]
description: matching target
"#,
        crate::rule::RuleKind::Sanitizer,
    );
    let impossible_rule = rule_from_yaml(
        r#"
id: python.test.escape
enabled: true
language: python
tag: test
severity: info
match:
  kind: call
  callee:
    attribute: [html, escape]
description: impossible target
"#,
        crate::rule::RuleKind::Sanitizer,
    );
    let matching = PreparedRule::new(&matching_rule).expect("matching rule prepares");
    let impossible = PreparedRule::new(&impossible_rule).expect("impossible rule prepares");
    let refs = vec![&matching, &impossible];
    let batch = PreparedRuleBatch::new(&refs, empty_rulepack_typing());
    let syntax = CompilerSyntaxHeader {
        calls: vec![bonsai_lang_api::CompilerCallHeader {
            name: "client.clean".to_string(),
            receiver: Some("client".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
        }],
        ..Default::default()
    };

    let (filtered, deferred, needs_constructor_resolution) = batch.filtered_rule_refs_for_syntax_header(
        refs,
        &syntax,
        "client.clean(value)",
        None,
        "python",
        true,
    );

    assert!(!deferred);
    assert!(!needs_constructor_resolution);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].rule.id, "python.test.clean");
}

#[test]
fn compiler_syntax_header_never_changes_type_identifier_case() {
    let rule = rule_from_yaml(
        r#"
id: java.test.client_send
enabled: true
language: java
tag: test
severity: info
match:
  kind: call
  callee:
    attribute: [Client, send]
description: exact receiver type identity
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let refs = vec![&prepared];
    let batch = PreparedRuleBatch::new(&refs, empty_rulepack_typing());
    let syntax = CompilerSyntaxHeader {
        calls: vec![bonsai_lang_api::CompilerCallHeader {
            name: "client.send".to_string(),
            receiver: Some("client".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
        }],
        type_aliases: vec![TypeAliasBinding {
            name: "client".to_string(),
            type_name: "client".to_string(),
        }],
        ..Default::default()
    };

    let (filtered, deferred, needs_constructor_resolution) =
        batch.filtered_rule_refs_for_syntax_header(refs, &syntax, "client.send(value)", None, "java", true);

    assert!(!deferred);
    assert!(!needs_constructor_resolution);
    assert!(
        filtered.is_empty(),
        "a lowercase declared type must not be rewritten to Client"
    );
}

#[test]
fn compiler_syntax_header_resolves_static_member_imports_before_body_decode() {
    let rule = rule_from_yaml(
        r#"
id: java.test.string_format
enabled: true
language: java
tag: test
severity: info
match:
  kind: call
  callee:
    attribute: [String, format]
description: static import target
"#,
        crate::rule::RuleKind::Sanitizer,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let refs = vec![&prepared];
    let batch = PreparedRuleBatch::new(&refs, empty_rulepack_typing());
    let syntax = CompilerSyntaxHeader {
        calls: vec![bonsai_lang_api::CompilerCallHeader {
            name: "format".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
        }],
        ..Default::default()
    };
    let imports = bonsai_lang_api::ImportIndex {
        file: FileId::new(0),
        imports: vec![bonsai_lang_api::ImportSpec {
            span: span(),
            module: "java.lang.String".to_string(),
            alias: Some("format".to_string()),
            is_wildcard: false,
            original_name: Some("format".to_string()),
            scope: Default::default(),
        }],
    };

    let (filtered, deferred, needs_constructor_resolution) = batch.filtered_rule_refs_for_syntax_header(
        refs,
        &syntax,
        "return format(value);",
        Some(&imports),
        "java",
        true,
    );

    assert!(!deferred);
    assert!(!needs_constructor_resolution);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].rule.id, "java.test.string_format");
}

#[test]
fn compiler_syntax_header_indexes_symbolic_tail_on_compound_attribute() {
    let rule = rule_from_yaml(
        r#"
id: ruby.test.password_compare
enabled: true
language: ruby
tag: constant-time
severity: info
match:
  kind: call
  callee:
    attribute: ["BCrypt::Password", "=="]
description: compound receiver with symbolic method
"#,
        crate::rule::RuleKind::Sanitizer,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let refs = vec![&prepared];
    let batch = PreparedRuleBatch::new(&refs, empty_rulepack_typing());
    let syntax = CompilerSyntaxHeader {
        calls: vec![bonsai_lang_api::CompilerCallHeader {
            name: "BCrypt::Password.==".to_string(),
            receiver: Some("BCrypt::Password".to_string()),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
        }],
        ..Default::default()
    };

    let (filtered, deferred, needs_constructor_resolution) = batch.filtered_rule_refs_for_syntax_header(
        refs,
        &syntax,
        "password == candidate",
        None,
        "ruby",
        true,
    );

    assert!(!deferred);
    assert!(!needs_constructor_resolution);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].rule.id, "ruby.test.password_compare");
}

#[test]
fn compiler_syntax_header_defers_only_calls_receiver_ancestry_can_change() {
    let rule = rule_from_yaml(
        r#"
id: java.test.base_run
enabled: true
language: java
tag: test
severity: info
match:
  kind: call
  callee:
    attribute: [Base, run]
description: inherited target
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let refs = vec![&prepared];
    let batch = PreparedRuleBatch::new(&refs, empty_rulepack_typing());
    let inherited_candidate = CompilerSyntaxHeader {
        calls: vec![bonsai_lang_api::CompilerCallHeader {
            name: "child.run".to_string(),
            receiver: Some("child".to_string()),
            receiver_types: vec!["Child".to_string()],
            call_kind: CallKind::Method,
        }],
        ..Default::default()
    };

    let (filtered, deferred, needs_constructor_resolution) = batch.filtered_rule_refs_for_syntax_header(
        refs.clone(),
        &inherited_candidate,
        "child.run(value)",
        None,
        "java",
        false,
    );
    assert!(filtered.is_empty());
    assert!(!needs_constructor_resolution);
    assert!(
        deferred,
        "Child.run may become Base.run after exact ancestry expansion"
    );

    let unrelated_method = CompilerSyntaxHeader {
        calls: vec![bonsai_lang_api::CompilerCallHeader {
            name: "child.stop".to_string(),
            receiver: Some("child".to_string()),
            receiver_types: vec!["Child".to_string()],
            call_kind: CallKind::Method,
        }],
        ..Default::default()
    };
    let (filtered, deferred, needs_constructor_resolution) = batch.filtered_rule_refs_for_syntax_header(
        refs,
        &unrelated_method,
        "child.stop(value)",
        None,
        "java",
        false,
    );
    assert!(filtered.is_empty());
    assert!(!needs_constructor_resolution);
    assert!(
        !deferred,
        "receiver ancestry cannot turn an unrelated method name into the rule target"
    );
}

#[test]
fn syntax_bound_resource_assignment_uses_rulepack_factory_type() {
    let mut factory = RulepackTyping::default();
    factory.by_language.insert(
        "python".to_string(),
        vec![FactoryReturnSpec {
            kind: MatchKind::Call,
            method: "AsyncClient".to_string(),
            receiver_path: vec!["httpx".to_string()],
            receiver_types: Vec::new(),
            type_name: "AsyncClient".to_string(),
            required_imports: Vec::new(),
            binding_origin: None,
        }],
    );
    let events = vec![FlowEvent::Using {
        span: span(),
        body: vec![FlowEvent::Assign {
            span: span(),
            target: "client".to_string(),
            source_name: None,
            source_call: Some("httpx.AsyncClient".to_string()),
            source_call_args: Vec::new(),
            source_names: vec!["httpx.AsyncClient".to_string()],
            declares_new_binding: false,
            value_kind: None,
        }],
    }];

    let aliases = synth_factory_type_aliases(
        &events,
        &[],
        &factory,
        "python",
        &std::collections::HashMap::new(),
        None,
        None,
        None,
    );

    assert_eq!(
        aliases,
        vec![TypeAliasBinding {
            name: "client".to_string(),
            type_name: "AsyncClient".to_string(),
        }]
    );
}

#[test]
fn qualified_factory_aliases_reach_a_sigil_binding_fixed_point() {
    let mut factory = RulepackTyping::default();
    factory.by_language.insert(
        "perl".to_string(),
        vec![
            FactoryReturnSpec {
                kind: MatchKind::Call,
                method: "connect".to_string(),
                receiver_path: vec!["Example".to_string()],
                receiver_types: Vec::new(),
                type_name: "Example::Connection".to_string(),
                required_imports: Vec::new(),
                binding_origin: None,
            },
            FactoryReturnSpec {
                kind: MatchKind::Call,
                method: "prepare".to_string(),
                receiver_path: vec!["Example".to_string(), "Connection".to_string()],
                receiver_types: Vec::new(),
                type_name: "Example::Statement".to_string(),
                required_imports: Vec::new(),
                binding_origin: None,
            },
        ],
    );
    let events = vec![
        FlowEvent::Assign {
            span: Span::new(FileId::new(0), 0, 20),
            target: "$connection".to_string(),
            source_name: None,
            source_call: Some("Example->connect".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: Span::new(FileId::new(0), 21, 40),
            target: "$statement".to_string(),
            source_name: None,
            source_call: Some("connection->prepare".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
    ];

    let aliases = synth_factory_type_aliases(
        &events,
        &[],
        &factory,
        "perl",
        &std::collections::HashMap::new(),
        None,
        None,
        None,
    );

    assert!(aliases.contains(&TypeAliasBinding {
        name: "$connection".to_string(),
        type_name: "Example::Connection".to_string(),
    }));
    assert!(aliases.contains(&TypeAliasBinding {
        name: "$statement".to_string(),
        type_name: "Example::Statement".to_string(),
    }));
}

#[test]
fn receiver_typed_factory_aliases_form_an_exact_fixed_point() {
    let mut factory = RulepackTyping::default();
    factory.by_language.insert(
        "rust".to_string(),
        vec![
            FactoryReturnSpec {
                kind: MatchKind::Call,
                method: "query".to_string(),
                receiver_path: vec!["warp".to_string()],
                receiver_types: Vec::new(),
                type_name: "WarpFilter".to_string(),
                required_imports: Vec::new(),
                binding_origin: None,
            },
            FactoryReturnSpec {
                kind: MatchKind::Call,
                method: "and".to_string(),
                receiver_path: Vec::new(),
                receiver_types: vec!["WarpFilter".to_string()],
                type_name: "WarpFilter".to_string(),
                required_imports: Vec::new(),
                binding_origin: None,
            },
        ],
    );
    let events = vec![
        FlowEvent::Assign {
            span: Span::new(FileId::new(0), 0, 20),
            target: "input".to_string(),
            source_name: None,
            source_call: Some("warp::query".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: Span::new(FileId::new(0), 21, 40),
            target: "combined".to_string(),
            source_name: None,
            source_call: Some("input.and".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: Span::new(FileId::new(0), 41, 60),
            target: "collision".to_string(),
            source_name: None,
            source_call: Some("local.and".to_string()),
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: None,
        },
    ];

    let mut alias_map = std::collections::HashMap::new();
    let mut aliases = Vec::new();
    loop {
        let prior_len = aliases.len();
        for alias in synth_factory_type_aliases(&events, &[], &factory, "rust", &alias_map, None, None, None)
        {
            if !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
        if aliases.len() == prior_len {
            break;
        }
        extend_alias_map_with_declared_types(&mut alias_map, &aliases[prior_len..]);
    }
    assert!(aliases.contains(&TypeAliasBinding {
        name: "input".to_string(),
        type_name: "WarpFilter".to_string(),
    }));
    assert!(aliases.contains(&TypeAliasBinding {
        name: "combined".to_string(),
        type_name: "WarpFilter".to_string(),
    }));
    assert!(
        aliases.iter().all(|alias| alias.name != "collision"),
        "same-named local methods must not inherit an external receiver type: {aliases:#?}"
    );
}

#[test]
fn exact_call_expression_typing_matches_assigned_chains_and_fails_closed() {
    let statement_spec = FactoryReturnSpec {
        kind: MatchKind::Call,
        method: "open".to_string(),
        receiver_path: Vec::new(),
        receiver_types: vec!["Factory".to_string()],
        type_name: "Session".to_string(),
        required_imports: Vec::new(),
        binding_origin: None,
    };
    let mut factory = RulepackTyping::default();
    factory
        .by_language
        .insert("test".to_string(), vec![statement_spec.clone()]);
    let aliases = std::collections::HashMap::from([(
        "factory".to_string(),
        AliasTarget::Type {
            type_name: "Factory".to_string(),
        },
    )]);
    let direct_calls = vec![
        CallFact {
            callee: "factory.open".to_string(),
            receiver: Some("factory".to_string()),
            span: Span::new(FileId::new(0), 0, 12),
            args: Vec::new(),
            receiver_types: vec!["Factory".to_string()],
            call_kind: CallKind::Method,
            origin: CallFactOrigin::RealCall,
        },
        CallFact {
            callee: "factory.open().run".to_string(),
            receiver: Some("factory.open()".to_string()),
            span: Span::new(FileId::new(0), 0, 18),
            args: Vec::new(),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            origin: CallFactOrigin::RealCall,
        },
    ];
    let receiver_span = Span::new(FileId::new(0), 0, 14);
    let direct_receivers = vec![bonsai_lang_api::CallReceiverFact {
        call_span: direct_calls[1].span,
        receiver_span,
        value_flow: bonsai_lang_api::ExpressionFlow {
            call_sites: vec![receiver_span],
            ..Default::default()
        },
        role: bonsai_lang_api::CallReceiverRole::Value,
        static_value: None,
    }];
    let direct = synth_exact_call_expression_type_aliases(
        &direct_calls,
        &direct_receivers,
        &factory,
        "test",
        &aliases,
        None,
        None,
        None,
    );
    assert_eq!(
        direct,
        vec![TypeAliasBinding {
            name: "factory.open()".to_string(),
            type_name: "Session".to_string(),
        }],
        "the compiler-proven direct receiver expression must receive the declared return type"
    );

    let assigned_events = vec![FlowEvent::Assign {
        span: Span::new(FileId::new(0), 0, 14),
        target: "session".to_string(),
        source_name: None,
        source_call: Some("factory.open".to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: None,
    }];
    let assigned = synth_factory_type_aliases(
        &assigned_events,
        &[],
        &factory,
        "test",
        &aliases,
        None,
        None,
        None,
    );
    assert_eq!(
        assigned.first().map(|alias| alias.type_name.as_str()),
        Some("Session")
    );

    let unrelated_aliases = std::collections::HashMap::from([(
        "factory".to_string(),
        AliasTarget::Type {
            type_name: "LocalFactory".to_string(),
        },
    )]);
    assert!(
        synth_exact_call_expression_type_aliases(
            &direct_calls,
            &direct_receivers,
            &factory,
            "test",
            &unrelated_aliases,
            None,
            None,
            None,
        )
        .is_empty(),
        "a same-spelled method on an unrelated compiler type must not inherit the external return contract"
    );

    factory
        .by_language
        .get_mut("test")
        .expect("test typing specs")
        .push(FactoryReturnSpec {
            type_name: "OtherSession".to_string(),
            ..statement_spec
        });
    assert!(
        synth_exact_call_expression_type_aliases(
            &direct_calls,
            &direct_receivers,
            &factory,
            "test",
            &aliases,
            None,
            None,
            None,
        )
        .is_empty(),
        "ambiguous return contracts must fail closed"
    );
}

#[test]
fn qualified_receiver_types_do_not_collapse_to_a_same_named_local_type() {
    assert!(type_name_matches_attribute_prefix(
        "*github.com/gin-gonic/gin.Context",
        &["gin".to_string(), "Context".to_string()],
    ));
    assert!(!type_name_matches_attribute_prefix(
        "Context",
        &["gin".to_string(), "Context".to_string()],
    ));
    assert!(type_name_matches_attribute_prefix(
        "*github.com/gin-gonic/gin.Context",
        &["Context".to_string()],
    ));
}

#[test]
fn typed_receiver_matches_an_exact_multipart_callable_suffix() {
    assert!(receiver_type_attribute_matches(
        "widget.consume:mode:",
        &["Widget".to_string()],
        &["Widget".to_string(), "consume:mode:".to_string(),],
    ));
    assert!(!receiver_type_attribute_matches(
        "widget.consume:other:",
        &["Widget".to_string()],
        &["Widget".to_string(), "consume:mode:".to_string(),],
    ));
}

#[test]
fn external_typed_multipart_call_matches_compiler_receiver_and_import_facts() {
    let rule = rule_from_yaml(
        r#"
id: objc.test.external-multipart
enabled: true
language: objc
tag: injection
severity: high
packages: [Framework]
imports: [Framework]
match:
  kind: call
  callee:
    attribute: [Widget, "consume:mode:"]
    receiver_type_in: [Widget]
description: Neutral multipart receiver fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    assert!(rule_target_matches_call(
        "widget.consume:mode:",
        &["Widget".to_string()],
        rule.match_spec.callee.as_ref().expect("callee target"),
    ));

    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "consumer.m",
        r#"
#import <Framework/Header.h>
void render(Widget *widget, id input) {
  [widget consume:input mode:nil];
}
"#,
    );
    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(matches.len(), 1, "matches: {matches:#?}");
    assert_eq!(matches[0].match_text, "widget.consume:mode:");
}

#[test]
fn external_receiver_type_rejects_local_type_shadow_but_accepts_qualified_identity() {
    let rule = rule_from_yaml(
        r#"
id: swift.test.external_client
enabled: true
language: swift
tag: sql-injection
severity: high
packages: [External]
imports: [External]
cwe: [CWE-89]
match:
  kind: call
  callee:
    regex: '^[A-Za-z_][A-Za-z0-9_]*\.execute$'
    receiver_type_in: [Client]
constraints:
- arg_tainted: { index: 0 }
description: test
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("prepared rule");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "entry.swift",
        "import External\nstruct Client {}\nfunc run(client: Client, input: String) { client.execute(input) }\n",
    );
    let index = ws.db().decl_index(file).expect("Swift declaration index");

    assert!(external_receiver_type_is_workspace_shadow(
        &prepared,
        &["Client".to_string()],
        &index.defs,
        None,
    ));
    assert!(!external_receiver_type_is_workspace_shadow(
        &prepared,
        &["External.Client".to_string()],
        &index.defs,
        None,
    ));
}

#[test]
fn exact_enclosing_base_is_source_provenance_without_package_presence() {
    let rule = rule_from_yaml(
        r#"
id: ruby.test.controller_input
enabled: true
language: ruby
trust: remote
tag: http-input
packages: [external-web-runtime]
match:
  kind: read
  target:
    name: input_data
    in_class: [FrameworkController]
description: Neutral compiler-owned controller input fixture.
"#,
        crate::rule::RuleKind::Source,
    );
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "controllers.rb",
        r#"
class ReportsController < FrameworkController
  def show
    input_data[:query]
  end
end

class LocalController < ApplicationBase
  def show
    input_data[:query]
  end
end

def helper(input_data)
  input_data[:query]
end
"#,
    );

    let hits = match_rule_against_facts(&ws, &rule);
    assert_eq!(
        hits.len(),
        1,
        "only the read in the exact compiler-owned framework subclass may satisfy source provenance: {hits:#?}"
    );
    assert_eq!(hits[0].enclosing_fn.as_deref(), Some("show"));
}

#[test]
fn unresolved_typed_parameter_proves_external_identity_but_workspace_shadow_fails_closed() {
    let rule = rule_from_yaml(
        r#"
id: objc.test.external_typed_boundary
enabled: true
language: objc
trust: remote
tag: http-input
category: http-input
packages: [TransportKit]
match:
  kind: param
  target:
    regex: '^[A-Za-z_][A-Za-z0-9_]*$'
    param_type_in: [InboundEnvelope]
description: neutral typed external request boundary
"#,
        crate::rule::RuleKind::Source,
    );

    let external = Workspace::new(bonsai_adapters::all_languages_registry());
    external.vfs().write(
        "Handler.m",
        r#"
#import <Foundation/Foundation.h>
void receive(InboundEnvelope *packet) { NSLog(@"%@", packet); }
"#,
    );
    let hits = match_rule_against_facts(&external, &rule);
    assert_eq!(
        hits.len(),
        1,
        "an exact unresolved parameter type with no workspace owner is external compiler identity: {hits:#?}"
    );

    let shadowed = Workspace::new(bonsai_adapters::all_languages_registry());
    shadowed.vfs().write(
        "InboundEnvelope.m",
        r#"
#import <Foundation/Foundation.h>
@interface InboundEnvelope : NSObject
@end
@implementation InboundEnvelope
@end
"#,
    );
    shadowed.vfs().write(
        "Handler.m",
        r#"
#import <Foundation/Foundation.h>
void receive(InboundEnvelope *packet) { NSLog(@"%@", packet); }
"#,
    );
    let hits = match_rule_against_facts(&shadowed, &rule);
    assert!(
        hits.is_empty(),
        "a same-named workspace type must never inherit an external boundary contract: {hits:#?}"
    );
}

#[test]
fn exact_parameter_type_constraint_rejects_same_tail_and_unqualified_types() {
    let rule = rule_from_yaml(
        r#"
id: cpp.test.exact_typed_boundary
enabled: true
language: cpp
trust: remote
tag: network-input
category: network-input
match:
  kind: param
  target:
    regex: '^[A-Za-z_][A-Za-z0-9_]*$'
    param_type_exact_in: [alpha::Packet]
description: neutral exact typed boundary
"#,
        crate::rule::RuleKind::Source,
    );
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "entry.cpp",
        r#"
namespace alpha { struct Packet {}; }
namespace beta { struct Packet {}; }
struct Packet {};
void accepted(const alpha::Packet& value) { consume(value); }
void wrong_provider(const beta::Packet& value) { consume(value); }
void unqualified(const Packet& value) { consume(value); }
"#,
    );

    let hits = match_rule_against_facts(&ws, &rule);
    assert_eq!(
        hits.len(),
        1,
        "only the exact qualified type may match: {hits:#?}"
    );
    assert_eq!(hits[0].match_text, "value");
    assert_eq!(hits[0].enclosing_fn.as_deref(), Some("accepted"));
}

#[test]
fn typed_write_rules_require_exact_declared_receiver_evidence() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "positive.cs",
        r#"
using External.Config;
class Positive {
  void Configure(ExternalSettings settings) { settings.Mode = "weak"; }
}
"#,
    );
    ws.vfs().write(
        "wrong_type.cs",
        r#"
using External.Config;
class LocalSettings { public string Mode { get; set; } }
class WrongType {
  void Configure(LocalSettings settings) { settings.Mode = "weak"; }
}
"#,
    );
    ws.vfs().write(
        "local_shadow.cs",
        r#"
using External.Config;
class ExternalSettings { public string Mode { get; set; } }
class LocalShadow {
  void Configure(ExternalSettings settings) { settings.Mode = "weak"; }
}
"#,
    );
    ws.vfs().write(
        "ambiguous_shadow.cs",
        r#"
using External.Config;
using First;
using Second;
namespace First { class ExternalSettings { public string Mode { get; set; } } }
namespace Second { class ExternalSettings { public string Mode { get; set; } } }
class AmbiguousShadow {
  void Configure(ExternalSettings settings) { settings.Mode = "weak"; }
}
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: csharp.test.typed_write
enabled: true
language: csharp
tag: weak-configuration
severity: high
imports: [External.Config]
match:
  kind: write
  target:
    regex: '^[A-Za-z_][A-Za-z0-9_]*\.Mode$'
    receiver_type_in: [ExternalSettings]
description: Neutral typed write endpoint.
"#,
        crate::rule::RuleKind::Sink,
    );

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(matches.len(), 1, "matches: {matches:#?}");
    assert_eq!(matches[0].file, "positive.cs");

    let factory = build_rulepack_typing(&[&rule]);
    let global_headers = streaming_global_headers(&ws);
    let receiver_base_map_cell = OnceLock::new();
    let tainted_calls = [];
    assert!(
        rule_match_passes_constraints_with_taint_view(
            &ws,
            &rule,
            &matches[0],
            &InterTaintView::new(&tainted_calls),
            &RuleConstraintTaintContext {
                endpoint_identity_proven: false,
                factory: factory.as_ref(),
                global_headers: &global_headers,
                receiver_base_map_cell: &receiver_base_map_cell,
            },
        ),
        "exact endpoint rechecks must retain the same typed-receiver proof as the broad write scan"
    );
}

#[test]
fn write_binding_origin_uses_exact_runtime_and_import_scope_facts() {
    let runtime_ws = Workspace::new(bonsai_adapters::all_languages_registry());
    runtime_ws
        .vfs()
        .write("runtime_positive.js", "runtimeRoot.config.mode = 'weak';\n");
    runtime_ws.vfs().write(
        "parameter_shadow.js",
        "function configure(runtimeRoot) { runtimeRoot.config.mode = 'weak'; }\n",
    );
    runtime_ws.vfs().write(
        "local_shadow.js",
        "function configure() { const runtimeRoot = localFactory(); runtimeRoot.config.mode = 'weak'; }\n",
    );
    runtime_ws.vfs().write(
        "module_shadow.js",
        "const runtimeRoot = localFactory();\nfunction configure() { runtimeRoot.config.mode = 'weak'; }\n",
    );
    let runtime_rule = rule_from_yaml(
        r#"
id: javascript.test.runtime-write-owner
enabled: true
language: javascript
tag: weak-configuration
severity: high
match:
  kind: write
  target:
    attribute: [runtimeRoot, config, mode]
    binding_origin: runtime-global
description: Neutral runtime-owned write endpoint.
"#,
        crate::rule::RuleKind::Sink,
    );

    let runtime_matches = match_rules_against_facts(&runtime_ws, &[&runtime_rule]);
    assert_eq!(runtime_matches.len(), 1, "matches: {runtime_matches:#?}");
    assert_eq!(runtime_matches[0].file, "runtime_positive.js");

    let imported_rule = rule_from_yaml(
        r#"
id: python.test.imported-write-owner
enabled: true
language: python
tag: weak-configuration
severity: high
imports: [external_provider]
match:
  kind: write
  target:
    attribute: [provider, config, mode]
    binding_origin: imported
description: Neutral imported write endpoint.
"#,
        crate::rule::RuleKind::Sink,
    );
    let imported_ws = Workspace::new(bonsai_adapters::all_languages_registry());
    imported_ws.vfs().write(
        "external.py",
        "import external_provider as provider\nprovider.config.mode = 'weak'\n",
    );
    let imported_matches = match_rules_against_facts(&imported_ws, &[&imported_rule]);
    assert_eq!(imported_matches.len(), 1, "matches: {imported_matches:#?}");

    let local_ws = Workspace::new(bonsai_adapters::all_languages_registry());
    local_ws
        .vfs()
        .write("external_provider.py", "config = object()\n");
    local_ws.vfs().write(
        "local.py",
        "import external_provider as provider\nprovider.config.mode = 'weak'\n",
    );
    assert!(
        match_rules_against_facts(&local_ws, &[&imported_rule]).is_empty(),
        "a workspace-local module must shadow a rule-declared external provider"
    );

    let namespace_rule = rule_from_yaml(
        r#"
id: csharp.test.imported-namespace-write-owner
enabled: true
language: csharp
tag: weak-configuration
severity: high
imports: [Example.Provider]
match:
  kind: write
  target:
    attribute: [GlobalOptions, Mode]
    binding_origin: imported
description: Neutral imported namespace write endpoint.
"#,
        crate::rule::RuleKind::Sink,
    );
    let namespace_ws = Workspace::new(bonsai_adapters::all_languages_registry());
    namespace_ws.vfs().write(
        "namespace_positive.cs",
        "using Example.Provider; class App { void Configure() { GlobalOptions.Mode = 1; } }",
    );
    let namespace_matches = match_rules_against_facts(&namespace_ws, &[&namespace_rule]);
    assert_eq!(namespace_matches.len(), 1, "matches: {namespace_matches:#?}");

    let namespace_shadow_ws = Workspace::new(bonsai_adapters::all_languages_registry());
    namespace_shadow_ws.vfs().write(
        "namespace_shadow.cs",
        "using Example.Provider; class GlobalOptions { public static int Mode { get; set; } } class App { void Configure() { GlobalOptions.Mode = 1; } }",
    );
    assert!(
        match_rules_against_facts(&namespace_shadow_ws, &[&namespace_rule]).is_empty(),
        "a workspace declaration must shadow a namespace-imported write owner"
    );
}

#[test]
fn read_binding_origin_uses_exact_runtime_scope_facts() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "runtime_positive.js",
        "function readMode() { return runtimeRoot.config.mode; }\n",
    );
    ws.vfs().write(
        "parameter_shadow.js",
        "function readMode(runtimeRoot) { return runtimeRoot.config.mode; }\n",
    );
    ws.vfs().write(
        "local_shadow.js",
        "function readMode() { const runtimeRoot = localFactory(); return runtimeRoot.config.mode; }\n",
    );
    ws.vfs().write(
        "module_shadow.js",
        "const runtimeRoot = localFactory();\nfunction readMode() { return runtimeRoot.config.mode; }\n",
    );
    let rule = rule_from_yaml(
        r#"
id: javascript.test.runtime-read-owner
enabled: true
language: javascript
trust: remote
tag: remote-input
match:
  kind: read
  target:
    attribute: [runtimeRoot, config, mode]
    binding_origin: runtime-global
description: Neutral runtime-owned read endpoint.
"#,
        crate::rule::RuleKind::Source,
    );

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(matches.len(), 1, "matches: {matches:#?}");
    assert_eq!(matches[0].file, "runtime_positive.js");
}

#[test]
fn typed_read_rules_require_exact_declared_or_imported_receiver_evidence() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "positive.java",
        r#"
import external.config.ExternalMode;
class Positive { Object select() { return ExternalMode.WEAK; } }
"#,
    );
    ws.vfs().write(
        "wrong_type.java",
        r#"
import external.config.ExternalMode;
class LocalMode { Object WEAK; }
class WrongType { Object select(LocalMode mode) { return mode.WEAK; } }
"#,
    );
    ws.vfs().write(
        "local_shadow.java",
        r#"
import external.config.ExternalMode;
class ExternalMode { static final Object WEAK = new Object(); }
class LocalShadow { Object select() { return ExternalMode.WEAK; } }
"#,
    );
    ws.vfs().write(
        "ambiguous_shadow.java",
        r#"
import first.ExternalMode;
import second.ExternalMode;
import external.config.*;
class AmbiguousShadow { Object select() { return ExternalMode.WEAK; } }
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: java.test.typed_read
enabled: true
language: java
tag: weak-configuration
severity: high
imports: [external.config]
match:
  kind: read
  target:
    regex: '^[A-Za-z_][A-Za-z0-9_]*\.WEAK$'
    receiver_type_in: [ExternalMode, external.config.ExternalMode]
description: Neutral typed read endpoint.
"#,
        crate::rule::RuleKind::Sink,
    );

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(matches.len(), 1, "matches: {matches:#?}");
    assert_eq!(matches[0].file, "positive.java");
}

#[test]
fn aggregate_field_constraint_uses_exact_compiler_values_and_fails_closed() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "positive.js",
        "const timeout = dynamicTimeout; client.configure({ timeout, transport: { verify: false } });\n",
    );
    ws.vfs().write(
        "secure.js",
        "client.configure({ transport: { verify: true }, timeout: 1000 });\n",
    );
    ws.vfs().write(
        "dynamic.js",
        "client.configure({ transport: { verify: setting }, timeout: 1000 });\n",
    );
    ws.vfs().write(
        "spread.js",
        "client.configure({ ...defaults, transport: { verify: false } });\n",
    );
    ws.vfs().write("non_aggregate.js", "client.configure(false);\n");
    ws.vfs().write(
        "duplicate_path.js",
        "client.configure({ transport: { verify: false }, transport: { verify: true } });\n",
    );
    ws.vfs().write(
        "dynamic_key.js",
        "client.configure({ [field]: false, transport: { verify: false } });\n",
    );
    let rule = rule_from_yaml(
        r#"
id: javascript.test.exact-aggregate-config
enabled: true
language: javascript
tag: weak-configuration
category: source-independent
severity: high
match:
  kind: call
  callee:
    attribute: [client, configure]
constraints:
  - arg_aggregate_fields_equal:
      argument_index: 0
      required_fields:
        - path: [transport, verify]
          value: { kind: boolean, value: false }
description: Neutral exact aggregate configuration fixture.
"#,
        crate::rule::RuleKind::Sink,
    );

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(matches.len(), 1, "matches: {matches:#?}");
    assert_eq!(matches[0].file, "positive.js");
}

#[test]
fn structured_new_metadata_is_exact_and_function_shaped_typing_fails_closed_without_identity() {
    let constructor_rule = rule_from_yaml(
        r#"
id: kotlin.test.lowercase_constructor
enabled: true
language: kotlin
tag: path-traversal
severity: high
cwe: [CWE-22]
match:
  kind: new
  callee:
    attribute: [example, lowercase]
constraints: []
match_examples:
  - code: 'fun f() { example.lowercase() }'
description: exact external constructor metadata
"#,
        crate::rule::RuleKind::Sink,
    );
    let return_type_rule = rule_from_yaml(
        r#"
id: kotlin.typing.lowercase_constructor
enabled: true
language: kotlin
returns_type: lowercase
match:
  kind: new
  callee:
    attribute: [example, lowercase]
constraints: []
match_examples:
  - code: 'fun f() { val value = example.lowercase() }'
description: exact external constructor result type
"#,
        crate::rule::RuleKind::Typing,
    );
    let constructor_only = build_rulepack_typing(&[&constructor_rule]);
    let typing = build_rulepack_typing(&[&constructor_rule, &return_type_rule]);
    let alias_map = std::collections::HashMap::from([(
        "lowercase".to_string(),
        AliasTarget::Namespace {
            module: "example.lowercase".to_string(),
        },
    )]);

    assert!(rulepack_constructor_matches_call(
        &constructor_only,
        "kotlin",
        "lowercase",
        None,
        &alias_map,
        None,
    ));
    assert!(!rulepack_constructor_matches_call(
        &typing,
        "kotlin",
        "unrelated",
        None,
        &alias_map,
        None,
    ));

    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "value".to_string(),
        source_name: None,
        source_call: Some("example.lowercase".to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: None,
    }];
    assert!(
        synth_factory_type_aliases(
            &events,
            &[],
            &constructor_only,
            "kotlin",
            &alias_map,
            None,
            None,
            None,
        )
        .is_empty(),
        "constructor identity alone must not inject a result type"
    );
    assert!(
        synth_factory_type_aliases(&events, &[], &typing, "kotlin", &alias_map, None, None, None).is_empty(),
        "a function-shaped CST call must not receive constructor return typing without exact workspace identity"
    );
}

#[test]
fn collect_calls_drops_assignment_source_call_shadowed_by_real_call() {
    let events = vec![
        FlowEvent::Call {
            name: "eval".to_string(),
            receiver: None,
            args: vec![
                CallArg {
                    passing_mode: Default::default(),
                    span: span(),
                    name: None,
                    place: None,
                    source_names: Vec::new(),
                    value_text: "py_expr".to_string(),
                },
                CallArg {
                    passing_mode: Default::default(),
                    span: span(),
                    name: None,
                    place: None,
                    source_names: Vec::new(),
                    value_text: "{\"attributes\": attributes}".to_string(),
                },
            ],
            receiver_types: Vec::new(),
            span: span(),
            call_kind: CallKind::Function,
        },
        FlowEvent::Assign {
            span: span(),
            target: "result".to_string(),
            source_name: None,
            source_call: Some("eval".to_string()),
            source_call_args: vec!["py_expr".to_string(), "{\"attributes\": attributes}".to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        },
    ];

    let calls = collect_calls(&events);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].callee, "eval");
    assert_eq!(calls[0].origin, CallFactOrigin::RealCall);
    assert!(calls[0].receiver_types.is_empty());
    assert_eq!(
        calls[0]
            .args
            .iter()
            .map(|arg| arg.value_text.as_str())
            .collect::<Vec<_>>(),
        vec!["py_expr", "{\"attributes\": attributes}"]
    );
}

#[test]
fn receiver_type_facts_match_type_method_rules_without_receiver_names() {
    let attr = vec!["Cookie".to_string(), "getValue".to_string()];
    assert!(callee_matches_with_receiver_types(
        "c.getValue",
        &["Cookie".to_string()],
        None,
        Some(&attr),
        None,
    ));
    assert!(callee_matches_with_receiver_types(
        "c.getValue",
        &["jakarta.servlet.http.Cookie".to_string()],
        None,
        Some(&attr),
        None,
    ));
    assert!(!callee_matches_with_receiver_types(
        "c.getValue",
        &["Header".to_string()],
        None,
        Some(&attr),
        None,
    ));
}

#[test]
fn receiver_type_facts_match_regex_rules_for_canonical_instance_places() {
    let regex = Regex::new(r"^XStream\.fromXML$").expect("valid fixture regex");
    assert!(callee_matches_with_receiver_types(
        "this.xstream.fromXML",
        &["com.thoughtworks.xstream.XStream".to_string()],
        None,
        None,
        Some(&regex),
    ));
    assert!(!callee_matches_with_receiver_types(
        "this.parser.fromXML",
        &["SafeXmlParser".to_string()],
        None,
        None,
        Some(&regex),
    ));
    assert!(!callee_matches_with_receiver_types(
        "client.get().fromXML",
        &["com.thoughtworks.xstream.XStream".to_string()],
        None,
        None,
        Some(&regex),
    ));
}

#[test]
fn qualified_implicit_receiver_uses_compiler_type_evidence() {
    let rule = rule_from_yaml(
        r#"
id: java.test.typed_logger
enabled: true
language: java
tag: log-injection
severity: high
match:
  kind: call
  callee:
    regex: '(^|[.])info$'
    receiver_type_in: [Logger]
description: Typed logger fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    assert!(base_receiver_type_allows(
        &prepared,
        None,
        "this.log.info",
        &["Logger".to_string()],
        &[],
    ));
    assert!(
        !base_receiver_type_allows(&prepared, None, "info", &[], &[]),
        "a terminal ref without receiver evidence must fail closed"
    );
}

#[test]
fn provider_qualified_receiver_identity_accepts_only_the_exact_provider() {
    let rule = rule_from_yaml(
        r#"
id: python.test.provider-client
enabled: true
language: python
tag: injection
severity: high
packages: [provider]
imports: [provider]
match:
  kind: call
  callee: { name: execute }
constraints:
  - receiver_type_in: [Client, provider.Client]
description: Neutral provider-qualified receiver fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");

    assert!(!external_receiver_type_is_workspace_shadow(
        &prepared,
        &["provider.Client".to_string()],
        &[],
        None,
    ));
    assert!(external_receiver_type_is_workspace_shadow(
        &prepared,
        &["application.Client".to_string()],
        &[],
        None,
    ));
}

#[test]
fn imported_receiver_qualifier_proves_a_rule_scoped_simple_type() {
    let rule = rule_from_yaml(
        r#"
id: go.test.import-qualified-client
enabled: true
language: go
tag: injection
severity: high
packages: [example.org/provider]
match:
  kind: call
  callee: { name: execute }
constraints:
  - receiver_type_in: [Client]
description: Neutral imported receiver fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let matching_import = bonsai_lang_api::ImportIndex {
        file: FileId::new(0),
        imports: vec![bonsai_lang_api::ImportSpec {
            span: span(),
            module: "example.org/provider".to_string(),
            alias: Some("provider".to_string()),
            is_wildcard: false,
            original_name: None,
            scope: bonsai_lang_api::ImportScope::Module,
        }],
    };
    assert!(!external_receiver_type_is_workspace_shadow(
        &prepared,
        &["provider.Client".to_string()],
        &[],
        Some(&matching_import),
    ));

    let qualified_import = bonsai_lang_api::ImportIndex {
        file: FileId::new(0),
        imports: vec![bonsai_lang_api::ImportSpec {
            span: span(),
            module: "example.org/provider".to_string(),
            alias: Some("Client".to_string()),
            is_wildcard: false,
            original_name: None,
            scope: bonsai_lang_api::ImportScope::Module,
        }],
    };
    assert!(!external_receiver_type_is_workspace_shadow(
        &prepared,
        &["example.org/provider.Client".to_string()],
        &[],
        Some(&qualified_import),
    ));

    let wrong_import = bonsai_lang_api::ImportIndex {
        file: FileId::new(0),
        imports: vec![bonsai_lang_api::ImportSpec {
            span: span(),
            module: "example.org/application".to_string(),
            alias: Some("provider".to_string()),
            is_wildcard: false,
            original_name: None,
            scope: bonsai_lang_api::ImportScope::Module,
        }],
    };
    assert!(external_receiver_type_is_workspace_shadow(
        &prepared,
        &["provider.Client".to_string()],
        &[],
        Some(&wrong_import),
    ));
}

#[test]
fn unaliased_import_proves_nested_receiver_head_and_ambiguity_fails_closed() {
    let rule = rule_from_yaml(
        r#"
id: scala.test.imported-nested-builder
enabled: true
language: scala
tag: injection
severity: high
packages: [example.org/provider]
imports: [example.org.provider.Client]
match:
  kind: call
  callee:
    name: configure
    receiver_type_in: [Builder, example.org.provider.Client.Builder]
description: Neutral imported nested receiver fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let import = |module: &str| bonsai_lang_api::ImportSpec {
        span: span(),
        module: module.to_string(),
        alias: None,
        is_wildcard: false,
        original_name: None,
        scope: bonsai_lang_api::ImportScope::Module,
    };
    let matching_import = bonsai_lang_api::ImportIndex {
        file: FileId::new(0),
        imports: vec![import("example.org.provider.Client")],
    };
    assert!(!external_receiver_type_is_workspace_shadow(
        &prepared,
        &["Client.Builder".to_string()],
        &[],
        Some(&matching_import),
    ));

    let wrong_import = bonsai_lang_api::ImportIndex {
        file: FileId::new(0),
        imports: vec![import("example.org.application.Client")],
    };
    assert!(external_receiver_type_is_workspace_shadow(
        &prepared,
        &["Client.Builder".to_string()],
        &[],
        Some(&wrong_import),
    ));

    let ambiguous_imports = bonsai_lang_api::ImportIndex {
        file: FileId::new(0),
        imports: vec![
            import("example.org.provider.Client"),
            import("example.org.application.Client"),
        ],
    };
    assert!(external_receiver_type_is_workspace_shadow(
        &prepared,
        &["Client.Builder".to_string()],
        &[],
        Some(&ambiguous_imports),
    ));

    let namespace_and_member_same_provider = bonsai_lang_api::ImportIndex {
        file: FileId::new(0),
        imports: vec![
            import("example.org.provider"),
            bonsai_lang_api::ImportSpec {
                span: span(),
                module: "example.org.provider".to_string(),
                alias: None,
                is_wildcard: false,
                original_name: Some("Client".to_string()),
                scope: bonsai_lang_api::ImportScope::Module,
            },
        ],
    };
    assert!(!external_receiver_type_is_workspace_shadow(
        &prepared,
        &["example.org.provider.Client.Builder".to_string()],
        &[],
        Some(&namespace_and_member_same_provider),
    ));
}

#[test]
fn imported_type_alias_expands_nested_call_receiver_without_hiding_local_collisions() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "positive.kt",
        r#"
import external.client.Provider as RemoteProvider
class Positive {
  fun run(builder: RemoteProvider.Builder) { builder.configure() }
}
"#,
    );
    ws.vfs().write(
        "local_collision.kt",
        r#"
import external.client.Provider as ImportedProvider
class RemoteProvider { class Builder { fun configure() {} } }
class LocalCollision {
  fun run(builder: RemoteProvider.Builder, imported: ImportedProvider) {
    builder.configure()
  }
}
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: kotlin.test.imported-nested-receiver
enabled: true
language: kotlin
tag: weak-configuration
category: source-independent
severity: high
packages: [external.client]
imports: [external.client.Provider]
match:
  kind: call
  callee:
    name: configure
    receiver_type_in: [external.client.Provider.Builder]
description: Neutral imported nested receiver fixture.
"#,
        crate::rule::RuleKind::Sink,
    );

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(matches.len(), 1, "matches: {matches:#?}");
    assert_eq!(matches[0].file, "positive.kt");
}

#[test]
fn imported_nested_receiver_and_exact_inline_callback_join_without_name_guesses() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "positive.kt",
        r#"
import external.client.Provider as RemoteProvider
class Positive {
  fun run(builder: RemoteProvider.Builder) {
    builder.configure { left, right -> true }
  }
}
"#,
    );
    ws.vfs().write(
        "false_return.kt",
        r#"
import external.client.Provider as RemoteProvider
class FalseReturn {
  fun run(builder: RemoteProvider.Builder) {
    builder.configure { left, right -> false }
  }
}
"#,
    );
    ws.vfs().write(
        "mixed_return.kt",
        r#"
import external.client.Provider as RemoteProvider
class MixedReturn {
  fun run(builder: RemoteProvider.Builder, allow: Boolean) {
    builder.configure { left, right -> if (allow) true else false }
  }
}
"#,
    );
    ws.vfs().write(
        "named_callback.kt",
        r#"
import external.client.Provider as RemoteProvider
class NamedCallback {
  fun decide(left: Any, right: Any): Boolean = true
  fun run(builder: RemoteProvider.Builder) {
    builder.configure(::decide)
  }
}
"#,
    );
    ws.vfs().write(
        "local_collision.kt",
        r#"
import external.client.Provider as ImportedProvider
class RemoteProvider {
  class Builder { fun configure(value: (Any, Any) -> Boolean) {} }
}
class LocalCollision {
  fun run(builder: RemoteProvider.Builder, imported: ImportedProvider) {
    builder.configure { left, right -> true }
  }
}
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: kotlin.test.imported-inline-callback
enabled: true
language: kotlin
tag: weak-configuration
category: source-independent
severity: high
packages: [external.client]
imports: [external.client.Provider]
match:
  kind: call
  callee:
    name: configure
    receiver_type_in: [external.client.Provider.Builder]
constraints:
  - arg_inline_callback_returns_static:
      index: 0
      value: {kind: boolean, value: true}
description: Neutral imported callback endpoint fixture.
"#,
        crate::rule::RuleKind::Sink,
    );

    let positive_file = ws
        .db()
        .vfs()
        .all_files()
        .into_iter()
        .find(|file| {
            ws.db()
                .vfs()
                .path(*file)
                .is_ok_and(|path| path.ends_with("positive.kt"))
        })
        .expect("positive Kotlin fixture");
    let positive_index = ws
        .db()
        .decl_index(positive_file)
        .expect("positive Kotlin compiler index");
    let positive_imports = ws
        .db()
        .import_index(positive_file)
        .expect("positive Kotlin compiler imports");
    let positive_decl = positive_index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("positive run declaration");
    assert!(
        positive_decl
            .type_aliases
            .iter()
            .any(|alias| alias.name == "builder" && alias.type_name == "RemoteProvider.Builder"),
        "explicit nested receiver type was lost: {:#?}",
        positive_decl.type_aliases
    );
    let import_aliases = bonsai_lang_api::alias_map_from_imports(&positive_imports);
    let mut positive_calls = collect_calls(&positive_decl.flow_events);
    enrich_call_fact_receiver_types(&mut positive_calls, &positive_decl.type_aliases);
    enrich_call_fact_receiver_import_types(&mut positive_calls, &import_aliases);
    let positive_call = positive_calls
        .iter()
        .find(|call| call.callee == "builder.configure")
        .expect("positive configure call");
    assert!(
        positive_call
            .receiver_types
            .iter()
            .any(|type_name| type_name == "external.client.Provider.Builder"),
        "import-expanded receiver identity was lost: {positive_call:#?}"
    );
    let callback_fact = bonsai_lang_api::call_argument_value_fact(
        &positive_index.call_argument_values,
        positive_call.span,
        0,
    )
    .unwrap_or_else(|| {
        panic!(
            "callback fact did not join the exact call span {:?}: {:#?}",
            positive_call.span, positive_index.call_argument_values
        )
    });
    assert_eq!(
        callback_fact.inline_callback_static_return,
        Some(bonsai_lang_api::StaticScalarValue::Boolean(true)),
        "inline callback summary is not an exact static true: {callback_fact:#?}"
    );
    let prepared = PreparedRule::new(&rule).expect("neutral callback rule prepares");
    let matched_callee = prepared
        .call_target_matches(positive_call, &positive_call.receiver_types, &import_aliases)
        .expect("typed configure target matches");
    assert!(base_receiver_type_allows(
        &prepared,
        Some(positive_decl),
        &matched_callee,
        &positive_call.receiver_types,
        &[],
    ));
    assert!(!external_receiver_type_is_workspace_shadow(
        &prepared,
        &positive_call.receiver_types,
        &positive_index.defs,
        Some(&positive_imports),
    ));
    assert!(constraints_pass(ConstraintEval {
        rule_id: &rule.id,
        callee: &matched_callee,
        receiver: positive_call.receiver.as_deref(),
        args: &positive_call.args,
        receiver_types: &positive_call.receiver_types,
        span: positive_call.span,
        call_origin: Some(positive_call.origin),
        constraints: &rule.constraints.0,
        constraint_regexes: &prepared.constraint_regexes,
        receiver_call_count: None,
        assignment_texts: None,
        ast_arg_values: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        enclosing_modifiers: None,
        alias_chains: None,
        runtime_types: None,
        lifecycle_transitions: None,
        structural_context: Some(StructuralConstraintContext {
            current_decl: positive_decl,
            file_decls: &positive_index.defs,
            assignment_values: &positive_index.assignment_values,
            call_argument_values: &positive_index.call_argument_values,
            string_compositions: &positive_index.string_compositions,
            factory_import_identity: None,
        }),
    }));

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(matches.len(), 1, "matches: {matches:#?}");
    assert_eq!(matches[0].file, "positive.kt");
}

#[test]
fn provider_qualified_receiver_identity_fails_closed_on_ambiguous_types() {
    let rule = rule_from_yaml(
        r#"
id: python.test.provider-client-ambiguous
enabled: true
language: python
tag: injection
severity: high
packages: [provider]
imports: [provider]
match:
  kind: call
  callee: { name: execute }
constraints:
  - receiver_type_in: [Client, provider.Client]
description: Neutral ambiguous receiver fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");

    assert!(external_receiver_type_is_workspace_shadow(
        &prepared,
        &["provider.Client".to_string(), "application.Client".to_string()],
        &[],
        None,
    ));
}

#[test]
fn provider_scoped_simple_receiver_rejects_a_workspace_type_shadow() {
    let rule = rule_from_yaml(
        r#"
id: python.test.provider-client-shadow
enabled: true
language: python
tag: injection
severity: high
packages: [provider]
imports: [provider]
match:
  kind: call
  callee: { name: execute }
constraints:
  - receiver_type_in: [Client, provider.Client]
description: Neutral simple receiver shadow fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "consumer.py",
        "class Client:\n    def execute(self, value):\n        return value\n",
    );
    let index = ws.db().decl_index(file).expect("Python declaration index");

    assert!(external_receiver_type_is_workspace_shadow(
        &prepared,
        &["Client".to_string()],
        &index.defs,
        None,
    ));
}

#[test]
fn provider_qualified_receiver_identity_is_enforced_end_to_end() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "positive.rs",
        r#"
use provider::Client;
fn configure(client: Client) { client.execute(); }
"#,
    );
    ws.vfs().write(
        "local_shadow.rs",
        r#"
use provider::ProviderClient;
struct Client;
impl Client { fn execute(&self) {} }
fn configure(client: Client) { client.execute(); }
"#,
    );
    ws.vfs().write(
        "ambiguous.rs",
        r#"
use provider::Client;
use application::Client;
fn configure(client: Client) { client.execute(); }
"#,
    );
    let rule = rule_from_yaml(
        r#"
id: rust.test.provider-client-end-to-end
enabled: true
language: rust
tag: injection
severity: high
packages: [provider]
imports: [provider]
match:
  kind: call
  callee: { name: execute }
constraints:
  - receiver_type_in: [Client, "provider::Client"]
  - arg_count: 0
description: Neutral provider-qualified receiver fixture.
"#,
        crate::rule::RuleKind::Sink,
    );

    let matches = match_rules_against_facts(&ws, &[&rule]);
    assert_eq!(matches.len(), 1, "matches: {matches:#?}");
    assert_eq!(matches[0].file, "positive.rs");
}

#[test]
fn sigiled_receiver_uses_normalized_rulepack_factory_type_evidence() {
    let rule = rule_from_yaml(
        r#"
id: php.test.typed_response
enabled: true
language: php
tag: xss
severity: high
match:
  kind: call
  callee:
    regex: '^[A-Za-z_$][A-Za-z0-9_$]*\.write$'
    receiver_type_in: [ResponseBody]
description: Typed PHP response fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let aliases = vec![TypeAliasBinding {
        name: "$body".to_string(),
        type_name: "ResponseBody".to_string(),
    }];

    assert!(base_receiver_type_allows(
        &prepared,
        None,
        "body.write",
        &[],
        &aliases,
    ));
    assert!(
        !base_receiver_type_allows(&prepared, None, "other.write", &[], &aliases),
        "normalization must not broaden ownership to another receiver"
    );
}

#[test]
fn perl_arrow_call_uses_typed_receiver_and_package_evidence_exactly() {
    let rule = rule_from_yaml(
        r#"
id: perl.test.typed_arrow
enabled: true
language: perl
trust: service
tag: queue-input
packages: ["Example::Client"]
imports: ["Example::Client"]
match:
  kind: call
  callee:
    name: receive
constraints:
  - receiver_type_in: ["Example::Client"]
  - max_args: 1
description: Typed Perl arrow-call fixture.
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let call = CallFact {
        callee: "client->receive".to_string(),
        receiver: Some("client".to_string()),
        args: vec![CallArg {
            passing_mode: Default::default(),
            span: span(),
            name: None,
            value_text: "5".to_string(),
            place: None,
            source_names: Vec::new(),
        }],
        receiver_types: vec!["Example::Client".to_string()],
        span: span(),
        call_kind: CallKind::Method,
        origin: CallFactOrigin::RealCall,
    };
    let aliases = std::collections::HashMap::new();
    let receiver_types = call.receiver_types.clone();
    let matched = prepared
        .call_target_matches(&call, &receiver_types, &aliases)
        .expect("arrow call target matches terminal method");
    let packages = AHashSet::from(["Example::Client".to_string()]);
    assert!(prepared.call_context_allows(&call.callee, &receiver_types, &aliases, &packages,));
    assert!(constraints_pass(ConstraintEval {
        rule_id: &rule.id,
        callee: &matched,
        receiver: call.receiver.as_deref(),
        args: &call.args,
        receiver_types: &receiver_types,
        span: call.span,
        call_origin: Some(call.origin),
        constraints: &rule.constraints.0,
        constraint_regexes: &prepared.constraint_regexes,
        receiver_call_count: None,
        assignment_texts: None,
        ast_arg_values: None,
        mode: ConstraintMode::Inventory,
        taint_view: None,
        enclosing_decorators: None,
        enclosing_modifiers: None,
        alias_chains: None,
        runtime_types: None,
        lifecycle_transitions: None,
        structural_context: None,
    }));
}

#[test]
fn enclosing_decorator_not_in_uses_only_exact_enclosing_decorator_facts() {
    let constraints = [ConstraintKind::EnclosingDecoratorNotIn {
        enclosing_decorator_not_in: vec!["Profile".to_string(), "TestOnly".to_string()],
    }];
    let regexes = compile_constraint_regexes("test.decorator_not_in", &constraints)
        .expect("non-regex decorator constraint compiles");
    let evaluate = |decorators: Option<&[String]>| {
        constraints_pass(ConstraintEval {
            rule_id: "test.decorator_not_in",
            callee: "execute",
            receiver: None,
            args: &[],
            receiver_types: &[],
            span: span(),
            call_origin: Some(CallFactOrigin::RealCall),
            constraints: &constraints,
            constraint_regexes: &regexes,
            receiver_call_count: None,
            assignment_texts: None,
            ast_arg_values: None,
            mode: ConstraintMode::Strict,
            taint_view: None,
            enclosing_decorators: decorators,
            enclosing_modifiers: None,
            alias_chains: None,
            runtime_types: None,
            lifecycle_transitions: None,
            structural_context: None,
        })
    };
    let production = vec!["RequestMapping".to_string()];
    let excluded = vec!["RequestMapping".to_string(), "Profile".to_string()];
    let empty = Vec::<String>::new();

    assert!(evaluate(Some(&production)));
    assert!(evaluate(Some(&empty)));
    assert!(!evaluate(Some(&excluded)));
    assert!(
        !evaluate(None),
        "missing compiler decorator context must fail closed"
    );
}

#[test]
fn text_prefilter_requires_package_and_context_anchors() {
    let hibernate = rule_from_yaml(
        r#"
id: java.hibernate.session_get
enabled: true
language: java
trust: database
tag: db-input
packages: ["org.hibernate"]
match:
  kind: call
  callee:
    attribute: [Session, get]
description: Hibernate Session.get.
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&hibernate).expect("rule prepares");
    assert!(
        prepared.syntax_target_possible_in_mode(
            "class App { Object get(Session s) { return s.get(id); } }",
            ConstraintMode::Inventory,
            CallTextPrefilter::Parenthesized,
        ),
        "the pre-decode gate must retain a real syntax target even when only imports can later prove its package"
    );
    assert!(
        !prepared.syntax_target_possible_in_mode(
            "class App { Object find(Session s) { return s.find(id); } }",
            ConstraintMode::Inventory,
            CallTextPrefilter::Parenthesized,
        ),
        "the pre-decode gate should reject files that cannot contain the structured target"
    );
    assert!(
        !prepared.text_possible_in("class App { Object get(Session s) { return s.get(id); } }", None),
        "package-gated rules should not force parsing files with only receiver/tail text"
    );
    assert!(
        prepared.text_possible_in(
            "import org.hibernate.*; class App { Object get(Session s) { return s.get(id); } }",
            None
        ),
        "package text plus structured target text should remain parseable"
    );

    let main_args = rule_from_yaml(
        r#"
id: java.source.main_args
enabled: true
language: java
trust: local
tag: cli-input
match:
  kind: param
  target:
    in_method: [main]
    param_index_in: [0]
    param_type_in: [String]
    param_count_in: [1]
constraints:
  - enclosing_modifier_in: [static]
description: Java main args.
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&main_args).expect("rule prepares");
    assert!(!prepared.text_possible_in("void mainForTest(String args) {}", None));
    assert!(prepared.text_possible_in("public static void main(String[] args) {}", None));
    assert!(
        prepared.text_possible_in("public static void main(String[] commandLine) {}", None),
        "the prefilter must follow the Java entry-point signature, not a conventional parameter name"
    );
}

#[test]
fn semantic_decorator_config_does_not_become_a_raw_literal_anchor() {
    let rule = rule_from_yaml(
        r#"
id: python.test.decorator_config
enabled: true
language: python
trust: remote
tag: queue-input
match:
  kind: call
  callee: { name: sink }
constraints:
  - enclosing_decorator_in: [job.bind=true]
description: Exact compiler decorator config test.
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    assert!(
        prepared.syntax_target_possible_in_mode(
            "@job(bind=True)\ndef task(value):\n    return sink(value)\n",
            ConstraintMode::Inventory,
            CallTextPrefilter::Parenthesized,
        ),
        "language-specific literal spelling must not drop an exact semantic decorator candidate"
    );
    assert!(
        !prepared.syntax_target_possible_in_mode(
            "def task(value):\n    return sink(value)\n",
            ConstraintMode::Inventory,
            CallTextPrefilter::Parenthesized,
        ),
        "the callable decorator spelling remains a conservative raw anchor"
    );
}

#[test]
fn two_part_attribute_prefilter_never_uses_identifier_case_as_type_evidence() {
    let rule = rule_from_yaml(
        r#"
id: java.test.lowercase_receiver_type
enabled: true
language: java
tag: test
severity: info
match:
  kind: call
  callee:
    attribute: [lowercase_type, send]
description: Lowercase user-defined types remain valid compiler identities.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");

    assert!(prepared.syntax_target_possible_in_mode(
        "class App { void run(Transport transport) { transport.send(value); } }",
        ConstraintMode::Inventory,
        CallTextPrefilter::Parenthesized,
    ));
    assert!(!prepared.syntax_target_possible_in_mode(
        "class App { void run(Transport transport) { transport.receive(value); } }",
        ConstraintMode::Inventory,
        CallTextPrefilter::Parenthesized,
    ));
}

#[test]
fn package_gated_regex_accepts_semantic_receiver_type_context() {
    let rule = rule_from_yaml(
        r#"
id: kotlin.sqli.connection_createstatement_execute
enabled: true
language: kotlin
tag: sql-injection
severity: high
packages: [java.sql]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.createStatement\\(\\)\\.executeQuery$"
description: JDBC chained execute query.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let mut aliases = std::collections::HashMap::new();
    aliases.insert(
        "Connection".to_string(),
        AliasTarget::Type {
            type_name: "java.sql.Connection".to_string(),
        },
    );

    assert!(
        prepared.call_context_allows(
            "conn.createStatement().executeQuery",
            &["Connection".to_string()],
            &aliases,
            &AHashSet::new(),
        ),
        "receiver-type facts expand through imports before package matching"
    );
    let file_packages = AHashSet::from_iter(["java.sql".to_string()]);
    assert!(
        !prepared.call_context_allows(
            "conn.createStatement().executeQuery",
            &[],
            &std::collections::HashMap::new(),
            &file_packages,
        ),
        "sink rules need call-site receiver or alias evidence; file imports alone are too broad"
    );
    let direct_rule = rule_from_yaml(
        r#"
id: python.test.gql_execute
enabled: true
language: python
tag: command-injection
severity: high
packages: [gql]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.execute$"
description: gql execute.
"#,
        crate::rule::RuleKind::Sink,
    );
    let direct_prepared = PreparedRule::new(&direct_rule).expect("direct package rule prepares");
    assert!(
        direct_prepared.call_context_allows(
            "gql.execute",
            &[],
            &std::collections::HashMap::new(),
            &AHashSet::new(),
        ),
        "direct package-qualified calls must satisfy receiver-agnostic package gates"
    );
    let source_rule = rule_from_yaml(
        r#"
id: python.source.request_args_get
enabled: true
language: python
trust: remote
packages: [flask]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.args\\.get$"
description: Flask request args source.
"#,
        crate::rule::RuleKind::Source,
    );
    let source_prepared = PreparedRule::new(&source_rule).expect("source rule prepares");
    let source_file_packages = AHashSet::from_iter(["flask".to_string()]);
    assert!(
        source_prepared.call_context_allows(
            "req.args.get",
            &[],
            &std::collections::HashMap::new(),
            &source_file_packages,
        ),
        "source rules may use file-level package evidence for dynamic request receiver extraction"
    );
    let exact_source_rule = rule_from_yaml(
        r#"
id: typescript.source.readline_sync_question
enabled: true
language: typescript
trust: local
packages: [readline-sync]
analysis_semantics:
  allow_file_package_evidence: false
match:
  kind: call
  callee:
    name: question
description: readline-sync question.
"#,
        crate::rule::RuleKind::Source,
    );
    let exact_source_prepared = PreparedRule::new(&exact_source_rule).expect("exact source rule prepares");
    let source_file_packages = AHashSet::from_iter(["readline-sync".to_string()]);
    let alias_map = std::collections::HashMap::from_iter([(
        "rlsync".to_string(),
        AliasTarget::Namespace {
            module: "readline-sync".to_string(),
        },
    )]);
    assert!(
        exact_source_prepared.call_context_allows("rlsync.question", &[], &alias_map, &source_file_packages,),
        "an exact namespace-import binding must satisfy the source package gate"
    );
    assert!(
        !exact_source_prepared
            .call_context_allows("survey.question", &[], &alias_map, &source_file_packages,),
        "file package presence must not qualify an unrelated same-named source method"
    );
    let receiver_taint_rule = rule_from_yaml(
        r#"
id: javascript.test.uploaded_file_mv
enabled: true
language: javascript
tag: file-upload
severity: high
packages: [express-fileupload]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.mv$"
constraints:
  - arg_tainted:
      index: 0
  - receiver_tainted: true
description: Uploaded file move.
"#,
        crate::rule::RuleKind::Sink,
    );
    let receiver_taint_prepared =
        PreparedRule::new(&receiver_taint_rule).expect("receiver-taint package rule prepares");
    let upload_packages = AHashSet::from_iter(["express-fileupload".to_string()]);
    assert!(
        receiver_taint_prepared.call_context_allows(
            "uploaded.mv",
            &[],
            &std::collections::HashMap::new(),
            &upload_packages,
        ),
        "a receiver-taint constraint supplies endpoint dataflow identity for a package-gated receiver-agnostic call"
    );
    let lifecycle_rule = rule_from_yaml(
        r#"
id: go.race.mutex_unlock
enabled: true
language: go
tag: race
packages: [sync]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.Unlock$"
description: Lifecycle audit-pair transition.
"#,
        crate::rule::RuleKind::Sink,
    );
    let lifecycle_prepared = PreparedRule::new(&lifecycle_rule).expect("lifecycle rule prepares");
    let lifecycle_file_packages = AHashSet::from_iter(["sync".to_string()]);
    assert!(
        lifecycle_prepared.call_context_allows(
            "mu.Unlock",
            &[],
            &std::collections::HashMap::new(),
            &lifecycle_file_packages,
        ),
        "lifecycle audit-pair rules may use file-level package evidence for transition sites"
    );
    assert!(
        !prepared.call_context_allows(
            "client.createStatement().executeQuery",
            &[],
            &std::collections::HashMap::new(),
            &AHashSet::new(),
        ),
        "without import, alias, or receiver-type evidence, package-gated regexes fail closed"
    );
}

#[test]
fn anchored_receiver_regexes_keep_terminal_call_keys_and_text_anchors() {
    let rule = rule_from_yaml(
        r#"
id: python.test.gql_execute
enabled: true
language: python
tag: command-injection
severity: high
packages: [gql]
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.execute$"
description: gql execute.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let source = r#"
import gql

def handler(payload):
    return gql.execute(payload)
"#;

    assert_eq!(
        regex_literal_anchor_tokens("^[A-Za-z_$][A-Za-z0-9_$]*\\.execute$"),
        vec!["execute".to_string()],
        "regex character classes must not become impossible text anchors"
    );
    assert!(
        regex_literal_anchor_tokens("^CC_MD5(_Init|_Update|_Final)?$").is_empty(),
        "optional regex suffixes must not become mandatory text anchors"
    );
    assert!(
        regex_literal_anchor_tokens(r"^(ElementTree|ET)\.XML$").is_empty(),
        "alternative regex branches must not become mandatory text anchors"
    );
    assert_eq!(
        regex_required_hir_anchor_tokens(r"^(ElementTree|ET)\.XML$"),
        vec!["XML".to_string()],
        "HIR must retain a literal required after every alternative branch"
    );
    assert_eq!(
        regex_required_hir_anchor_tokens(
            r"(^|\.)set(NString|Bytes|BigDecimal|Date|Time|Timestamp|Double|Float|Short|Byte|Null)$"
        ),
        vec![
            "BigDecimal".to_string(),
            "Byte".to_string(),
            "Bytes".to_string(),
            "Date".to_string(),
            "Double".to_string(),
            "Float".to_string(),
            "NString".to_string(),
            "Null".to_string(),
            "Short".to_string(),
            "Time".to_string(),
            "Timestamp".to_string(),
        ],
        "HIR alternation anchors must include every viable long branch token without API-specific code"
    );
    assert!(
        regex_required_hir_anchor_tokens(r"^(?:safe|[A-Z]+)$").is_empty(),
        "an alternative branch without a required literal must disable the prefilter"
    );
    assert!(
        regex_terminal_call_key("^(list|binary)_to_atom$").is_none(),
        "prefix alternatives must not be keyed by a non-candidate suffix"
    );
    assert!(
        regex_terminal_call_key("^_?is_safe_url$").is_none(),
        "optional leading underscores must not be keyed without the underscore"
    );
    assert!(
        regex_terminal_call_key("(?i)^none$").is_none(),
        "case-insensitive targets must stay wildcarded in a case-sensitive candidate map"
    );
    assert_eq!(
        regex_terminal_call_key(r"^[A-Za-z_$][A-Za-z0-9_$]*\.\$queryRawUnsafe$"),
        Some("queryRawUnsafe".to_string()),
        "regex-derived call keys must use the same sigil-stripping as call candidates"
    );
    assert_eq!(
        regex_terminal_call_keys(
            r"^[A-Za-z_$][A-Za-z0-9_$]*\.(originalname|originalFilename|name|filename)$|^[A-Za-z_$][A-Za-z0-9_$]*\.file\.originalname$"
        ),
        vec![
            "filename".to_string(),
            "name".to_string(),
            "originalFilename".to_string(),
            "originalname".to_string(),
        ],
        "terminal alternatives must all remain reachable through the candidate index"
    );
    assert_eq!(
        regex_terminal_call_key(r"^(?:mysql|postgres)\.execute$"),
        Some("execute".to_string()),
        "receiver alternatives may still use one exact boundary-separated terminal key"
    );
    assert_eq!(
        regex_terminal_call_key(r"(^|\.)execute$"),
        Some("execute".to_string()),
        "start-or-member-boundary regexes must retain their exact terminal key"
    );
    assert_eq!(
        regex_prefix_literal_anchor_token("^ResponseEntity(?:<.*>)?$").as_deref(),
        Some("ResponseEntity"),
        "anchored constructor regexes should contribute their required prefix to text prefiltering"
    );
    assert_eq!(
        regex_required_literal_anchor_tokens(r"::|__\$\{"),
        vec!["::".to_string(), "__${".to_string()],
        "literal return regex alternatives should contribute safe exact text anchors"
    );
    let file_packages = AHashSet::from_iter(["gql".to_string()]);
    assert!(
        prepared.text_possible_in(source, Some(&file_packages)),
        "text prefilter must keep source files that contain the terminal call"
    );
    assert_eq!(
        prepared_regex_call_keys(&prepared),
        vec!["execute".to_string()],
        "call-rule index should key anchored receiver regexes by the terminal method"
    );
    let alias_map = std::collections::HashMap::new();
    let keys = call_candidate_keys("gql.execute", &alias_map);
    assert!(
        keys.iter().any(|key| key == "execute"),
        "call candidate keys should include the terminal method: {keys:?}"
    );
    assert_eq!(
        callee_or_alias_matches(
            "gql.execute",
            &[],
            prepared.name,
            prepared.attribute,
            prepared.regex.as_ref(),
            &alias_map,
        )
        .as_deref(),
        Some("gql.execute"),
        "callee matcher should evaluate anchored regexes against the emitted callee"
    );
    assert!(
        prepared.call_context_allows("gql.execute", &[], &alias_map, &AHashSet::new()),
        "direct package-qualified calls must satisfy package gates without file imports"
    );
}

#[test]
fn keyed_read_candidates_are_a_lossless_projection_of_rule_targets() {
    let keyed_regex_rule = rule_from_yaml(
        r#"
id: java.test.static_none
enabled: true
language: java
tag: test
severity: high
imports: [example.security.Mode]
match:
  kind: read
  target:
    regex: '^[A-Za-z_$][A-Za-z0-9_$]*\.NONE$'
    receiver_type_in: [example.security.Mode]
description: Exact typed static read fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let attribute_rule = rule_from_yaml(
        r#"
id: java.test.static_unsafe
enabled: true
language: java
tag: test
severity: high
match:
  kind: read
  target:
    attribute: [Mode, UNSAFE]
description: Exact attribute read fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let wildcard_rule = rule_from_yaml(
        r#"
id: java.test.alternative
enabled: true
language: java
tag: test
severity: high
match:
  kind: read
  target:
    regex: '^(NONE|UNSAFE)$'
description: Every exact regex terminal remains keyed.
"#,
        crate::rule::RuleKind::Sink,
    );
    let keyed_regex = PreparedRule::new(&keyed_regex_rule).expect("regex rule prepares");
    let attribute = PreparedRule::new(&attribute_rule).expect("attribute rule prepares");
    let wildcard = PreparedRule::new(&wildcard_rule).expect("wildcard rule prepares");
    let refs = vec![&keyed_regex, &attribute, &wildcard];
    let batch = PreparedRuleBatch::new(&refs, empty_rulepack_typing());
    let aliases = std::collections::HashMap::from([(
        "Alias".to_string(),
        AliasTarget::Type {
            type_name: "Mode".to_string(),
        },
    )]);

    let mut none_candidates = Vec::new();
    push_read_candidate_rules(&mut none_candidates, &batch, "Alias.NONE", &aliases);
    assert!(none_candidates
        .iter()
        .any(|candidate| candidate.rule.id == keyed_regex.rule.id));
    assert!(none_candidates
        .iter()
        .any(|candidate| candidate.rule.id == wildcard.rule.id));

    let mut unsafe_candidates = Vec::new();
    push_read_candidate_rules(&mut unsafe_candidates, &batch, "Mode.UNSAFE", &aliases);
    assert!(unsafe_candidates
        .iter()
        .any(|candidate| candidate.rule.id == attribute.rule.id));
    assert!(unsafe_candidates
        .iter()
        .any(|candidate| candidate.rule.id == wildcard.rule.id));

    let mut unrelated_candidates = Vec::new();
    push_read_candidate_rules(&mut unrelated_candidates, &batch, "Mode.SAFE", &aliases);
    assert!(unrelated_candidates
        .iter()
        .all(|candidate| candidate.rule.id != wildcard.rule.id));
    assert!(unrelated_candidates
        .iter()
        .all(|candidate| candidate.rule.id != keyed_regex.rule.id));
    assert!(
        unrelated_candidates
            .iter()
            .any(|candidate| candidate.rule.id == attribute.rule.id),
        "owner-key over-approximation is intentional; the canonical attribute matcher still rejects Mode.SAFE"
    );
}

#[test]
fn compact_package_planning_evidence_matches_materialized_marker_semantics() {
    let rule = rule_from_yaml(
        r#"
id: neutral.test.package_planning
enabled: true
language: neutral
tag: test
severity: high
packages: [example.framework]
match:
  kind: call
  callee:
    attribute: [example.framework, execute]
description: Exact package-planning fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&rule).expect("package rule prepares");
    let signal = "example.framework".to_string();

    for (direct, component, manifest, is_template) in [
        (true, false, false, false),
        (false, true, false, false),
        (false, false, true, false),
        (false, false, true, true),
        (false, false, false, false),
    ] {
        let mut direct_file_packages = AHashSet::new();
        let mut component_packages = AHashSet::new();
        let mut manifest_packages = AHashSet::new();
        let mut materialized = AHashSet::new();
        if direct {
            direct_file_packages.insert(signal.clone());
            materialized.insert(signal.clone());
        }
        if component {
            component_packages.insert(signal.clone());
            materialized.insert(component_import_package_marker(&signal));
        }
        if manifest {
            manifest_packages.insert(signal.clone());
            materialized.insert(if is_template {
                template_manifest_package_marker(&signal)
            } else {
                manifest_package_marker(&signal)
            });
        }
        let compact = FilePackagePlanningEvidence {
            direct_file_packages,
            component_packages: Arc::new(WorkspaceImportPackageContext {
                packages: component_packages,
                fingerprint: 1,
            }),
            manifest_packages: manifest.then_some(crate::deps::WorkspaceDependencyPackages {
                fingerprint: 1,
                packages: Arc::new(manifest_packages),
            }),
            is_template,
        };
        assert_eq!(
            prepared.package_evidence_allows_text_anchor_skip(&materialized),
            prepared.package_evidence_allows_text_anchor_skip_in_planning(&compact),
            "compact planning evidence diverged for direct={direct} component={component} manifest={manifest} template={is_template}"
        );
        assert_eq!(
            prepared.call_context_allows(
                "client.execute",
                &[],
                &std::collections::HashMap::new(),
                &materialized,
            ),
            prepared.call_context_allows(
                "client.execute",
                &[],
                &std::collections::HashMap::new(),
                &compact,
            ),
            "compact endpoint evidence diverged for direct={direct} component={component} manifest={manifest} template={is_template}"
        );
    }

    let mut local = AHashSet::new();
    local.insert(local_import_package_signal_marker(&signal));
    local.insert(local_import_package_marker("client", &signal));
    let compact = FilePackagePlanningEvidence {
        direct_file_packages: local.clone(),
        component_packages: Arc::new(WorkspaceImportPackageContext::default()),
        manifest_packages: None,
        is_template: false,
    };
    assert_eq!(
        prepared.package_evidence_allows_text_anchor_skip(&local),
        prepared.package_evidence_allows_text_anchor_skip_in_planning(&compact),
        "local relative-import package markers must retain their exact planning semantics"
    );
    assert_eq!(
        prepared.call_context_allows("client.execute", &[], &std::collections::HashMap::new(), &local,),
        prepared.call_context_allows("client.execute", &[], &std::collections::HashMap::new(), &compact,),
        "local relative-import endpoint ownership must retain exact semantics"
    );

    let constrained_overlay_rule = rule_from_yaml(
        r#"
id: neutral.test.package_overlay_negative
enabled: true
language: neutral
tag: test
severity: high
packages: [example.framework]
match:
  kind: read
  target: {name: input}
description: Bare source names cannot borrow workspace package ownership.
"#,
        crate::rule::RuleKind::Source,
    );
    let constrained_overlay = PreparedRule::new(&constrained_overlay_rule).expect("overlay rule prepares");
    let component = AHashSet::from_iter([signal.clone()]);
    let manifest = AHashSet::from_iter([signal.clone()]);
    let compact = FilePackagePlanningEvidence {
        direct_file_packages: AHashSet::new(),
        component_packages: Arc::new(WorkspaceImportPackageContext {
            packages: component,
            fingerprint: 2,
        }),
        manifest_packages: Some(crate::deps::WorkspaceDependencyPackages {
            fingerprint: 2,
            packages: Arc::new(manifest),
        }),
        is_template: false,
    };
    let materialized = AHashSet::from_iter([
        component_import_package_marker(&signal),
        manifest_package_marker(&signal),
    ]);
    assert_eq!(
        constrained_overlay.package_evidence_allows_text_anchor_skip(&materialized),
        constrained_overlay.package_evidence_allows_text_anchor_skip_in_planning(&compact)
    );
    assert!(
        !constrained_overlay.package_evidence_allows_text_anchor_skip_in_planning(&compact),
        "a rule overlay that lacks typed/compiler ownership must not gain manifest or component evidence"
    );
}

#[test]
fn read_receiver_staging_preserves_direct_ancestry_and_derived_alias_verdicts() {
    let target_typed_rule = rule_from_yaml(
        r#"
id: neutral.test.typed_read
enabled: true
language: neutral
tag: test
severity: high
match:
  kind: read
  target:
    name: payload
    receiver_type_in: [TrustedBase]
description: Neutral typed read fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let constraint_typed_rule = rule_from_yaml(
        r#"
id: neutral.test.constrained_read
enabled: true
language: neutral
tag: test
severity: high
match:
  kind: read
  target: {name: payload}
constraints:
- receiver_type_in: [TrustedBase]
description: Neutral constrained read fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let negative_typed_rule = rule_from_yaml(
        r#"
id: neutral.test.blocked_read
enabled: true
language: neutral
tag: test
severity: high
match:
  kind: read
  target: {name: payload}
constraints:
- receiver_type_not_in: [BlockedBase]
description: Neutral negative receiver fixture.
"#,
        crate::rule::RuleKind::Sink,
    );
    let target_typed = PreparedRule::new(&target_typed_rule).expect("target rule prepares");
    let constraint_typed = PreparedRule::new(&constraint_typed_rule).expect("constraint rule prepares");
    let negative_typed = PreparedRule::new(&negative_typed_rule).expect("negative rule prepares");

    let ancestry = AHashMap::from([("Child".to_string(), vec!["TrustedBase".to_string()])]);
    let direct_with_ancestry = expanded_receiver_types(&["Child".to_string()], &ancestry);
    assert!(!read_receiver_derivation_needed(
        &target_typed,
        &direct_with_ancestry
    ));
    assert!(!read_receiver_derivation_needed(
        &constraint_typed,
        &direct_with_ancestry
    ));
    assert!(read_receiver_constraints_allow(
        &constraint_typed,
        &direct_with_ancestry
    ));

    assert!(read_receiver_derivation_needed(&target_typed, &[]));
    assert!(read_receiver_derivation_needed(&constraint_typed, &[]));
    assert!(
        read_receiver_derivation_needed(&negative_typed, &[]),
        "negative receiver constraints must derive because a later alias can reverse the verdict"
    );

    let aliases = vec![TypeAliasBinding {
        name: "client".to_string(),
        type_name: "TrustedBase".to_string(),
    }];
    let mut derived_types = Vec::new();
    append_derived_receiver_types_for_match_base(&mut derived_types, &aliases, "client.payload");
    assert_eq!(derived_types, vec!["TrustedBase".to_string()]);
    assert!(base_receiver_type_allows(
        &target_typed,
        None,
        "client.payload",
        &derived_types,
        &aliases,
    ));
    assert!(read_receiver_constraints_allow(&constraint_typed, &derived_types));

    let blocked_aliases = vec![TypeAliasBinding {
        name: "client".to_string(),
        type_name: "BlockedBase".to_string(),
    }];
    let mut blocked_types = Vec::new();
    append_derived_receiver_types_for_match_base(&mut blocked_types, &blocked_aliases, "client.payload");
    assert!(!read_receiver_constraints_allow(&negative_typed, &blocked_types));
}

#[test]
fn symbolic_operator_calls_keep_their_exact_candidate_identity() {
    let alias_map = std::collections::HashMap::new();
    assert_eq!(call_candidate_keys("`", &alias_map), vec!["`".to_string()]);
    assert!(callee_matches("`", Some("`"), None, None));

    // Identifier sigils remain representation details when a real name
    // follows; this is what distinguishes them from symbolic operators.
    assert_eq!(call_candidate_keys("$exec", &alias_map), vec!["exec".to_string()]);
}

#[test]
fn complete_callee_name_matches_before_terminal_name_fallback() {
    assert!(callee_matches("pool.query", Some("pool.query"), None, None));
    assert!(callee_matches("pool.query", Some("query"), None, None));
    assert!(!callee_matches("other.query", Some("pool.query"), None, None));
}

#[test]
fn compound_attribute_components_match_canonical_compiler_identities() {
    for (callee, attribute) in [
        ("CryptoJS.DES.encrypt", vec!["CryptoJS.DES", "encrypt"]),
        ("ERB::Util.html_escape", vec!["ERB::Util", "html_escape"]),
        ("Crypt::DES->new", vec!["Crypt::DES", "new"]),
        ("BCrypt::Password.==", vec!["BCrypt::Password", "=="]),
    ] {
        let attribute = attribute.into_iter().map(str::to_string).collect();
        assert!(
            callee_matches(callee, None, Some(&attribute), None),
            "{callee} did not match {attribute:?}"
        );
    }
}

#[test]
fn sigiled_rule_attribute_matches_structural_call_identity() {
    let attribute = vec![":zip".to_string(), "extract".to_string()];
    assert!(callee_matches(":zip.extract", None, Some(&attribute), None));
}

#[test]
fn text_prefilter_uses_short_attribute_and_regex_terminal_anchors() {
    let short_attr_rule = rule_from_yaml(
        r#"
id: java.test.response_ok
enabled: true
language: java
tag: xss
severity: high
packages: [org.springframework.http]
match:
  kind: call
  callee:
    attribute: [ResponseEntity, ok]
description: ResponseEntity ok.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&short_attr_rule).expect("rule prepares");
    let file_package = AHashSet::from_iter(["org.springframework.http".to_string()]);
    assert!(
        !prepared.text_possible_in("class A { void f() { run(value); } }", Some(&file_package)),
        "exact file package evidence alone must not make a short-attribute rule parse every file"
    );
    assert!(
        prepared.text_possible_in(
            "class A { void f(String value) { ResponseEntity.ok(value); } }",
            Some(&file_package),
        ),
        "short method attributes should keep files containing the actual call"
    );
    assert!(
        prepared.text_possible_in(
            "class A { void f(String value) { ResponseEntity::ok(value); } }",
            Some(&file_package),
        ),
        "short method attributes should keep static separator call forms"
    );

    let regex_rule = rule_from_yaml(
        r#"
id: java.test.jdbc_query
enabled: true
language: java
tag: sql-injection
severity: high
packages: [org.springframework.jdbc]
match:
  kind: call
  callee:
    regex: "(^|\\.)(JdbcTemplate|[jJ][dD][bB][cC][tT]emplate)\\.query$"
description: JDBC query.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&regex_rule).expect("rule prepares");
    let file_package = AHashSet::from_iter(["org.springframework.jdbc".to_string()]);
    assert!(
        !prepared.text_possible_in("class A { void f() { execute(value); } }", Some(&file_package)),
        "terminal regex keys should keep package-gated regex rules from parsing unrelated files"
    );
    assert!(
        prepared.text_possible_in(
            "class A { void f(JdbcTemplate jdbcTemplate) { jdbcTemplate.query(sql); } }",
            Some(&file_package),
        ),
        "terminal regex keys should keep real candidate call files"
    );

    let search_rule = rule_from_yaml(
        r#"
id: java.test.ldap_search
enabled: true
language: java
tag: ldap-injection
severity: high
packages: [javax.naming.directory]
match:
  kind: call
  callee:
    name: search
description: LDAP search.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&search_rule).expect("rule prepares");
    let file_package = AHashSet::from_iter(["javax.naming.directory".to_string()]);
    assert!(
        !prepared.text_possible_in_mode(
            "class ElasticsearchHandler { String name = \"Elasticsearch\"; }",
            Some(&file_package),
            ConstraintMode::Inventory,
            CallTextPrefilter::Parenthesized,
        ),
        "plain words containing a call name must not satisfy broad call-name prefiltering"
    );
    assert!(
        prepared.text_possible_in_mode(
            "class App { void f(DirContext ctx, String q) { ctx.search(\"ou=users\", q, null); } }",
            Some(&file_package),
            ConstraintMode::Inventory,
            CallTextPrefilter::Parenthesized,
        ),
        "real call syntax should satisfy broad call-name prefiltering"
    );
    assert!(
        call_text_anchor_possible_in(
            "x = cond ? STDIN.gets : \"safe\"",
            "gets",
            CallTextPrefilter::ParenthesizedOrCommand,
        ),
        "Ruby command/no-arg call syntax without parentheses must remain prefilter-possible"
    );
    assert!(
        call_text_anchor_possible_in(
            "include $tainted;",
            "include",
            CallTextPrefilter::ParenthesizedOrCommand,
        ),
        "PHP include/require constructs normalized as calls must remain prefilter-possible"
    );
    assert!(
        !call_text_anchor_possible_in(
            "class ElasticsearchHandler {}",
            "search",
            CallTextPrefilter::Parenthesized,
        ),
        "Java call prefilter should still reject identifiers embedded in larger words"
    );

    let raw_html_rule = rule_from_yaml(
        r#"
id: java.test.raw_html_return
enabled: true
language: java
tag: xss
severity: high
match:
  kind: return
  target:
    regex: '(?is)<\s*(?:!doctype|html|body|script|div|span|p|a|img|svg|iframe|h[1-6]|ul|ol|li|table|form|input|textarea|button|br|hr)\b|&lt;'
description: Raw HTML return.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = PreparedRule::new(&raw_html_rule).expect("rule prepares");
    let refs = vec![&prepared];
    let batch = PreparedRuleBatch::new(&refs, empty_rulepack_typing());
    let unrelated_source =
        "/** <div> appears only in documentation. */ class Box<T> { List<String> values() { return values; } }";
    let unrelated_return_start = unrelated_source.find("return values").expect("return fixture");
    let unrelated = CompilerSyntaxHeader {
        returns: vec![bonsai_lang_api::CompilerReturnHeader {
            span: Span::new(
                FileId::new(0),
                unrelated_return_start as u64,
                (unrelated_return_start + "return values;".len()) as u64,
            ),
            value_text: Some("values".to_string()),
            value_name: Some("values".to_string()),
            assignment_value_spans: Vec::new(),
        }],
        ..Default::default()
    };
    let (filtered, deferred, needs_constructor_resolution) = batch.filtered_rule_refs_for_syntax_header(
        refs.clone(),
        &unrelated,
        unrelated_source,
        None,
        "java",
        true,
    );
    assert!(
        filtered.is_empty(),
        "Java generics must not force a return-rule body open"
    );
    assert!(!deferred);
    assert!(!needs_constructor_resolution);

    let matching = CompilerSyntaxHeader {
        returns: vec![bonsai_lang_api::CompilerReturnHeader {
            span: span(),
            value_text: Some("\"<div>\" + n".to_string()),
            value_name: None,
            assignment_value_spans: Vec::new(),
        }],
        ..Default::default()
    };
    let (filtered, _, _) = batch.filtered_rule_refs_for_syntax_header(
        refs.clone(),
        &matching,
        "class App { String f(String n) { return \"<div>\" + n; } }",
        None,
        "java",
        true,
    );
    assert_eq!(
        filtered.len(),
        1,
        "real adapter return targets must survive planning"
    );

    let assigned_source = "class App { String f(String n) { String page = \"<div>\" + n; return page; } }";
    let assignment_value_start = assigned_source.find("\"<div>\" + n").unwrap();
    let return_start = assigned_source.find("return page").unwrap();
    let assigned = CompilerSyntaxHeader {
        returns: vec![bonsai_lang_api::CompilerReturnHeader {
            span: Span::new(
                FileId::new(0),
                return_start as u64,
                (return_start + "return page;".len()) as u64,
            ),
            value_text: Some("page".to_string()),
            value_name: Some("page".to_string()),
            assignment_value_spans: vec![Span::new(
                FileId::new(0),
                assignment_value_start as u64,
                (assignment_value_start + "\"<div>\" + n".len()) as u64,
            )],
        }],
        ..Default::default()
    };
    let (filtered, _, _) = batch.filtered_rule_refs_for_syntax_header(
        vec![&prepared],
        &assigned,
        assigned_source,
        None,
        "java",
        true,
    );
    assert_eq!(
        filtered.len(),
        1,
        "compiler assignment RHS spans must keep a variable-return rule schedulable"
    );

    let normalized = CompilerSyntaxHeader {
        returns: vec![bonsai_lang_api::CompilerReturnHeader {
            span: span(),
            value_text: Some("<div>".to_string()),
            value_name: None,
            assignment_value_spans: Vec::new(),
        }],
        ..Default::default()
    };
    let (filtered, _, _) = batch.filtered_rule_refs_for_syntax_header(
        refs,
        &normalized,
        "class Synthetic { String f(); }",
        None,
        "java",
        true,
    );
    assert_eq!(
        filtered.len(),
        1,
        "adapter-normalized return values must survive even when their spelling is not raw source text"
    );
}

#[test]
fn batch_text_anchor_scan_preserves_individual_rule_predicates() {
    let search_rule = rule_from_yaml(
        r#"
id: java.test.batch_search
enabled: true
language: java
tag: ldap-injection
severity: high
packages: [javax.naming.directory]
match:
  kind: call
  callee:
    name: search
description: LDAP search.
"#,
        crate::rule::RuleKind::Sink,
    );
    let execute_rule = rule_from_yaml(
        r#"
id: java.test.batch_execute
enabled: true
language: java
tag: sql-injection
severity: high
packages: [java.sql]
match:
  kind: call
  callee:
    attribute: [Statement, execute]
description: JDBC execute.
"#,
        crate::rule::RuleKind::Sink,
    );
    let prepared = [
        PreparedRule::new(&search_rule).expect("search rule prepares"),
        PreparedRule::new(&execute_rule).expect("execute rule prepares"),
    ];
    let refs = prepared.iter().collect::<Vec<_>>();
    let batch = PreparedRuleBatch::new(&refs, empty_rulepack_typing());
    let packages = AHashSet::from_iter(["javax.naming.directory".to_string(), "java.sql".to_string()]);

    for source in [
        "class ElasticsearchHandler { String name = \"Elasticsearch\"; }",
        "class App { void f(DirContext ctx, String q) { ctx.search(\"ou=users\", q, null); } }",
        "class App { void f(Statement stmt, String q) { stmt.execute(q); } }",
        "class App { void f() { executeLater(); } }",
    ] {
        let syntax = CallTextPrefilter::Parenthesized;
        let matches = batch.text_anchor_matches(source, syntax, ConstraintMode::Inventory);
        for rule in &prepared {
            let expected =
                rule.text_possible_in_mode(source, Some(&packages), ConstraintMode::Inventory, syntax);
            let actual = rule.text_possible_in_mode_with_anchor_lookup(
                source,
                Some(&packages),
                ConstraintMode::Inventory,
                syntax,
                &|anchor| batch.text_anchor_present(source, &matches, anchor),
                &|anchor| batch.call_text_anchor_present(source, &matches, anchor, syntax),
            );
            assert_eq!(
                actual, expected,
                "batch anchor evidence diverged for {} in {source}",
                rule.rule.id
            );
        }
    }
}

#[test]
fn base_name_not_in_blocks_module_decoder_bases() {
    let rule = rule_from_yaml(
        r#"
id: python.passthrough.bytes_decode_receiver
enabled: true
language: python
tag: passthrough-decode
match:
  kind: call
  callee:
    regex: "^[A-Za-z_$][A-Za-z0-9_$\\.]*\\.decode$"
    base_name_not_in: [jsonpickle]
description: Receiver decode passthrough.
"#,
        crate::rule::RuleKind::Sanitizer,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");

    assert!(prepared.base_name_allows("raw.decode"));
    assert!(prepared.base_name_allows("self.raw.decode"));
    assert!(!prepared.base_name_allows("jsonpickle.decode"));
}

#[test]
fn return_flow_reads_strip_call_callee_but_keep_argument_reads() {
    let mut reads = Vec::new();
    collect_flow_read_sites(
        &[FlowEvent::Return {
            span: span(),
            value_kind: None,
            value_text: Some("params(input)".to_string()),
            value_name: None,
            value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(vec!["input".to_string()]),
        }],
        &[],
        &[],
        &mut reads,
    );
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].1, vec!["input"]);

    reads.clear();
    collect_flow_read_sites(
        &[FlowEvent::Return {
            span: span(),
            value_kind: None,
            value_text: Some(r#"render(params["name"])"#.to_string()),
            value_name: None,
            value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(vec![
                "params".to_string(),
                "name".to_string(),
            ]),
        }],
        &[],
        &[],
        &mut reads,
    );
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].1, vec!["params", "name"]);
}

#[test]
fn method_chain_components_require_their_own_compiler_call_fact() {
    let attr = vec!["Command".to_string(), "new".to_string()];

    assert!(!callee_matches(
        r#"Command::new("sh").arg("-c").output"#,
        None,
        Some(&attr),
        None
    ));
    assert!(!callee_matches(
        r#"std/process/Command::new("sh").arg("-c").output"#,
        None,
        Some(&attr),
        None
    ));
    assert!(callee_matches("Command::new", None, Some(&attr), None));
    assert!(
        !callee_matches(r#"callbacks.add(Command::new("sh"))"#, None, Some(&attr), None),
        "callback-passing expressions must not match the inner method-chain head"
    );
    assert!(
        !callee_matches(
            r#"callbacks.add(std/process/Command::new("sh"))"#,
            None,
            Some(&attr),
            None
        ),
        "import-path chain heads inside callback arguments must not match"
    );
}

#[test]
fn same_receiver_call_count_constraint_requires_repeated_receiver() {
    let constraint = vec![ConstraintKind::SameReceiverCallCountAtLeast {
        same_receiver_call_count_at_least: 2,
    }];
    let constraint_regexes =
        compile_constraint_regexes("test.same_receiver", &constraint).expect("non-regex constraints compile");

    assert!(constraints_pass(ConstraintEval {
        rule_id: "test.same_receiver",
        callee: "balance.lock",
        receiver: None,
        args: &[],
        receiver_types: &[],
        span: Span::new(FileId::new(0), 0, 0),
        call_origin: None,
        constraints: &constraint,
        constraint_regexes: &constraint_regexes,
        receiver_call_count: Some(2),
        assignment_texts: None,
        ast_arg_values: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        enclosing_modifiers: None,
        alias_chains: None,
        runtime_types: None,
        lifecycle_transitions: None,
        structural_context: None,
    }));
    assert!(!constraints_pass(ConstraintEval {
        rule_id: "test.same_receiver",
        callee: "stdin.lock",
        receiver: None,
        args: &[],
        receiver_types: &[],
        span: Span::new(FileId::new(0), 0, 0),
        call_origin: None,
        constraints: &constraint,
        constraint_regexes: &constraint_regexes,
        receiver_call_count: Some(1),
        assignment_texts: None,
        ast_arg_values: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        enclosing_modifiers: None,
        alias_chains: None,
        runtime_types: None,
        lifecycle_transitions: None,
        structural_context: None,
    }));
    assert!(!constraints_pass(ConstraintEval {
        rule_id: "test.same_receiver",
        callee: "lock",
        receiver: None,
        args: &[],
        receiver_types: &[],
        span: Span::new(FileId::new(0), 0, 0),
        call_origin: None,
        constraints: &constraint,
        constraint_regexes: &constraint_regexes,
        receiver_call_count: None,
        assignment_texts: None,
        ast_arg_values: None,
        mode: ConstraintMode::Strict,
        taint_view: None,
        enclosing_decorators: None,
        enclosing_modifiers: None,
        alias_chains: None,
        runtime_types: None,
        lifecycle_transitions: None,
        structural_context: None,
    }));
}

#[test]
fn receiver_regex_constraint_uses_the_parsed_call_receiver() {
    let constraint = vec![ConstraintKind::ReceiverNotMatchesRegex {
        receiver_not_matches_regex: r#"putHeader\("content-type",\s*"text/plain"\)"#.to_string(),
    }];
    let constraint_regexes =
        compile_constraint_regexes("test.receiver_regex", &constraint).expect("valid receiver regex");
    let passes = |callee| {
        constraints_pass(ConstraintEval {
            rule_id: "test.receiver_regex",
            callee,
            receiver: None,
            args: &[],
            receiver_types: &[],
            span: Span::new(FileId::new(0), 0, 0),
            call_origin: None,
            constraints: &constraint,
            constraint_regexes: &constraint_regexes,
            receiver_call_count: None,
            assignment_texts: None,
            ast_arg_values: None,
            mode: ConstraintMode::Strict,
            taint_view: None,
            enclosing_decorators: None,
            enclosing_modifiers: None,
            alias_chains: None,
            runtime_types: None,
            lifecycle_transitions: None,
            structural_context: None,
        })
    };

    assert!(passes("response.end"));
    assert!(!passes(
        r#"req.response().putHeader("content-type", "text/plain").end"#
    ));
    assert!(
        !passes("end"),
        "receiver constraints must fail closed on a bare call"
    );
}

#[test]
fn receiver_regex_prefers_the_adapter_emitted_receiver_for_symbolic_calls() {
    let constraint = vec![ConstraintKind::ReceiverMatchesRegex {
        receiver_matches_regex: r"^std::cin$".to_string(),
    }];
    let constraint_regexes =
        compile_constraint_regexes("test.symbolic_receiver", &constraint).expect("valid receiver regex");
    let evaluate = |receiver| {
        constraints_pass(ConstraintEval {
            rule_id: "test.symbolic_receiver",
            callee: ">>",
            receiver,
            args: &[],
            receiver_types: &[],
            span: Span::new(FileId::new(0), 0, 0),
            call_origin: Some(CallFactOrigin::RealCall),
            constraints: &constraint,
            constraint_regexes: &constraint_regexes,
            receiver_call_count: None,
            assignment_texts: None,
            ast_arg_values: None,
            mode: ConstraintMode::Strict,
            taint_view: None,
            enclosing_decorators: None,
            enclosing_modifiers: None,
            alias_chains: None,
            runtime_types: None,
            lifecycle_transitions: None,
            structural_context: None,
        })
    };

    assert!(evaluate(Some("std::cin")));
    assert!(
        !evaluate(None),
        "a symbolic callee has no receiver text to guess; exact adapter evidence is required"
    );
    assert!(!evaluate(Some("application_stream")));
}

#[test]
fn prior_call_collection_uses_only_calls_guaranteed_on_the_hir_path() {
    let call = |start, end, name: &str, receiver: Option<&str>, args: Vec<CallArg>| FlowEvent::Call {
        span: Span::new(FileId::new(0), start, end),
        name: name.to_string(),
        receiver: receiver.map(str::to_string),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        args,
    };
    let header_args = || {
        vec![
            CallArg {
                span: Span::new(FileId::new(0), 2, 3),
                passing_mode: Default::default(),
                name: None,
                value_text: "\"Content-Type\"".to_string(),
                place: None,
                source_names: Vec::new(),
            },
            CallArg {
                span: Span::new(FileId::new(0), 4, 5),
                passing_mode: Default::default(),
                name: None,
                value_text: "\"application/octet-stream\"".to_string(),
                place: None,
                source_names: Vec::new(),
            },
        ]
    };
    let sink_span = Span::new(FileId::new(0), 20, 25);
    let straight_line = vec![
        call(1, 10, "self.set_header", Some("self"), header_args()),
        call(20, 25, "self.write", Some("self"), Vec::new()),
    ];
    let mut prior = Vec::new();
    collect_guaranteed_prior_calls(&straight_line, sink_span, &mut prior);
    assert_eq!(prior.len(), 1);
    assert_eq!(prior[0].name, "self.set_header");

    let branch_only = vec![
        FlowEvent::Branch {
            span: Span::new(FileId::new(0), 0, 15),
            condition: Some("flag".to_string()),
            then_events: vec![call(2, 10, "self.set_header", Some("self"), header_args())],
            else_events: Vec::new(),
        },
        call(20, 25, "self.write", Some("self"), Vec::new()),
    ];
    prior.clear();
    collect_guaranteed_prior_calls(&branch_only, sink_span, &mut prior);
    assert!(
        prior.is_empty(),
        "a header set on only one branch must not suppress a sink after the merge"
    );
}

#[test]
fn prior_call_static_arguments_use_language_decoded_values() {
    let call_span = Span::new(FileId::new(0), 10, 20);
    let argument = |index, value| bonsai_lang_api::CallArgumentValueFact {
        call_span,
        argument_index: index,
        argument_span: Span::new(FileId::new(0), 11 + index as u64, 12 + index as u64),
        direct_call_span: None,
        value_kind: None,
        inline_callback_params: Vec::new(),
        inline_callback_span: None,
        inline_callback_static_return: None,
        inline_callback_fields: Vec::new(),
        value_flow: Default::default(),
        static_value: value,
        exact_static_aggregate_fields: Vec::new(),
        exact_static_sequence_values: None,
    };
    let facts = vec![
        argument(
            0,
            Some(bonsai_lang_api::StaticScalarValue::String(
                "Content-Type".to_string(),
            )),
        ),
        argument(
            1,
            Some(bonsai_lang_api::StaticScalarValue::String(
                "application/octet-stream".to_string(),
            )),
        ),
    ];
    assert_eq!(
        static_string_call_arguments(&facts, call_span, 2).as_deref(),
        Some("Content-Type\u{1f}application/octet-stream")
    );

    let dynamic = vec![argument(0, None)];
    assert!(
        static_string_call_arguments(&dynamic, call_span, 1).is_none(),
        "a dynamic argument must not satisfy a static sanitizer guard"
    );
    let non_string = vec![argument(
        0,
        Some(bonsai_lang_api::StaticScalarValue::Boolean(true)),
    )];
    assert!(
        static_string_call_arguments(&non_string, call_span, 1).is_none(),
        "language-decoded non-string values must not be rendered and compared as strings"
    );
}

#[test]
fn invalid_constraint_regex_fails_closed() {
    let constraint = vec![ConstraintKind::AnyArgMatchesRegex {
        any_arg_matches_regex: "[".to_string(),
    }];
    assert!(
        compile_constraint_regexes("test.invalid_regex", &constraint).is_none(),
        "invalid constraint regexes must fail rule preparation instead of silently compiling to None"
    );
}

#[test]
fn prepared_rule_drops_rule_with_invalid_constraint_regex() {
    let rule = rule_from_yaml(
        r#"
id: python.sqli.invalid_constraint_regex
enabled: true
language: python
tag: sql-injection
severity: high
cwe: [CWE-89]
match:
  kind: call
  callee:
    name: execute
constraints:
  - any_arg_matches_regex: "["
match_examples:
  - name: example
    code: "def demo(cursor, sql): cursor.execute(sql)"
description: Invalid regex fixture.
"#,
        crate::rule::RuleKind::Sink,
    );

    assert!(
        PreparedRule::new(&rule).is_none(),
        "an invalid constraint regex should disable the full rule for this analysis run"
    );
}

#[test]
fn empty_inferred_type_alias_does_not_panic() {
    let mut aliases = std::collections::HashMap::new();
    aliases.insert(
        "client".to_string(),
        AliasTarget::Type {
            type_name: String::new(),
        },
    );
    let attr = vec!["HttpClient".to_string(), "execute".to_string()];

    assert_eq!(
        callee_or_alias_matches("client.execute", &[], None, Some(&attr), None, &aliases),
        None
    );
}

#[test]
fn receiver_method_call_counts_group_by_receiver_and_method() {
    let calls = vec![
        test_call_fact("balance.lock", CallFactOrigin::RealCall),
        test_call_fact("balance.lock", CallFactOrigin::RealCall),
        test_call_fact("stdin.lock", CallFactOrigin::RealCall),
        test_call_fact("balance.clone", CallFactOrigin::RealCall),
        test_call_fact("balance.lock", CallFactOrigin::AssignmentSourceCall),
    ];
    let counts = receiver_method_call_counts(&calls);

    assert_eq!(
        counts
            .get(&receiver_method_key("balance.lock").expect("balance key"))
            .copied(),
        Some(2)
    );
    assert_eq!(
        counts
            .get(&receiver_method_key("stdin.lock").expect("stdin key"))
            .copied(),
        Some(1)
    );
    assert_eq!(
        counts
            .get(&receiver_method_key("balance.clone").expect("clone key"))
            .copied(),
        Some(1)
    );
}

#[test]
fn overlapping_arg_taint_uses_compiler_carriers_not_rendered_text() {
    let tainted = bonsai_taint::TaintedArgAtCall {
        index: 0,
        value_text: "untrusted rendering".to_string(),
        place: Some("name".to_string()),
        source_names: vec!["name".to_string()],
    };
    let literal = CallArg {
        span: span(),
        passing_mode: bonsai_lang_api::ArgumentPassingMode::Value,
        name: None,
        value_text: r#""SELECT * FROM users WHERE name = ?""#.to_string(),
        place: None,
        source_names: Vec::new(),
    };
    assert!(
        !arg_matches_tainted_value(&literal, &tainted),
        "words in rendered literal text are not compiler value carriers"
    );

    let compound = CallArg {
        value_text: "fmt.Sprintf(query, name)".to_string(),
        source_names: vec!["query".to_string(), "name".to_string()],
        ..literal
    };
    assert!(arg_matches_tainted_value(&compound, &tainted));

    let rendered_only = bonsai_taint::TaintedArgAtCall {
        value_text: "name".to_string(),
        place: None,
        source_names: Vec::new(),
        ..tainted
    };
    assert!(
        !arg_matches_tainted_value(&compound, &rendered_only),
        "taint attribution must not recover identities from render-only text"
    );
}

fn test_call_fact(callee: &str, origin: CallFactOrigin) -> CallFact {
    CallFact {
        callee: callee.to_string(),
        receiver: None,
        span: span(),
        args: Vec::new(),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        origin,
    }
}

// --- P3: integer-literal parsing + arg_lt/arg_le/arg_gt/arg_ge tests ---

#[test]
fn parse_int_literal_decimal_forms() {
    assert_eq!(super::parse_int_literal("1024"), Some(1024));
    assert_eq!(super::parse_int_literal("-5"), Some(-5));
    assert_eq!(super::parse_int_literal("+42"), Some(42));
    assert_eq!(super::parse_int_literal("1_000_000"), Some(1_000_000));
    assert_eq!(super::parse_int_literal(" 256 "), Some(256));
}

#[test]
fn parse_int_literal_hex_oct_bin() {
    assert_eq!(super::parse_int_literal("0xFF"), Some(255));
    assert_eq!(super::parse_int_literal("0Xff"), Some(255));
    assert_eq!(super::parse_int_literal("0o777"), Some(0o777));
    assert_eq!(super::parse_int_literal("0b1010"), Some(0b1010));
    assert_eq!(super::parse_int_literal("0B1111_0000"), Some(0b1111_0000));
}

#[test]
fn parse_int_literal_rejects_non_literals() {
    // Variables and expressions must never speculate to a value.
    assert_eq!(super::parse_int_literal("size"), None);
    assert_eq!(super::parse_int_literal("2048 + 0"), None);
    assert_eq!(super::parse_int_literal("Math.pow(2, 10)"), None);
    assert_eq!(super::parse_int_literal(""), None);
    assert_eq!(super::parse_int_literal("null"), None);
}

#[test]
fn arg_int_compare_threshold_semantics() {
    let args = vec![CallArg {
        passing_mode: Default::default(),
        span: span(),
        name: None,
        place: None,
        source_names: Vec::new(),
        value_text: "1024".to_string(),
    }];
    // arg_lt: 2048 should pass (1024 < 2048).
    assert!(super::arg_int_compare(&args, 0, |literal| literal < 2048));
    // arg_lt: 1024 fails on equality.
    assert!(!super::arg_int_compare(&args, 0, |literal| literal < 1024));
    // arg_le: 1024 passes on equality.
    assert!(super::arg_int_compare(&args, 0, |literal| literal <= 1024));
    // arg_gt: 512 passes (1024 > 512).
    assert!(super::arg_int_compare(&args, 0, |literal| literal > 512));
    // arg_ge: 1024 passes on equality.
    assert!(super::arg_int_compare(&args, 0, |literal| literal >= 1024));
}

#[test]
fn arg_int_compare_unknown_arg_fails_conservatively() {
    let args = vec![CallArg {
        passing_mode: Default::default(),
        span: span(),
        name: None,
        place: None,
        source_names: Vec::new(),
        value_text: "user_size".to_string(),
    }];
    // Variable arg → no literal → constraint fails. This is the
    // conservative choice: don't speculate.
    assert!(!super::arg_int_compare(&args, 0, |_| true));
}

#[test]
fn arg_int_compare_out_of_bounds_fails() {
    let args = vec![CallArg {
        passing_mode: Default::default(),
        span: span(),
        name: None,
        place: None,
        source_names: Vec::new(),
        value_text: "1024".to_string(),
    }];
    // index 1 is out of bounds — constraint fails.
    assert!(!super::arg_int_compare(&args, 1, |_| true));
}

#[test]
fn write_fact_uses_structured_assignment_operands() {
    let events = vec![FlowEvent::Assign {
        span: span(),
        target: "decoder.Strict".to_string(),
        source_name: Some("false".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["false".to_string()],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
    }];

    let writes = super::collect_writes(&events);
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].target, "decoder.Strict");
    assert_eq!(writes[0].argument.value_text, "false");
    assert_eq!(writes[0].argument.source_names, ["false"]);
    assert_eq!(writes[0].ast_values, ["false"]);
}

#[test]
fn branch_condition_ast_values_have_no_hidden_cap() {
    let events = (0..8_192)
        .map(|index| FlowEvent::Branch {
            span: span(),
            condition: Some(format!("allowed[{index}]")),
            then_events: Vec::new(),
            else_events: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut values = Vec::new();
    super::collect_branch_condition_values(&events, &mut values);
    assert_eq!(values.len(), events.len());
    assert_eq!(values.last().map(String::as_str), Some("allowed[8191]"));
}

#[test]
fn collect_calls_uses_ast_call_event_for_yielded_expression() {
    // `yield exec(cmd)` / C# `yield return Sink(x)` lowers both the value
    // event and its parsed call. The matcher must consume that real call
    // rather than re-parsing `Yield::value_text`.
    let events = vec![
        FlowEvent::Call {
            span: span(),
            name: "exec".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                passing_mode: Default::default(),
                span: span(),
                name: None,
                value_text: "cmd".to_string(),
                place: Some("cmd".to_string()),
                source_names: vec!["cmd".to_string()],
            }],
        },
        FlowEvent::Yield {
            span: span(),
            value_text: Some("exec(cmd)".to_string()),
            value_flow: bonsai_lang_api::ExpressionFlow::from_source_names(vec!["cmd".to_string()]),
        },
    ];
    let calls = collect_calls(&events);
    assert_eq!(
        calls.len(),
        1,
        "a sink in the yielded value must become a CallFact"
    );
    assert_eq!(calls[0].callee, "exec");
    assert_eq!(calls[0].origin, CallFactOrigin::RealCall);
    assert_eq!(
        calls[0]
            .args
            .iter()
            .map(|arg| arg.value_text.as_str())
            .collect::<Vec<_>>(),
        vec!["cmd"]
    );
}

#[test]
fn collect_calls_ignores_non_call_yield_value() {
    // A bare `yield x` carries no call; do not synthesize a CallFact.
    let events = vec![FlowEvent::Yield {
        span: span(),
        value_text: Some("x".to_string()),
        value_flow: bonsai_lang_api::ExpressionFlow::from_place("x"),
    }];
    assert!(collect_calls(&events).is_empty());
}

// audit re-apply: H10 RED-before/GREEN-after (matcher portion): before adding

#[test]
fn receiver_root_name_strips_kotlin_safe_call_sigil() {
    // H10: safe-call receivers (`stmt?.executeQuery`) leave `call_receiver_text`
    // returning `stmt?`; the root must still resolve to `stmt`.
    assert_eq!(receiver_root_name("stmt?"), Some("stmt".to_string()));
    assert_eq!(receiver_root_name("obj?.field"), Some("obj".to_string()));
}

#[test]
fn safe_call_receiver_inherits_type_alias() {
    // H10 integration: `stmt?.executeQuery(query)` must adopt the alias
    // type of `stmt` so the matcher's [Statement, executeQuery] rule fires.
    let events = vec![FlowEvent::Call {
        name: "stmt?.executeQuery".to_string(),
        receiver: Some("stmt?".to_string()),
        args: Vec::new(),
        receiver_types: Vec::new(),
        span: span(),
        call_kind: CallKind::Method,
    }];
    let mut calls = collect_calls(&events);
    enrich_call_fact_receiver_types(
        &mut calls,
        &[TypeAliasBinding {
            name: "stmt".to_string(),
            type_name: "java.sql.Statement".to_string(),
        }],
    );
    let real = calls
        .iter()
        .find(|c| c.callee == "stmt?.executeQuery")
        .expect("real call fact present");
    assert_eq!(
        real.receiver_types,
        vec!["java.sql.Statement".to_string()],
        "safe-call receiver must inherit the alias type of its root binding"
    );
}

#[test]
fn sigil_receiver_inherits_normalized_factory_type_alias() {
    let events = vec![FlowEvent::Call {
        name: "$client.method".to_string(),
        receiver: Some("$client".to_string()),
        args: Vec::new(),
        receiver_types: Vec::new(),
        span: span(),
        call_kind: CallKind::Method,
    }];
    let mut calls = collect_calls(&events);
    enrich_call_fact_receiver_types(
        &mut calls,
        &[TypeAliasBinding {
            name: "$client".to_string(),
            type_name: "Client".to_string(),
        }],
    );

    assert_eq!(calls[0].receiver_types, vec!["Client".to_string()]);
}

#[test]
fn binding_origin_uses_import_runtime_and_lexical_compiler_facts() {
    let evaluate = |source: &str, extras: &[(&str, &str)], callee: &str, origin, required: &[&str]| {
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        let file = ws.vfs().write("entry.js", source);
        for (path, text) in extras {
            ws.vfs().write(path, *text);
        }
        let index = ws.db().decl_index(file).expect("JavaScript declaration index");
        let (caller, call) = index
            .defs
            .iter()
            .find_map(|decl| {
                collect_calls(&decl.flow_events)
                    .into_iter()
                    .find(|call| call.callee == callee)
                    .map(|call| (decl, call))
            })
            .unwrap_or_else(|| panic!("missing {callee} call in {source}"));
        let alias_map = file_alias_map(&ws, file);
        let compiler_imports = ws.db().import_index(file);
        let required = required
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        let global = ws.db().global_index();
        let context = WorkspaceCallIdentityContext {
            ws: &ws,
            global: global.as_ref(),
            caller,
        };
        call_binding_origin_is_valid(
            origin,
            false,
            caller,
            Some(&index.defs),
            Some(&context),
            &call,
            &alias_map,
            &required,
            compiler_imports.as_deref(),
        )
    };

    assert!(evaluate(
        "import { getQuery } from 'h3';\nfunction entry(event) { return getQuery(event); }\n",
        &[],
        "getQuery",
        RuleBindingOrigin::Imported,
        &[],
    ));
    assert!(evaluate(
        "const request = require('request');\nfunction entry(options) { return request(options); }\n",
        &[("sibling.js", "function request(options) { return options; }\n",)],
        "request",
        RuleBindingOrigin::Imported,
        &["request"],
    ));
    assert!(evaluate(
        "function entry(value) { const provider = require('example-provider'); return provider.create(value); }\n",
        &[],
        "provider.create",
        RuleBindingOrigin::Imported,
        &["example-provider"],
    ));
    assert!(!evaluate(
        "function entry(value, local) { let provider = require('example-provider'); provider = local; return provider.create(value); }\n",
        &[],
        "provider.create",
        RuleBindingOrigin::Imported,
        &["example-provider"],
    ));
    assert!(!evaluate(
        "function entry(event) { return getQuery(event); }\n",
        &[],
        "getQuery",
        RuleBindingOrigin::Imported,
        &[],
    ));
    assert!(evaluate(
        "function entry() { return localStorage.getItem('key'); }\n",
        &[],
        "localStorage.getItem",
        RuleBindingOrigin::RuntimeGlobal,
        &[],
    ));
    assert!(!evaluate(
        "function entry() { const localStorage = store(); return localStorage.getItem('key'); }\n",
        &[],
        "localStorage.getItem",
        RuleBindingOrigin::RuntimeGlobal,
        &[],
    ));
    assert!(!evaluate(
        "const localStorage = store();\nfunction entry() { return localStorage.getItem('key'); }\n",
        &[],
        "localStorage.getItem",
        RuleBindingOrigin::RuntimeGlobal,
        &[],
    ));
    assert!(evaluate(
        "function entry(value) { return PlatformValue.decode(value); }\n",
        &[],
        "PlatformValue.decode",
        RuleBindingOrigin::RuntimeGlobal,
        &[],
    ));
    assert!(!evaluate(
        "class PlatformValue { static decode(value) { return value; } }\nfunction entry(value) { return PlatformValue.decode(value); }\n",
        &[],
        "PlatformValue.decode",
        RuleBindingOrigin::RuntimeGlobal,
        &[],
    ));
    assert!(!evaluate(
        "import { getQuery } from 'h3';\nfunction entry(getQuery, event) { return getQuery(event); }\n",
        &[],
        "getQuery",
        RuleBindingOrigin::Imported,
        &[],
    ));
    assert!(!evaluate(
        "import { getQuery } from './local.js';\nfunction entry(event) { return getQuery(event); }\n",
        &[("local.js", "export function getQuery(value) { return value; }\n")],
        "getQuery",
        RuleBindingOrigin::Imported,
        &[],
    ));

    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "wildcard.scala",
        "import play.api.mvc._\nobject Routes { def entry(value: String) = Action(value) }\n",
    );
    let index = ws.db().decl_index(file).expect("Scala declaration index");
    let (caller, call) = index
        .defs
        .iter()
        .find_map(|decl| {
            collect_calls(&decl.flow_events)
                .into_iter()
                .find(|call| call.callee == "Action")
                .map(|call| (decl, call))
        })
        .expect("wildcard-imported Scala call");
    let alias_map = file_alias_map(&ws, file);
    let compiler_imports = ws.db().import_index(file);
    let global = ws.db().global_index();
    let context = WorkspaceCallIdentityContext {
        ws: &ws,
        global: global.as_ref(),
        caller,
    };
    assert!(call_binding_origin_is_valid(
        RuleBindingOrigin::Imported,
        true,
        caller,
        Some(&index.defs),
        Some(&context),
        &call,
        &alias_map,
        &["play.api.mvc".to_string()],
        compiler_imports.as_deref(),
    ));

    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "entry.scala",
        "import play.api.mvc.Action\nobject Action { def apply(value: String): String = value }\nobject Routes { def entry(value: String) = Action(value) }\n",
    );
    let index = ws.db().decl_index(file).expect("Scala declaration index");
    let (caller, call) = index
        .defs
        .iter()
        .find_map(|decl| {
            collect_calls(&decl.flow_events)
                .into_iter()
                .find(|call| call.callee == "Action")
                .map(|call| (decl, call))
        })
        .expect("local Scala object call");
    let alias_map = file_alias_map(&ws, file);
    let compiler_imports = ws.db().import_index(file);
    let global = ws.db().global_index();
    let context = WorkspaceCallIdentityContext {
        ws: &ws,
        global: global.as_ref(),
        caller,
    };
    assert!(
        !call_binding_origin_is_valid(
            RuleBindingOrigin::Imported,
            true,
            caller,
            Some(&index.defs),
            Some(&context),
            &call,
            &alias_map,
            &["play.api.mvc".to_string()],
            compiler_imports.as_deref(),
        ),
        "a local bare-callable type/object must shadow an imported provider binding"
    );
}

#[test]
fn qualified_owner_accepts_only_rule_declared_alias_of_an_exact_import() {
    let call = CallFact {
        callee: "provider.Client.run".to_string(),
        receiver: Some("provider.Client".to_string()),
        span: span(),
        args: Vec::new(),
        receiver_types: Vec::new(),
        call_kind: CallKind::Method,
        origin: CallFactOrigin::RealCall,
    };
    let import = bonsai_lang_api::ImportSpec {
        span: span(),
        module: "provider/header.hpp".to_string(),
        alias: None,
        is_wildcard: false,
        original_name: None,
        scope: bonsai_lang_api::ImportScope::Module,
    };
    assert!(qualified_call_owner_matches_import(
        &call,
        &import,
        &["provider/header.hpp".to_string(), "provider".to_string()],
    ));
    assert!(
        !qualified_call_owner_matches_import(&call, &import, &["provider/header.hpp".to_string()],),
        "an include filename must not imply an undeclared namespace alias"
    );
}

#[test]
fn qualified_import_binding_uses_exact_owner_and_rejects_local_namespace_shadow() {
    let evaluate = |path: &str, source: &str, callee_suffix: &str, required_import: &str| {
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        let file = ws.vfs().write(path, source);
        let index = ws.db().decl_index(file).expect("declaration index");
        let (caller, call) = index
            .defs
            .iter()
            .find_map(|decl| {
                collect_calls(&decl.flow_events)
                    .into_iter()
                    .find(|call| call.callee.ends_with(callee_suffix))
                    .map(|call| (decl, call))
            })
            .unwrap_or_else(|| panic!("missing qualified call ending in {callee_suffix}: {index:#?}"));
        let alias_map = file_alias_map(&ws, file);
        let compiler_imports = ws.db().import_index(file);
        let global = ws.db().global_index();
        let context = WorkspaceCallIdentityContext {
            ws: &ws,
            global: global.as_ref(),
            caller,
        };
        call_binding_origin_is_valid(
            RuleBindingOrigin::Imported,
            true,
            caller,
            Some(&index.defs),
            Some(&context),
            &call,
            &alias_map,
            &[required_import.to_string()],
            compiler_imports.as_deref(),
        )
    };

    assert!(
        evaluate(
            "entry.pl",
            "use Vendor::Queue::Client;\nsub entry { return Vendor::Queue::Client->new(); }\n",
            "Vendor::Queue::Client->new",
            "Vendor::Queue::Client",
        ),
        "an unaliased qualified import owns its exact qualified call receiver"
    );
    assert!(!evaluate(
        "entry.rb",
        "require \"vendor-package\"\nmodule Vendor\n  class Client; end\nend\ndef entry\n  Vendor::Client.new\nend\n",
        "Vendor::Client.new",
        "vendor-package",
    ), "a same-root local namespace declaration must shadow external package evidence");
    assert!(!evaluate(
        "entry.pl",
        "use Vendor::Queue::Client;\npackage Vendor::Queue::Client;\nsub new { return bless {}, __PACKAGE__; }\npackage main;\nsub entry { return Vendor::Queue::Client->new(); }\n",
        "Vendor::Queue::Client->new",
        "Vendor::Queue::Client",
    ), "a locally declared qualified Perl package must shadow the same imported external package identity");
}

#[test]
fn inventory_dedup_prefers_callable_attribution_for_one_concrete_site() {
    let site = Span::new(FileId::new(3), 40, 55);
    let make = |enclosing_fn: &str, match_text: &str| RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: "dart.ipc.process_result".to_string(),
        language: "dart".to_string(),
        file: "auth_service.dart".to_string(),
        line: 15,
        column: 18,
        span: site,
        match_text: match_text.to_string(),
        enclosing_fn: Some(enclosing_fn.to_string()),
    };
    let mut matches = vec![
        make("__module__", "Process.runSync"),
        make("runAdminCommand", "Process.runSync"),
    ];

    dedup_inventory_matches(&mut matches);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].enclosing_fn.as_deref(), Some("runAdminCommand"));
}

#[test]
fn inventory_dedup_collapses_expression_wrapper_around_same_read_token() {
    let make = |span: Span| RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: "objc.source.nsprocessinfo_environment".to_string(),
        language: "objc".to_string(),
        file: "App.m".to_string(),
        line: 18,
        column: 27,
        span,
        match_text: "NSProcessInfo.processInfo.environment".to_string(),
        enclosing_fn: Some("handle_request".to_string()),
    };
    let exact_read = Span::new(FileId::new(3), 700, 711);
    let expression_wrapper = Span::new(FileId::new(3), 700, 750);
    let mut matches = vec![make(expression_wrapper), make(exact_read)];

    dedup_inventory_matches(&mut matches);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].span, exact_read);
}

#[test]
fn inventory_dedup_keeps_distinct_same_line_parameter_bindings() {
    let declaration = Span::new(FileId::new(4), 64, 77);
    let make = |text: &str| RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: "elixir.phoenix.liveview_handle_params".to_string(),
        language: "elixir".to_string(),
        file: "page_live.ex".to_string(),
        line: 4,
        // `kind: param` binds the declaration anchor; the bound parameter
        // text is the remaining compiler identity for each carrier.
        column: 7,
        span: declaration,
        match_text: text.to_string(),
        enclosing_fn: Some("handle_params".to_string()),
    };
    let mut matches = vec![make("params"), make("uri")];

    dedup_inventory_matches(&mut matches);

    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].match_text, "params");
    assert_eq!(matches[1].match_text, "uri");
}

#[test]
fn typed_read_name_matches_an_exact_terminal_member_only() {
    let typed = rule_from_yaml(
        r#"
id: test.typed_read
enabled: true
language: swift
match:
  kind: read
  target:
    name: text
    receiver_type_in: [TextInput]
description: typed member read
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&typed).expect("typed read prepares");
    assert_eq!(
        flow_read_rule_match(&prepared, &["field.text".to_string()]),
        Some("field.text".to_string())
    );
    assert_eq!(
        flow_read_rule_match(&prepared, &["field.title".to_string()]),
        None
    );

    let untyped = rule_from_yaml(
        r#"
id: test.untyped_read
enabled: true
language: swift
match:
  kind: read
  target:
    name: text
description: untyped bare read
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&untyped).expect("untyped read prepares");
    assert_eq!(
        flow_read_rule_match(&prepared, &["field.text".to_string()]),
        None,
        "an untyped bare name must never gain implicit member matching"
    );
}

#[test]
fn manifest_regex_prefix_detection_uses_structural_qualified_names() {
    assert!(regex_has_literal_qualified_prefix("^runtime:receive$"));
    assert!(regex_has_literal_qualified_prefix("^Runtime.Transport.receive$"));
    assert!(!regex_has_literal_qualified_prefix("^receive$"));
    assert!(!regex_has_literal_qualified_prefix(
        "^[A-Za-z_][A-Za-z0-9_]*\\.receive$"
    ));
}

#[test]
fn exact_static_rule_owner_rejects_a_same_named_workspace_type() {
    let rule = rule_from_yaml(
        r#"
id: swift.test.external-static-read
enabled: true
language: swift
trust: local
tag: local-input
packages: [ProviderKit]
match:
  kind: read
  target:
    regex: '^Provider\.shared\.(?:text|url)$'
description: Neutral provider-owned static read fixture.
"#,
        crate::rule::RuleKind::Source,
    );
    let prepared = PreparedRule::new(&rule).expect("rule prepares");
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws.vfs().write(
        "entry.swift",
        "import ProviderKit\nstruct Provider { static let shared = Provider() }\nfunc run() { consume(Provider.shared.text) }\n",
    );
    let index = ws.db().decl_index(file).expect("Swift declaration index");

    assert!(external_receiver_type_is_workspace_shadow_at(
        &prepared,
        &[],
        &index.defs,
        None,
        Some("Provider.shared.text"),
    ));
    assert!(!external_receiver_type_is_workspace_shadow_at(
        &prepared,
        &[],
        &[],
        None,
        Some("Provider.shared.text"),
    ));
    assert_eq!(
        exact_qualified_regex_root("^Provider\\.shared\\.text$"),
        Some("Provider")
    );
    assert_eq!(
        exact_qualified_regex_root("^[A-Za-z_][A-Za-z0-9_]*\\.text$"),
        None
    );
}

#[test]
fn prior_receiver_write_reaching_definition_fails_closed_at_control_merges() {
    let file = FileId::new(0);
    let write = |start, target: &str| FlowEvent::Assign {
        span: Span::new(file, start, start + 5),
        target: target.to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: Some(AssignValueKind::Literal),
    };
    let member = RuleTarget {
        name: Some("mode".to_string()),
        ..RuleTarget::default()
    };
    let target = Span::new(file, 100, 110);

    assert_eq!(
        reaching_prior_receiver_write(&[write(10, "worker.mode")], target, "worker", &member),
        ReachingPriorWrite::Known(Span::new(file, 10, 15))
    );
    assert_eq!(
        reaching_prior_receiver_write(
            &[
                write(10, "worker.mode"),
                FlowEvent::Branch {
                    span: Span::new(file, 20, 50),
                    condition: None,
                    then_events: vec![write(30, "worker.mode")],
                    else_events: Vec::new(),
                },
            ],
            target,
            "worker",
            &member,
        ),
        ReachingPriorWrite::Ambiguous,
        "a conditional overwrite must not inherit the earlier accepted state"
    );
    assert_eq!(
        reaching_prior_receiver_write(
            &[
                write(10, "worker.mode"),
                FlowEvent::Loop {
                    span: Span::new(file, 20, 50),
                    loop_kind: bonsai_lang_api::LoopKind::While,
                    body: vec![write(30, "worker.mode")],
                },
            ],
            target,
            "worker",
            &member,
        ),
        ReachingPriorWrite::Ambiguous,
        "zero versus one loop iterations produce an ambiguous reaching definition"
    );
    assert_eq!(
        reaching_prior_receiver_write(&[write(10, "peer.mode")], target, "worker", &member),
        ReachingPriorWrite::None,
        "same member spelling on a different compiler receiver must not collide"
    );
}

#[test]
fn prior_receiver_write_constraint_schema_accepts_exact_scalar_values() {
    let rule = rule_from_yaml(
        r#"
id: test.prior_receiver_write
enabled: true
language: neutral
match:
  kind: call
  callee: {name: execute}
constraints:
- receiver_type_in: [Executor]
- requires_prior_receiver_write:
    target: {name: mode}
    accepted_values:
    - {kind: string, value: strict}
description: neutral reaching-definition constraint
"#,
        crate::rule::RuleKind::Sink,
    );
    assert!(matches!(
        rule.constraints.0.as_slice(),
        [
            ConstraintKind::ReceiverTypeIn { .. },
            ConstraintKind::RequiresPriorReceiverWrite { .. }
        ]
    ));
}
