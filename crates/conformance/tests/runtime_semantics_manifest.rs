//! Completeness manifest for the compiler/runtime conformance gate.
//!
//! Behavioral tests remain the source of truth. This manifest prevents a
//! future refactor from deleting an entire semantic family while leaving a
//! superficially large test count. Every family names its executable gate
//! and distinctive assertions; missing files or renamed/removed tests fail
//! immediately and require an intentional manifest review.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

struct Gate {
    family: &'static str,
    files: &'static [&'static str],
    markers: &'static [&'static str],
}

const GATES: &[Gate] = &[
    Gate {
        family: "parser-recovery-diagnostics",
        files: &[
            "crates/conformance/tests/parser_error_conformance.rs",
            "crates/parser/src/tests.rs",
            "crates/lang_c/tests/conformance.rs",
            "crates/cli/tests/c_preprocessor_recovery.rs",
        ],
        markers: &[
            "every_language_reports_malformed_syntax_as_incomplete",
            "syntax_diagnostics_cover_nested_error_and_missing_nodes",
            "c_conditional_token_splice_remains_incomplete_without_configuration_facts",
            "c_complete_preprocessor_alternatives_are_not_flattened",
            "c_different_split_function_names_fail_closed",
            "c_recovery_preserves_a_large_prefix_of_clean_callables",
            "c_branch_free_preprocessor_recovery_keeps_security_analysis_complete",
        ],
    },
    Gate {
        family: "adapter-grammar-node-contract",
        files: &[
            "crates/lang_api/src/kit/mod.rs",
            "crates/conformance/src/lib.rs",
            "crates/conformance/tests/architecture_invariants.rs",
        ],
        markers: &[
            "declared_node_kinds",
            "declared_field_names",
            "validate_grammar_contract",
            "fn grammar_handler",
            "grammar_handler_for_path",
            "fn additional_grammar_node_kinds",
            "additional_grammar_node_kinds_for_path",
        ],
    },
    Gate {
        family: "deterministic-lowering-spans-serialization",
        files: &["crates/conformance/src/lib.rs"],
        markers: &[
            "declaration lowering is nondeterministic",
            "validate_all_serialized_spans",
            "DeclIndex serialization changed compiler facts",
        ],
    },
    Gate {
        family: "cross-fact-call-receiver-condition-integrity",
        files: &["crates/conformance/src/lib.rs"],
        markers: &[
            "validate_cross_fact_integrity",
            "call arguments are not in source order",
            "every conditional FlowEvent::Branch",
        ],
    },
    Gate {
        family: "straight-line-evaluation-and-return",
        files: &["crates/conformance/tests/runtime_evaluation_conformance.rs"],
        markers: &[
            "straight_line_calls_preserve_source_evaluation_order_in_every_language",
            "nested_calls_evaluate_arguments_before_outer_invocation_in_every_language",
            "function_return_terminates_control_before_later_calls",
            "abrupt_exception_or_panic_terminates_control_before_later_calls",
        ],
    },
    Gate {
        family: "typed-boolean-short-circuit-semantics",
        files: &["crates/conformance/tests/condition_expression_conformance.rs"],
        markers: &["every_language_lowers_boolean_evaluator_semantics_to_typed_ir"],
    },
    Gate {
        family: "mutually-exclusive-branches",
        files: &[
            "crates/conformance/tests/multi_arm_path_conformance.rs",
            "crates/taint/tests/compiler_semantic_regressions.rs",
        ],
        markers: &[
            "every_language_preserves_mutually_exclusive_multi_arm_paths",
            "mutually_exclusive_arms_never_share_taint_state",
        ],
    },
    Gate {
        family: "loop-phase-break-continue",
        files: &[
            "crates/conformance/tests/loop_control_conformance.rs",
            "crates/conformance/tests/loop_phase_conformance.rs",
            "crates/browse/tests/loop_phase_surfaces.rs",
            "crates/security/tests/security_pipeline_regressions.rs",
            "crates/taint/tests/compiler_semantic_regressions.rs",
        ],
        markers: &[
            "break_exits_the_body_and_reaches_code_after_the_loop",
            "continue_restarts_the_loop_and_skips_the_rest_of_the_body",
            "every_post_test_frontend_lowers_condition_body_and_runtime_order",
            "every_c_style_frontend_runs_update_after_continue_before_condition",
            "every_conditionless_frontend_has_no_implicit_false_exit",
            "public_syntax_inventories_include_condition_body_and_update_facts",
            "semantic_resolution_and_inspection_include_condition_body_and_update_calls",
            "loop_condition_and_update_calls_reach_security_taint_analysis",
            "c_style_loop_update_occurs_after_the_first_body_iteration",
        ],
    },
    Gate {
        family: "exceptions-catches-finally-defer",
        files: &[
            "crates/conformance/tests/multi_catch_path_conformance.rs",
            "crates/conformance/tests/cleanup_semantics_conformance.rs",
        ],
        markers: &[
            "every_applicable_language_preserves_multiple_catch_arms_as_alternatives",
            "finally_family_cleanup_runs_after_the_protected_body",
            "defer_cleanup_runs_at_scope_exit_not_at_declaration",
        ],
    },
    Gate {
        family: "positional-named-writeback-call-binding",
        files: &[
            "crates/conformance/tests/argument_passing_semantics.rs",
            "crates/taint/tests/language_matrix.rs",
        ],
        markers: &[
            "adapters_lower_writeback_syntax_to_one_language_neutral_fact",
            "sink_site_param_mapping_is_precise_for_every_language_with_multiple_params",
        ],
    },
    Gate {
        family: "closure-capture",
        files: &["crates/taint/tests/compiler_semantic_regressions.rs"],
        markers: &["captured_values_reach_calls_inside_first_class_closures"],
    },
    Gate {
        family: "callback-scope-and-provider-typing",
        files: &[
            "crates/lang_api/src/types.rs",
            "crates/security/tests/dart_callback_typing.rs",
            "crates/security/tests/matcher_batch.rs",
        ],
        markers: &[
            "compiler_syntax_header_retains_direct_callback_scope_identity",
            "run_functions_callback_types_the_exact_firebase_receiver_root",
            "parameter_signature_and_enclosing_base_suffix_are_exact_context_facts",
        ],
    },
    Gate {
        family: "module-behaviour-callback-ownership",
        files: &[
            "crates/lang_erlang/tests/conformance.rs",
            "crates/security/tests/erlang_source_boundaries.rs",
        ],
        markers: &[
            "module_behaviour_is_an_exact_owner_fact_for_callback_declarations",
            "gen_server_callbacks_require_exact_module_behaviour_ownership",
            "gen_server_messages_enter_the_idg",
        ],
    },
    Gate {
        family: "await-yield-suspension",
        files: &["crates/conformance/tests/async_runtime_conformance.rs"],
        markers: &[
            "grammar_owned_await_forms_emit_suspension_events",
            "grammar_owned_yield_forms_emit_transfer_events",
        ],
    },
    Gate {
        family: "aggregates-destructuring-field-sensitivity",
        files: &[
            "crates/conformance/tests/literal_value_contract.rs",
            "crates/taint/tests/semantic_container_fields.rs",
            "crates/taint/tests/receiver_field_writes_smoke.rs",
        ],
        markers: &[
            "every_adapter_distinguishes_literal_from_dynamic_argument",
            "python_constructor_property_read_keeps_receiver_fields_scoped",
            "dart_field_formal_constructor_populates",
        ],
    },
    Gate {
        family: "constructors-inheritance-dynamic-dispatch",
        files: &[
            "crates/taint/tests/super_dispatch.rs",
            "crates/taint/tests/receiver_field_writes_smoke.rs",
            "crates/conformance/tests/type_inference.rs",
        ],
        markers: &[
            "adapter_receiver_token_capabilities_match_language_syntax",
            "typescript_super_resolves_aliased_parent_method_across_files",
            "python_type_self_receiver_inherits_enclosing_class_type",
        ],
    },
    Gate {
        family: "modules-imports-cross-file-callgraph",
        files: &[
            "crates/taint/tests/language_matrix.rs",
            "crates/workspace/tests/cross_module.rs",
            "crates/workspace/tests/hell_chain.rs",
        ],
        markers: &[
            "interproc_propagates_mid_to_sink_for_every_language",
            "cross_module_defaults_are_semantically_uncapped",
            "assert_every_hop_is_captured",
        ],
    },
    Gate {
        family: "idg-fixed-point-projection-parity",
        files: &[
            "crates/taint/tests/value_flow_idg_parity.rs",
            "crates/taint/tests/value_flow_projection_parity.rs",
        ],
        markers: &["forward", "interprocedural_taint"],
    },
    Gate {
        family: "security-source-sink-arg-taint-join",
        files: &[
            "crates/security/tests/arg_tainted_constraint.rs",
            "crates/security/tests/security_pipeline_regressions.rs",
        ],
        markers: &[
            "arg_tainted_index_requires_taint_view_and_filters_literals",
            "run_taint_analysis",
        ],
    },
    Gate {
        family: "security-analysis-completeness-and-endpoint-attribution",
        files: &[
            "crates/security/src/analysis/finding_completeness_tests.rs",
            "crates/cli/tests/dynamic_native_security_regressions.rs",
            "crates/cli/tests/security_flow_capability_regressions.rs",
            "crates/cli/tests/per_lang_cli_matrix.rs",
        ],
        markers: &[
            "unattributed_security_endpoints_make_the_whole_report_incomplete",
            "taint analysis returned findings from an incomplete compiler snapshot",
            "taint regression fixture produced an incomplete compiler snapshot",
            "assert_security_analysis_complete",
        ],
    },
    Gate {
        family: "security-boundary-rulepack-completeness",
        files: &[
            "crates/security/tests/source_boundary_completeness.rs",
            "crates/security/tests/rulepack_conformance.rs",
        ],
        markers: &[
            "every_language_has_an_enabled_rule_for_every_canonical_source_boundary",
            "bundled_rulepack_contains_only_executable_rules",
            "enabled_rules_must_have_match_examples",
            "declared_rule_match_examples_fire",
        ],
    },
    Gate {
        family: "cache-snapshot-scheduling-scale",
        files: &["crates/conformance/tests/architecture_invariants.rs"],
        markers: &[
            "adapter_declaration_lowering_never_reparses_one_file_per_semantic_pass",
            "adapter_import_lowering_never_reparses_one_file_per_semantic_pass",
            "idg_backed_taint_queries_never_materialize_the_workspace_body_index",
            "resolved_callgraph_cache_is_single_flight_during_construction",
            "streaming_global_headers_have_no_batch_barriers_or_private_pool",
        ],
    },
    Gate {
        family: "adapter-single-tree-runtime-acquisition",
        files: &["crates/conformance/src/lib.rs"],
        markers: &[
            "CountingTreeProvider",
            "validate_single_tree_acquisition",
            "declaration lowering must acquire one exact Tree-sitter tree",
            "import lowering must acquire one exact Tree-sitter tree",
        ],
    },
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
        .to_path_buf()
}

#[test]
fn every_runtime_semantic_family_has_a_retained_executable_gate() {
    let mut families = BTreeSet::new();
    for gate in GATES {
        assert!(families.insert(gate.family), "duplicate family {}", gate.family);
        assert!(!gate.files.is_empty(), "{} has no test files", gate.family);
        assert!(
            !gate.markers.is_empty(),
            "{} has no behavioral markers",
            gate.family
        );
        let combined = gate
            .files
            .iter()
            .map(|relative| {
                fs::read_to_string(repo_root().join(relative))
                    .unwrap_or_else(|error| panic!("{}: read {relative}: {error}", gate.family))
            })
            .collect::<Vec<_>>()
            .join("\n");
        for marker in gate.markers {
            assert!(
                combined.contains(marker),
                "semantic family `{}` lost behavioral marker `{marker}`",
                gate.family
            );
        }
    }
    assert_eq!(
        families.len(),
        GATES.len(),
        "semantic family manifest contains duplicates"
    );
}
