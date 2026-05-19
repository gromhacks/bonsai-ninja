//! Meta-coverage contract for flow/taint command and language-semantic
//! regression tests.
//!
//! These checks do not replace the behavioral suites they reference.
//! They make the current audit goal concrete: if a future edit deletes
//! command, SDK, benchmark-gap, or rulepack-configurability coverage,
//! this suite fails even before the more expensive behavioral tests run.

use std::fs;
use std::path::PathBuf;

const SUPPORTED_LANGS: &[&str] = &[
    "c",
    "cpp",
    "csharp",
    "dart",
    "elixir",
    "erlang",
    "go",
    "java",
    "javascript",
    "kotlin",
    "lua",
    "objc",
    "perl",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "typescript",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("repo root")
        .to_path_buf()
}

fn read(path: &str) -> String {
    fs::read_to_string(repo_root().join(path)).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

fn assert_contains_all(label: &str, haystack: &str, needles: &[&str]) {
    let missing: Vec<_> = needles
        .iter()
        .copied()
        .filter(|needle| !haystack.contains(needle))
        .collect();
    assert!(
        missing.is_empty(),
        "{label} missing required coverage markers:\n{}",
        missing.join("\n")
    );
}

#[test]
fn all_language_matrices_name_every_supported_language() {
    let cli_matrix = read("crates/cli/tests/per_lang_cli_matrix.rs");
    let sdk_parity = read("crates/cli/tests/sdk_cli_parity.rs");
    let security_pipeline = read("crates/security/tests/security_pipeline_regressions.rs");
    let taint_applicability = read("crates/taint/tests/matrix/applicability.rs");

    for lang in SUPPORTED_LANGS {
        let quoted = format!("\"{lang}\"");
        assert!(
            cli_matrix.contains(&format!("{lang}_matrix")) || cli_matrix.contains(&quoted),
            "per-language CLI matrix is missing {lang}"
        );
        assert!(
            sdk_parity.contains(&quoted),
            "CLI/SDK parity matrix is missing {lang}"
        );
        assert!(
            security_pipeline.contains(&quoted),
            "security pipeline mega-flow matrix is missing {lang}"
        );
        assert!(
            taint_applicability.contains(&quoted),
            "taint applicability matrix is missing {lang}"
        );
    }
}

#[test]
fn flow_taint_cli_command_surfaces_have_per_language_behavioral_coverage() {
    let cli_matrix = read("crates/cli/tests/per_lang_cli_matrix.rs");
    assert_contains_all(
        "per-language CLI matrix",
        &cli_matrix,
        &[
            "micro_calls_include_verify_token_as_callee",
            "micro_args_shape",
            "micro_refs_verify_token",
            "micro_inspect_reaches_run_admin_command",
            "micro_trace_handler",
            "micro_dump_edges",
            "micro_dump_resolve_handler",
            "micro_dump_taint_from_handler",
            "micro_export_taint_graph",
            "micro_security_sources_semantic_inventory",
            "micro_security_sinks",
            "micro_security_sanitizers_semantic_inventory",
            "micro_security_source_analysis_semantic_chains",
            "micro_security_flows_min_findings",
            "micro_security_sarif_shape",
            "mega_flow_security_flows_produces_finding",
            "mega_flow_export_has_interproc_edges",
        ],
    );

    let paging = read("crates/cli/tests/paging.rs");
    assert_contains_all(
        "pagination matrix",
        &paging,
        &[
            "ALL_PAGED_COMMANDS",
            "\"calls\"",
            "\"args\"",
            "\"refs\"",
            "\"dump-edges\"",
            "\"inspect\"",
            "\"trace\"",
            "every_command_json_wraps_when_context_is_set",
            "every_command_page_2_resolves",
            "every_command_page_object_has_cursor_and_is_last",
        ],
    );

    let export_schema = read("crates/cli/tests/export_schema_drift.rs");
    assert_contains_all(
        "export schema drift guard",
        &export_schema,
        &[
            "every_lang_micro_export_funcid_refs_resolve",
            "taint_graph",
            "call_edges",
            "function_summaries",
            "flow_id_labels",
            "flow_graph",
        ],
    );
}

#[test]
fn sdk_parity_covers_all_flow_taint_commands_for_every_language() {
    let parity = read("crates/cli/tests/sdk_cli_parity.rs");
    assert_contains_all(
        "CLI/SDK parity tests",
        &parity,
        &[
            "security_analysis_cli_json_matches_sdk_for_every_language",
            "security_inventory_cli_json_matches_sdk_for_every_language",
            "browse_fact_commands_cli_json_match_sdk_for_every_language",
            "dump_and_trace_commands_cli_json_match_sdk_for_every_language",
            "export_graph_database_formats_cli_match_sdk_for_every_language",
            "native_export_json_cli_matches_sdk_for_every_language",
            "\"taint-analysis\"",
            "\"source-analysis\"",
            "\"sources\"",
            "\"sinks\"",
            "\"sanitizers\"",
            "\"calls\"",
            "\"args\"",
            "\"refs\"",
            "\"dump-edges\"",
            "\"dump-resolve\"",
            "\"dump-taint\"",
            "\"trace\"",
            "\"export\"",
        ],
    );
}

#[test]
fn benchmark_gap_regressions_cover_reported_taint_failure_families() {
    let gaps = read("crates/cli/tests/benchmark_gap_regressions.rs");
    assert_contains_all(
        "benchmark gap regressions",
        &gaps,
        &[
            "go_cross_file_nethttp_query_reaches_service_path_sink",
            "go_cross_file_nethttp_query_reaches_repo_sql_querycontext",
            "javascript_commonjs_route_source_reaches_service_sink",
            "javascript_graphql_args_arbitrary_field_reaches_cross_file_sql_sink",
            "typescript_graphql_args_arbitrary_field_reaches_cross_file_sql_sink",
            "python_graphql_args_reach_untyped_connection_execute_sql_sink",
            "go_graphql_resolveparams_args_reach_cross_file_sql_querycontext",
            "java_graphql_datafetching_argument_reaches_cross_file_sink",
            "java_jaxrs_queryparam_flows_to_runtime_exec",
            "java_vertx_request_param_flows_to_runtime_exec",
            "javascript_document_url_reaches_innerhtml_without_document_title_overtaint",
            "typescript_location_hash_reaches_innerhtml_without_sibling_overtaint",
            "javascript_decode_uri_component_preserves_query_taint_without_sibling_overtaint",
            "python_urllib_unquote_preserves_query_taint_without_sibling_overtaint",
            "go_url_query_unescape_preserves_query_taint_without_sibling_overtaint",
            "php_graphql_resolver_args_reach_execute_query_without_helper_overtaint",
            "ruby_graphql_resolver_args_reach_schema_execute_without_helper_overtaint",
            "rust_async_graphql_context_args_reach_schema_execute_without_helper_overtaint",
            "elixir_absinthe_resolver_args_reach_absinthe_run_without_helper_overtaint",
        ],
    );
}

#[test]
fn semantic_engine_suites_cover_positive_negative_and_wrong_flow_guards() {
    for path in [
        "crates/security/tests/assign_chain_audit.rs",
        "crates/security/tests/branch_merge_audit.rs",
        "crates/security/tests/callback_flow_audit.rs",
        "crates/security/tests/cross_file_chain_audit.rs",
        "crates/security/tests/no_fp_audit.rs",
        "crates/security/tests/receiver_type_audit.rs",
        "crates/security/tests/sanitizer_credit_audit.rs",
        "crates/security/tests/try_catch_audit.rs",
        "crates/security/tests/security_pipeline_regressions.rs",
        "crates/taint/tests/over_taint_per_language.rs",
    ] {
        let text = read(path);
        assert!(
            text.contains("REGRESSION")
                || text.contains("drift")
                || text.contains("Expected::Pass")
                || text.contains("expect"),
            "{path} must keep explicit semantic regression assertions"
        );
    }

    let taint_matrix = read("crates/taint/tests/matrix.rs");
    assert_contains_all(
        "taint matrix aggregator",
        &taint_matrix,
        &[
            "matrix/intra",
            "matrix/inter",
            "matrix/cross_file",
            "matrix/over_taint",
        ],
    );

    let wrong_flow_guard_text = [
        "crates/security/tests/no_fp_audit.rs",
        "crates/security/tests/security_pipeline_regressions.rs",
        "crates/cli/tests/benchmark_gap_regressions.rs",
        "crates/taint/tests/over_taint_per_language.rs",
    ]
    .into_iter()
    .map(read)
    .collect::<Vec<_>>()
    .join("\n");

    assert!(
        wrong_flow_guard_text.contains("negative")
            || wrong_flow_guard_text.contains("decoy")
            || wrong_flow_guard_text.contains("no_fp")
            || wrong_flow_guard_text.contains("must not")
            || wrong_flow_guard_text.contains("MUST NOT")
            || wrong_flow_guard_text.contains("over-taint")
            || wrong_flow_guard_text.contains("finding count drifted"),
        "semantic suites must keep explicit negative / wrong-flow assertions"
    );
}

#[test]
fn security_api_patterns_remain_rulepack_configurable_not_engine_hardcoded() {
    let engine_purity = read("crates/taint/tests/engine_purity.rs");
    assert_contains_all(
        "engine purity tests",
        &engine_purity,
        &[
            "default_config_carries_zero_embedded_library_knowledge",
            "rulepack",
            "default clean_output_overwrites must be empty",
            "default receiver_state_propagations must be empty",
            "default output_arg_flows must be empty",
        ],
    );

    let idg_transfer_tests = read("crates/idg/src/transfer_tests.rs");
    assert_contains_all(
        "IDG transfer configurability tests",
        &idg_transfer_tests,
        &[
            "decode_call_result_is_not_hardcoded_passthrough_by_default",
            "library decode passthrough belongs in rulepack semantics",
            "unknown decode methods must not become generic CallArg->CallRet passthroughs",
            "TransferOptions",
        ],
    );
}
