//! Meta-coverage contract for flow/taint command and language-semantic
//! regression tests.
//!
//! These checks do not replace the behavioral suites they reference.
//! They make the current audit goal concrete: if a future edit deletes
//! command, SDK, benchmark-gap, or rulepack-configurability coverage,
//! this suite fails even before the more expensive behavioral tests run.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use bonsai_lang_api::{FlowEdgeKind, FLOW_EDGE_TAXONOMY};

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

fn taxonomy_names() -> Vec<&'static str> {
    FlowEdgeKind::ALL.iter().map(|kind| kind.as_str()).collect()
}

fn registered_adapter_langs() -> BTreeSet<String> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect()
}

fn adapter_docs_table_langs(markdown: &str) -> BTreeSet<String> {
    markdown
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("| lang_") {
                return None;
            }
            line.split('|')
                .nth(1)
                .map(str::trim)
                .and_then(|cell| cell.strip_prefix("lang_"))
                .map(str::to_string)
        })
        .collect()
}

fn adapter_capability_snapshot_langs(snapshot: &str) -> BTreeSet<String> {
    snapshot
        .lines()
        .filter_map(|line| {
            let first = line.split_whitespace().next()?;
            first.strip_prefix("lang_").map(str::to_string)
        })
        .collect()
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
fn adapter_capability_docs_and_snapshot_name_registered_adapters() {
    let registered = registered_adapter_langs();
    let docs = read("docs/contributing/adapter-capabilities.mdx");
    let docs_langs = adapter_docs_table_langs(&docs);
    assert_eq!(
        docs_langs, registered,
        "adapter-capabilities.mdx table must name exactly the registered adapters"
    );

    let snapshot = read(".snapshots/ADAPTER_CAPABILITIES.snapshot");
    let snapshot_langs = adapter_capability_snapshot_langs(&snapshot);
    assert_eq!(
        snapshot_langs, registered,
        ".snapshots/ADAPTER_CAPABILITIES.snapshot must name exactly the registered adapters"
    );
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
            "micro_path_handler_to_verifier",
            "micro_slice_action_at_update_call",
            "micro_dump_edges",
            "micro_dump_resolution",
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
            "mega_flow_source_analysis_uses_semantic_paths",
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
            "\"operations\"",
            "\"refs\"",
            "\"dump-edges\"",
            "\"dump-resolution\"",
            "\"path\"",
            "\"slice\"",
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
            "slice_cli_json_matches_sdk_facade",
            "fn slice_site",
            "non-empty syntax-derived slice",
            "cache_commands_cli_json_match_sdk_facade",
            "navigation_cli_json_matches_sdk_facade",
            "inspect_structural_flow_ids_match_sdk_facade",
            "show_structural_ids_roundtrip_through_cli_and_sdk",
            "CLI show E:",
            "CLI show N:",
            "CLI show R:",
            "CLI show F:",
            "CLI show G:",
            "CLI show T:",
            "CLI show S:",
            "export_graph_database_formats_cli_match_sdk_for_every_language",
            "native_export_json_cli_matches_sdk_for_every_language",
            "\"cache\"",
            "\"show\"",
            "\"tree\"",
            "\"read-file\"",
            "\"taint-analysis\"",
            "\"source-analysis\"",
            "\"sources\"",
            "\"sinks\"",
            "\"sanitizers\"",
            "\"calls\"",
            "\"entrypoints\"",
            "\"args\"",
            "\"operations\"",
            "\"refs\"",
            "\"dump-edges\"",
            "\"dump-resolution\"",
            "\"path\"",
            "\"slice\"",
            "\"dump-resolve\"",
            "\"dump-taint\"",
            "\"trace\"",
            "\"export\"",
        ],
    );
}

#[test]
fn whole_program_flow_taxonomy_is_complete_documented_and_language_neutral() {
    const REQUIRED: &[&str] = &[
        "LOCAL_ASSIGN",
        "EXPR_PROPAGATION",
        "DEF_USE",
        "ARG_TO_PARAM",
        "RECEIVER_TO_THIS",
        "RETURN_TO_CALLER",
        "FIELD_WRITE",
        "FIELD_READ",
        "INDEX_WRITE",
        "INDEX_READ",
        "OBJECT_CONSTRUCTION",
        "DESTRUCTURING",
        "CLOSURE_CAPTURE",
        "GLOBAL_ACCESS",
        "IMPORT_EXPORT",
        "ALIAS",
        "DEREFERENCE",
        "HEAP_STORE",
        "HEAP_LOAD",
        "CONTAINER_STORE",
        "CONTAINER_LOAD",
        "ITERATION",
        "YIELD",
        "THROW_TO_CATCH",
        "AWAIT_RESOLUTION",
        "CALLBACK_INVOCATION",
        "EVENT_DISPATCH",
        "DYNAMIC_PROPERTY_ACCESS",
        "SERIALIZE",
        "DESERIALIZE",
        "SANITIZE",
        "SINK",
        "CONTROL_DEPENDENCE",
        "IMPLICIT_FLOW",
        "INTER_FILE",
        "INTER_PACKAGE",
    ];

    let names = taxonomy_names();
    let unique: BTreeSet<_> = names.iter().copied().collect();
    assert_eq!(unique.len(), names.len(), "taxonomy names must be unique");
    assert_eq!(
        unique,
        REQUIRED.iter().copied().collect(),
        "taxonomy must cover the full language-neutral edge contract"
    );
    assert_eq!(
        FLOW_EDGE_TAXONOMY.len(),
        FlowEdgeKind::ALL.len(),
        "every taxonomy enum variant needs an implementation spec"
    );

    for spec in FLOW_EDGE_TAXONOMY {
        assert!(
            !spec.carriers.is_empty(),
            "{} must name shared engine carriers",
            spec.name()
        );
        for carrier in spec.carriers {
            assert!(
                !SUPPORTED_LANGS
                    .iter()
                    .any(|lang| carrier.eq_ignore_ascii_case(lang)),
                "{} carrier `{carrier}` must describe shared engine facts, not one language",
                spec.name()
            );
        }
    }

    let docs = read("docs/contributing/taint-engine-spec.mdx");
    assert_contains_all("taint engine taxonomy docs", &docs, &names);
    assert_contains_all(
        "taint engine taxonomy caveats",
        &docs,
        &[
            "Whole-program data-flow edge taxonomy",
            "PASS",
            "ENGINE_ONLY",
            "STATIC_LIMIT",
            "Language-specific `N/A` belongs in the taint matrix",
            "InterThrow",
            "reserved",
            "Wildcard import",
        ],
    );
}

#[test]
fn adapter_flow_event_audit_tracks_current_flow_event_enum() {
    let script = read("scripts/audit-adapter-flow-events.sh");
    assert_contains_all(
        "adapter FlowEvent audit script",
        &script,
        &[
            "Call Branch Loop Assign Return Throw Try Break Continue Yield Await Defer Using Lifecycle",
            "fields on `FlowEvent::Loop` / `FlowEvent::Try`",
        ],
    );
    assert!(
        !script.contains("ForEach Param"),
        "adapter audit script must not look for stale FlowEvent variants"
    );

    let snapshot = read(".snapshots/ADAPTER_FLOW_EVENT_COVERAGE.snapshot");
    assert_contains_all(
        "adapter FlowEvent audit snapshot",
        &snapshot,
        &[
            "Loop",
            "Try",
            "Break",
            "Continue",
            "Yield",
            "Await",
            "Defer",
            "Using",
            "Lifecycle",
        ],
    );
    assert!(
        !snapshot.lines().next().unwrap_or_default().contains("ForEach"),
        "adapter FlowEvent snapshot must use current FlowEvent names"
    );
}

#[test]
fn public_security_accuracy_contract_is_semantic_only() {
    let precision = read("crates/common/src/precision.rs");
    assert_contains_all(
        "shared precision contract",
        &precision,
        &[
            "Public security findings have a single accuracy contract",
            "is_proven_static_evidence",
            "is_diagnostic_only",
            "OverApproximate",
            "Unknown",
        ],
    );

    let analysis = read("crates/security/src/analysis/mod.rs");
    assert_contains_all(
        "security analysis semantic-only contract",
        &analysis,
        &[
            "PUBLIC_SEMANTIC_MAX_PRECISION",
            "one accuracy contract",
            "semantic_precision_only",
            "precision.is_proven_static_evidence()",
        ],
    );

    let semantic_tests = read("crates/security/src/analysis/semantic_options_tests.rs");
    assert_contains_all(
        "semantic precision option tests",
        &semantic_tests,
        &[
            "taint_options_default_to_semantic_precision",
            "taint_options_clamp_broad_precision_to_semantic",
            "PUBLIC_SEMANTIC_MAX_PRECISION",
        ],
    );

    let status_tests = read("crates/security/src/analysis/compute_status_tests.rs");
    assert_contains_all(
        "finding precision filter tests",
        &status_tests,
        &[
            "diagnostic-only precision must never become public finding evidence",
            "unknown precision must remain diagnostic-only",
        ],
    );

    let baseline = read("docs/COVERAGE_BASELINE.md");
    assert_contains_all(
        "coverage baseline public accuracy wording",
        &baseline,
        &[
            "Public findings have one accuracy contract",
            "not a second accuracy level",
            "diagnostic-only",
            "not a lower public accuracy mode",
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

    let taint_applicability_sanity = read("crates/taint/tests/matrix/applicability_sanity.rs");
    assert_contains_all(
        "taint matrix applicability gate",
        &taint_applicability_sanity,
        &[
            "every_applicable_cell_has_an_executable_fixture",
            "construct_families_have_positive_and_precision_coverage",
            "scenario_catalog_matches_declared_totals_and_test_modules",
            "mark truly unsupported cells NotApplicable or unimplemented cells AdapterDeferred",
        ],
    );

    let taint_applicability = read("crates/taint/tests/matrix/applicability.rs");
    assert_contains_all(
        "taint matrix explicit gap manifest",
        &taint_applicability,
        &[
            "COVERAGE_GAP_OVERRIDES",
            "`Applicable` means there",
            "concrete per-language test function that runs",
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

#[test]
fn generated_capability_docs_and_diagnostics_stay_linked() {
    let adapter_docs = read("docs/contributing/adapter-capabilities.mdx");
    assert_contains_all(
        "adapter capability docs",
        &adapter_docs,
        &[
            "capability_matrix_report",
            "build/capability-matrix.md",
            "build/capability-matrix.json",
            "Project::diagnostics_report()",
            "bonsai-ninja diagnostics",
        ],
    );

    let conformance = read("crates/conformance/tests/capability_matrix.rs");
    assert_contains_all(
        "capability matrix conformance",
        &conformance,
        &[
            "write_matrix_to_build",
            "21 * Capability::ALL.len()",
            "assert_capability_universal",
        ],
    );

    let sdk = read("crates/sdk/src/lib.rs");
    assert_contains_all(
        "SDK diagnostics report",
        &sdk,
        &[
            "pub struct DiagnosticsReport",
            "pub struct AdapterCapabilityRow",
            "pub fn diagnostics_report",
            "adapter_capabilities",
            "workspace_languages",
        ],
    );

    let cli_diagnostics = read("crates/cli/src/commands/diagnostics.rs");
    assert_contains_all(
        "CLI diagnostics command",
        &cli_diagnostics,
        &["diagnostics_report", "serde_json::to_string_pretty"],
    );

    let parity = read("crates/cli/tests/sdk_cli_parity.rs");
    assert_contains_all(
        "diagnostics CLI/SDK parity",
        &parity,
        &[
            "index_and_diagnostics_cli_json_match_sdk_for_every_language",
            "diagnostics_report",
        ],
    );
}

#[test]
fn cli_reference_documents_stable_id_and_cache_surfaces() {
    let cli_reference = read("docs/cli-reference.mdx");
    assert_contains_all(
        "CLI reference stable id surface",
        &cli_reference,
        &[
            "| `F:` | `inspect --flow`",
            "| `G:` | `inspect --group`",
            "| `T:` | raw inspect taint path",
            "| `E:` | `dump-edges --edge`",
            "| `N:` | `dump-ast --node`",
            "| `R:` | `dump-resolve --candidate`",
            "| `S:` | `security taint-analysis --finding`",
            "bonsai-ninja show ./src S:",
            "bonsai-ninja show ./src R:",
            "bonsai-ninja show ./src T:",
        ],
    );
    assert_contains_all(
        "CLI reference hot cache workflow",
        &cli_reference,
        &[
            "cache stats ./src",
            "cache clear ./src --dataflow-only",
            "cache rebuild ./src",
            "does not run the legacy full-workspace dataflow prewarm",
            "taint-graph",
            "export sidecar",
        ],
    );
}

#[test]
fn long_command_progress_uses_scoped_cleanup_for_shared_renderers() {
    let page_cache = read("crates/cli/src/page_cache.rs");
    assert_contains_all(
        "shared rendered-page progress",
        &page_cache,
        &[
            "ScopedSpinner::new(\"validating rendered page cache\")",
            "ScopedSpinner::new(&render_label)",
            "ScopedSpinner::new(\"saving rendered page cache\")",
        ],
    );
    assert!(
        !page_cache.contains("progress::spinner("),
        "page-cache replay/render progress must use scoped cleanup so early render/cache errors cannot leave duplicate spinners"
    );

    let security = read("crates/cli/src/commands/security.rs");
    assert_contains_all(
        "security top-level progress",
        &security,
        &[
            "ScopedSpinner::new(\"loading security rules\")",
            "stage.finish();",
        ],
    );

    let diagnostics = read("crates/cli/src/commands/diagnostics.rs");
    assert_contains_all(
        "diagnostics progress cleanup",
        &diagnostics,
        &[
            "let parse_result = (|| -> Result<()>",
            "bar.finish_and_clear();",
            "parse_result?;",
        ],
    );
}

#[test]
fn relevance_ranking_runs_before_render_budget_across_shared_surfaces() {
    let common = read("crates/browse/src/common.rs");
    assert_contains_all(
        "browse relevance helpers",
        &common,
        &[
            "textual_relevance_key",
            "best_textual_relevance_key",
            "Lower is better",
            "rank exact matches first",
        ],
    );
    let common_tests = read("crates/browse/src/common_relevance_tests.rs");
    assert_contains_all(
        "browse relevance unit tests",
        &common_tests,
        &[
            "textual_relevance_orders_exact_prefix_and_substring",
            "textual_relevance_preserves_deterministic_sort_for_regex_or_empty_query",
            "best_textual_relevance_uses_best_candidate_in_row",
        ],
    );

    for (path, markers) in [
        (
            "crates/browse/src/defs.rs",
            &["def_relevance_key", "best_textual_relevance_key", "out.sort_by"][..],
        ),
        (
            "crates/browse/src/calls.rs",
            &["callee_rank", "caller_rank", "out.sort_by"][..],
        ),
        (
            "crates/browse/src/refs.rs",
            &["symbol_rank", "textual_relevance_key", "out.sort_by"][..],
        ),
        (
            "crates/browse/src/search.rs",
            &["One ranked search result", "hits.sort_by", "hits.truncate(limit)"][..],
        ),
        (
            "crates/browse/src/operations.rs",
            &["kind_rank", "name_rank", "out.sort_by"][..],
        ),
        (
            "crates/browse/src/entrypoints.rs",
            &[
                "entrypoint_relevance_key",
                "best_textual_relevance_key",
                "out.sort_by",
            ][..],
        ),
    ] {
        let text = read(path);
        assert_contains_all(path, &text, markers);
    }

    let read_file = read("crates/cli/src/commands/read_file.rs");
    assert_contains_all(
        "read-file relevance",
        &read_file,
        &[
            "ranked_path_matches",
            "nearest_path_suggestions",
            "score_a.cmp(score_b)",
        ],
    );
    let trace = read("crates/cli/src/commands/trace.rs");
    assert_contains_all(
        "trace suggestion relevance",
        &trace,
        &["let mut scored", "score += 80", "scored.sort_by"],
    );
    let security = read("crates/security/src/analysis/mod.rs");
    assert_contains_all(
        "security finding relevance",
        &security,
        &[
            "source_preference_rank_for_sink",
            "source_specificity_rank",
            "truncated when rankers read the first result",
        ],
    );
}
