//! Public command-line contract tests.
//!
//! These checks are deliberately about parsing, help, and selector aliases,
//! not analyzer semantics. They keep the CLI predictable for humans, shell
//! scripts, and agents while positional compatibility remains available.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bonsai-ninja"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical repository root")
}

fn workspace() -> PathBuf {
    repo_root().join("test-fixtures/languages/python/micro")
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .env("NO_COLOR", "1")
        .env("NO_PROGRESS", "1")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .unwrap_or_else(|error| panic!("run bonsai-ninja {args:?}: {error}"))
}

fn stdout(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "bonsai-ninja {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

fn temp_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bonsai-cli-contract-{label}-{}-{nanos}.json",
        std::process::id()
    ))
}

fn taint_json_with_cache(
    workspace: &std::path::Path,
    cache: &std::path::Path,
    global: &[&str],
    view: &[&str],
) -> serde_json::Value {
    let output = Command::new(binary())
        .args(global)
        .args(["--no-color", "--no-progress", "security"])
        .arg(workspace)
        .args([
            "taint-analysis",
            "--profile",
            "all",
            "--format",
            "json",
            "--context",
            "16k",
        ])
        .args(view)
        .env("BONSAI_WORKSPACE_DIR", cache)
        .env("NO_COLOR", "1")
        .env("NO_PROGRESS", "1")
        .output()
        .expect("run cached taint analysis");
    assert!(
        output.status.success(),
        "taint analysis failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("taint JSON")
}

#[test]
fn taint_json_is_the_complete_finding_model_and_selectors_are_view_only() {
    let workspace = temp_path("taint-view-workspace");
    let cache = temp_path("taint-view-cache");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    std::fs::write(
        workspace.join("app.py"),
        concat!(
            "import os\n",
            "from flask import request\n\n",
            "def execute(value):\n",
            "    return os.system(value)\n\n",
            "def endpoint():\n",
            "    command = request.args.get('command', '')\n",
            "    return execute(command)\n",
        ),
    )
    .expect("write taint fixture");

    let base = taint_json_with_cache(&workspace, &cache, &[], &[]);
    assert_eq!(base["analysis_complete"], true);
    let rows = base["rows"].as_array().expect("taint rows");
    assert_eq!(rows.len(), 1, "{base:#}");
    let row = &rows[0];
    assert!(
        row["hops"].as_array().is_some_and(|hops| !hops.is_empty()),
        "normal paged JSON omitted compiler flow bodies: {row:#}",
    );
    let annotations = row["flow"]["functions"]
        .as_array()
        .expect("flow functions")
        .iter()
        .flat_map(|function| function["lines"].as_array().into_iter().flatten())
        .filter_map(|line| line["annotation"].as_str())
        .collect::<Vec<_>>();
    assert!(
        annotations.iter().any(|line| line.contains(" SOURCE:")),
        "{row:#}"
    );
    assert!(annotations.iter().any(|line| line.contains(" TAINT:")), "{row:#}");
    assert!(annotations.iter().any(|line| line.contains(" SINK:")), "{row:#}");
    assert!(row["presentation"]["summary"].as_str().is_some(), "{row:#}");
    assert!(
        row["presentation"]["rules"]["python.cmdi.os_system"]["description"]
            .as_str()
            .is_some_and(|description| !description.is_empty()),
        "JSON omitted rule prose printed by the text renderer: {row:#}",
    );

    let finding_id = row["finding_id"].as_str().expect("finding id");
    let sink_count = base["summary"]["sink_rule_count"].clone();
    for selected in [
        taint_json_with_cache(&workspace, &cache, &[], &["--tag", "command-injection"]),
        taint_json_with_cache(&workspace, &cache, &[], &["--severity", "critical"]),
        taint_json_with_cache(&workspace, &cache, &[], &["--finding", finding_id]),
        taint_json_with_cache(
            &workspace,
            &cache,
            &["--contains", "return execute(command)"],
            &[],
        ),
    ] {
        assert_eq!(selected["summary"]["sink_rule_count"], sink_count);
        assert_eq!(selected["rows"].as_array().map(Vec::len), Some(1));
        assert_eq!(selected["rows"][0], *row);
    }

    let _ = std::fs::remove_dir_all(&cache);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn browse_json_and_text_filter_the_same_complete_definition_rows() {
    let workspace = temp_path("browse-parity-workspace");
    let cache = temp_path("browse-parity-cache");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    std::fs::write(
        workspace.join("app.py"),
        concat!(
            "import os\n\n",
            "def harmless(value):\n",
            "    return value\n\n",
            "def execute(value):\n",
            "    return os.system(value)\n",
        ),
    )
    .expect("write browse fixture");
    let workspace_text = workspace.to_str().expect("UTF-8 workspace");

    let run_filtered = |format: &str| {
        Command::new(binary())
            .args([
                "--contains",
                "execute(value)",
                "--no-color",
                "--no-progress",
                "defs",
                workspace_text,
                "--format",
                format,
                "--context",
                "16k",
            ])
            .env("BONSAI_WORKSPACE_DIR", &cache)
            .output()
            .expect("run filtered defs")
    };

    let json_output = run_filtered("json");
    assert!(
        json_output.status.success(),
        "{}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&json_output.stdout).expect("defs JSON");
    assert_eq!(report["analysis_complete"], true);
    assert_eq!(report["result_complete"], true);
    let rows = report["rows"].as_array().expect("defs rows");
    assert_eq!(rows.len(), 1, "{report:#}");
    assert_eq!(rows[0]["name"], "execute");
    assert_eq!(rows[0]["presentation"]["signature"], "execute(value)");
    assert!(
        rows[0]["presentation"]["callees"]
            .as_str()
            .is_some_and(|callees| callees.contains("os.system")),
        "{report:#}",
    );
    assert!(
        rows[0]["presentation"]["code"]
            .as_str()
            .is_some_and(|code| code.contains("def execute")),
        "{report:#}",
    );

    let text_output = run_filtered("text");
    assert!(
        text_output.status.success(),
        "{}",
        String::from_utf8_lossy(&text_output.stderr)
    );
    let text = String::from_utf8(text_output.stdout).expect("UTF-8 defs text");
    assert!(text.contains("execute"), "{text}");
    assert!(text.contains("os.system"), "{text}");
    assert!(!text.contains("harmless"), "{text}");

    let _ = std::fs::remove_dir_all(&cache);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn no_cache_taint_analysis_computes_exact_flow_without_persistent_artifacts() {
    let workspace = temp_path("no-cache-workspace");
    let cache = temp_path("no-cache-sidecars");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    std::fs::write(
        workspace.join("app.py"),
        concat!(
            "import os\n",
            "from flask import request\n\n",
            "def execute(value):\n",
            "    return os.system(value)\n\n",
            "def endpoint():\n",
            "    command = request.args.get('command', '')\n",
            "    return execute(command)\n",
        ),
    )
    .expect("write taint fixture");

    let output = Command::new(binary())
        .args([
            "security",
            workspace.to_str().expect("UTF-8 workspace"),
            "taint-analysis",
            "--profile",
            "all",
            "--no-cache",
            "--format",
            "json",
            "--all",
            "--no-color",
            "--no-progress",
        ])
        .env("BONSAI_WORKSPACE_DIR", &cache)
        .output()
        .expect("run uncached taint analysis");
    assert!(
        output.status.success(),
        "uncached taint analysis failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON taint report");
    assert_eq!(report["analysis_complete"], true);
    assert!(
        report["rows"]
            .as_array()
            .is_some_and(|findings| !findings.is_empty()),
        "requested source-to-sink analysis must still be exact: {report:#}"
    );
    assert!(
        !cache.exists()
            || std::fs::read_dir(&cache)
                .expect("read cache directory")
                .next()
                .is_none(),
        "--no-cache must not publish reusable sidecars under {}",
        cache.display()
    );

    let _ = std::fs::remove_dir_all(&cache);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn leaf_help_names_the_full_command_and_documents_global_options() {
    let top_level = [
        "index",
        "show",
        "diagnostics",
        "dump-hir",
        "dump-cfg",
        "dump-callgraph",
        "dump-edges",
        "dump-resolution",
        "dump-ast",
        "dump-resolve",
        "dump-taint",
        "defs",
        "entrypoints",
        "calls",
        "imports",
        "vars",
        "strings",
        "comments",
        "args",
        "operations",
        "classes",
        "refs",
        "search",
        "inspect-graph",
        "export",
        "tree",
        "read-file",
    ];
    let mut cases = top_level
        .iter()
        .map(|command| {
            (
                vec![(*command).to_string(), "--help".to_string()],
                format!("USAGE: bonsai-ninja {command}"),
            )
        })
        .collect::<Vec<_>>();
    for action in [
        "sources",
        "sinks",
        "sanitizers",
        "deps",
        "taint-analysis",
        "source-analysis",
        "sink-analysis",
        "pack",
    ] {
        cases.push((
            vec![
                "security".to_string(),
                ".".to_string(),
                action.to_string(),
                "--help".to_string(),
            ],
            format!("USAGE: bonsai-ninja security <WORKSPACE> {action}"),
        ));
    }
    for action in ["stats", "clear", "rebuild"] {
        cases.push((
            vec!["cache".to_string(), action.to_string(), "--help".to_string()],
            format!("USAGE: bonsai-ninja cache {action}"),
        ));
    }

    for (args, expected_usage) in cases {
        let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
        let help = stdout(&borrowed);
        assert!(
            help.contains(&expected_usage),
            "{args:?} omitted its full invocation from help:\n{help}"
        );
        assert!(
            !help.contains("_POS]"),
            "{args:?} leaked an internal positional field name into help:\n{help}"
        );
        for expected in ["GLOBAL OPTIONS", "--no-color", "--no-progress", "--memory-budget"] {
            assert!(
                help.contains(expected),
                "{args:?} help omitted `{expected}`:\n{help}"
            );
        }
    }
}

#[test]
fn preferred_usage_keeps_workspace_before_the_selector() {
    for (command, expected) in [
        (
            "search",
            "USAGE: bonsai-ninja search [OPTIONS] <WORKSPACE> [QUERY]",
        ),
        (
            "inspect-graph",
            "USAGE: bonsai-ninja inspect-graph [OPTIONS] <WORKSPACE> [QUERY]",
        ),
        (
            "read-file",
            "USAGE: bonsai-ninja read-file [OPTIONS] <WORKSPACE> [PATH]",
        ),
    ] {
        let help = stdout(&[command, "--help"]);
        assert!(help.contains(expected), "unexpected {command} usage:\n{help}");
    }
}

#[test]
fn help_stays_on_themed_full_path_with_options_before_it() {
    for args in [
        vec!["--memory-budget", "1024", "inspect-graph", "--help"],
        vec!["--theme=dracula", "search", "--help"],
        vec!["inspect-graph", "--query", "target", "--help"],
    ] {
        let help = stdout(&args);
        let command = if args.contains(&"search") {
            "search"
        } else {
            "inspect-graph"
        };
        assert!(
            help.contains(&format!("USAGE: bonsai-ninja {command}")),
            "{args:?} fell off the full themed help path:\n{help}"
        );
        assert!(help.contains("GLOBAL OPTIONS:"), "{args:?}:\n{help}");
        assert!(!help.contains("\nUsage:"), "{args:?}:\n{help}");
    }
}

#[test]
fn compact_global_help_preserves_the_correctness_contract() {
    let help = stdout(&["inspect-graph", "--help"]);
    assert!(help.contains("results remain identical"), "{help}");
    assert!(help.contains("analysis remains exact and exhaustive"), "{help}");
    assert!(help.contains("without enabling extra analysis"), "{help}");
}

#[test]
fn security_analysis_help_documents_production_default_and_minified_opt_in() {
    for action in ["taint-analysis", "source-analysis", "sink-analysis"] {
        let help = stdout(&["security", ".", action, "--help"]);
        for expected in ["--profile", "production", "--profile all", "--minified-js"] {
            assert!(
                help.contains(expected),
                "security {action} help omitted `{expected}`:\n{help}"
            );
        }
        if action == "taint-analysis" {
            assert!(
                help.contains("every sink severity"),
                "security {action} help must document the all-severity production default:\n{help}"
            );
            assert!(
                !help.contains("selects severity `high`"),
                "security {action} help retained the obsolete high-only production default:\n{help}"
            );
        }
    }
}

#[test]
fn minified_javascript_opt_in_is_consistent_across_compiler_commands() {
    let root = temp_path("minified-workspace");
    std::fs::create_dir_all(&root).expect("create minified policy workspace");
    std::fs::write(
        root.join("app.js"),
        "import { minifiedEntry } from './vendor.min.js';\nfunction maintainedEntry(value) { return minifiedEntry(value); }\n",
    )
    .expect("write maintained JavaScript");
    std::fs::write(
        root.join("vendor.min.js"),
        "export function minifiedEntry(value){return value;}\n",
    )
    .expect("write minified JavaScript");
    let root_text = root.to_str().expect("UTF-8 temp workspace");

    let default_index: serde_json::Value =
        serde_json::from_str(&stdout(&["index", root_text, "--format", "json"])).expect("default index JSON");
    assert_eq!(default_index["files"], 1);
    assert_eq!(default_index["include_minified_sources"], false);
    let inclusive_index: serde_json::Value = serde_json::from_str(&stdout(&[
        "index",
        root_text,
        "--minified-js",
        "--format",
        "json",
    ]))
    .expect("inclusive index JSON");
    assert_eq!(inclusive_index["files"], 2);
    assert_eq!(inclusive_index["include_minified_sources"], true);
    let inclusive_warm: serde_json::Value = serde_json::from_str(&stdout(&[
        "index",
        root_text,
        "--minified-js",
        "--format",
        "json",
    ]))
    .expect("warm inclusive index JSON");
    assert_eq!(inclusive_warm["compiler_cache"], "hit");
    assert_eq!(inclusive_warm["files"], 2);
    assert_eq!(inclusive_warm["include_minified_sources"], true);

    let inclusive_semantic: serde_json::Value = serde_json::from_str(&stdout(&[
        "index",
        root_text,
        "--semantic",
        "--minified-js",
        "--format",
        "json",
    ]))
    .expect("inclusive semantic index JSON");
    assert_eq!(inclusive_semantic["files"], 2);
    assert_eq!(inclusive_semantic["include_minified_sources"], true);
    assert_eq!(inclusive_semantic["semantic_ready"], true);

    let tree = stdout(&["tree", root_text, "--all"]);
    assert!(tree.contains("vendor.min.js"), "{tree}");

    let default_defs = stdout(&["defs", root_text, "--format", "json", "--all"]);
    let default_defs_json: serde_json::Value =
        serde_json::from_str(&default_defs).expect("default defs JSON");
    let default_def_names = default_defs_json["rows"]
        .as_array()
        .expect("default defs rows")
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect::<Vec<_>>();
    assert!(default_def_names.contains(&"maintainedEntry"), "{default_defs}");
    assert!(!default_def_names.contains(&"minifiedEntry"), "{default_defs}");
    let inclusive_defs = stdout(&["defs", root_text, "--minified-js", "--format", "json", "--all"]);
    let inclusive_defs_json: serde_json::Value =
        serde_json::from_str(&inclusive_defs).expect("inclusive defs JSON");
    let inclusive_def_names = inclusive_defs_json["rows"]
        .as_array()
        .expect("inclusive defs rows")
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect::<Vec<_>>();
    assert!(
        inclusive_def_names.contains(&"maintainedEntry"),
        "{inclusive_defs}"
    );
    assert!(inclusive_def_names.contains(&"minifiedEntry"), "{inclusive_defs}");

    let default_export = stdout(&["export", root_text, "--format", "json"]);
    let default_export_json: serde_json::Value =
        serde_json::from_str(&default_export).expect("default export JSON");
    let default_files = default_export_json["files"]
        .as_array()
        .expect("default export files");
    assert!(default_files.iter().any(|file| file["path"] == "app.js"));
    assert!(!default_files.iter().any(|file| file["path"] == "vendor.min.js"));
    assert!(default_export_json["callgraph"]
        .as_array()
        .is_some_and(Vec::is_empty));
    let inclusive_export = stdout(&["export", root_text, "--minified-js", "--format", "json"]);
    let inclusive_export_json: serde_json::Value =
        serde_json::from_str(&inclusive_export).expect("inclusive export JSON");
    let inclusive_files = inclusive_export_json["files"]
        .as_array()
        .expect("inclusive export files");
    assert!(inclusive_files.iter().any(|file| file["path"] == "app.js"));
    assert!(inclusive_files.iter().any(|file| file["path"] == "vendor.min.js"));
    assert!(inclusive_export_json["callgraph"]
        .as_array()
        .is_some_and(|edges| edges
            .iter()
            .any(|edge| { edge["caller"] == "maintainedEntry" && edge["callee"] == "minifiedEntry" })));

    let rejected_read = run(&["read-file", root_text, "vendor.min.js"]);
    assert_eq!(rejected_read.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&rejected_read.stderr).contains("--minified-js"),
        "{}",
        String::from_utf8_lossy(&rejected_read.stderr)
    );
    let inclusive_read = stdout(&[
        "read-file",
        root_text,
        "vendor.min.js",
        "--minified-js",
        "--format",
        "json",
    ]);
    assert!(inclusive_read.contains("minifiedEntry"), "{inclusive_read}");

    let cleared = run(&["cache", "clear", root_text]);
    assert!(cleared.status.success());
    std::fs::remove_dir_all(root).expect("remove minified policy workspace");
}

#[test]
fn missing_or_duplicate_selectors_are_parse_errors() {
    let workspace = workspace();
    let workspace = workspace.to_str().expect("UTF-8 workspace");
    let cases: &[&[&str]] = &[
        &["search", workspace],
        &["refs", workspace],
        &["dump-hir", workspace],
        &["read-file", workspace],
        &["search", workspace, "handle", "--query", "request"],
        &["refs", workspace, "handle", "--symbol", "request"],
        &["inspect-graph", workspace, "handle", "--query", "request"],
        &["read-file", workspace, "gateway.py", "--symbol", "handle_request"],
    ];

    for args in cases {
        let output = run(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?} should fail during argument parsing, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("USAGE:") || stderr.contains("Usage:"),
            "{args:?} omitted usage:\n{stderr}"
        );
        assert!(
            !stderr.starts_with("Error:"),
            "{args:?} fell through to an application error:\n{stderr}"
        );
    }
}

#[test]
fn explicit_selector_flags_work_and_positionals_remain_compatible() {
    let workspace = workspace();
    let workspace = workspace.to_str().expect("UTF-8 workspace");
    let successful: &[&[&str]] = &[
        &[
            "search",
            workspace,
            "--query",
            "handle_request",
            "--format",
            "json",
        ],
        &["search", workspace, "handle_request", "--format", "json"],
        &[
            "refs",
            workspace,
            "--symbol",
            "handle_request",
            "--format",
            "json",
        ],
        &[
            "inspect-graph",
            workspace,
            "--query",
            "handle_request",
            "--format",
            "json",
        ],
        &["inspect-graph", workspace, "handle_request", "--format", "json"],
        &["read-file", workspace, "--file", "gateway.py", "--format", "json"],
        &["read-file", workspace, "gateway.py", "--format", "json"],
    ];

    for args in successful {
        let output = run(args);
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .unwrap_or_else(|error| panic!("{args:?} did not emit JSON: {error}"));
    }
}

#[test]
fn output_path_has_standard_short_and_long_aliases() {
    let workspace = workspace();
    let workspace = workspace.to_str().expect("UTF-8 workspace");
    for (label, flag) in [("short", "-o"), ("long", "--output")] {
        let path = temp_path(label);
        let output = run(&[
            "defs",
            workspace,
            "--format",
            "json",
            flag,
            path.to_str().expect("UTF-8 output path"),
        ]);
        assert!(
            output.status.success(),
            "{flag} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{flag} should redirect stdout");
        let document = std::fs::read(&path).expect("read redirected output");
        serde_json::from_slice::<serde_json::Value>(&document).expect("redirected JSON");
        std::fs::remove_file(path).expect("remove redirected output");
    }
}

// ---------------------------------------------------------------------------
// Whole-parent secondary filtering + stable envelopes.
//
// `--contains` / `--not-contains` select complete semantic objects: a match
// on any child field keeps the whole parent (inspect-graph hit, sink-analysis
// candidate) and the JSON envelope keeps one shape for
// empty, filtered, and populated results.
// ---------------------------------------------------------------------------

fn json(args: &[&str]) -> serde_json::Value {
    let text = stdout(args);
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{args:?} did not print JSON ({error}):\n{text}"))
}

fn rules_dir() -> String {
    repo_root()
        .join("security-patterns")
        .to_string_lossy()
        .into_owned()
}

fn assert_envelope(value: &serde_json::Value, context: &str) {
    for key in [
        "analysis_complete",
        "analysis_incomplete_reasons",
        "result_complete",
        "result_incomplete_reasons",
        "page",
    ] {
        assert!(
            value.get(key).is_some(),
            "{context}: envelope lacks `{key}`:\n{value:#}"
        );
    }
    assert!(
        value["analysis_incomplete_reasons"].is_array() && value["result_incomplete_reasons"].is_array(),
        "{context}: completeness reasons must be arrays:\n{value:#}"
    );
    assert!(
        value["page"].is_object(),
        "{context}: page must be an object:\n{value:#}"
    );
}

#[test]
fn sink_analysis_contains_selects_the_complete_hydrated_sink() {
    let ws = workspace();
    let ws = ws.to_str().expect("UTF-8 workspace");
    let rules = rules_dir();
    let base = json(&[
        "security",
        ws,
        "sink-analysis",
        "--rules-dir",
        &rules,
        "--profile",
        "all",
        "--sink",
        "^python\\.cmdi\\.",
        "--format",
        "json",
        "--all",
    ]);
    assert_envelope(&base, "sink-analysis");
    let base_rows = base["rows"].as_array().expect("sink rows");
    assert_eq!(base_rows.len(), 1, "{base:#}");
    // The needle is a source line of an upstream hop that exists only after
    // the lineage bodies are hydrated; the compact engine candidate never
    // carries it.
    let selected = json(&[
        "--contains",
        "run_admin_command(user_id, action)",
        "security",
        ws,
        "sink-analysis",
        "--rules-dir",
        &rules,
        "--profile",
        "all",
        "--sink",
        "^python\\.cmdi\\.",
        "--format",
        "json",
        "--all",
    ]);
    assert_envelope(&selected, "filtered sink-analysis");
    let rows = selected["rows"].as_array().expect("filtered sink rows");
    assert_eq!(rows.len(), 1, "{selected:#}");
    assert_eq!(
        rows[0]["sink"], base_rows[0]["sink"],
        "the complete sink object is retained"
    );
    assert_eq!(
        rows[0]["upstream_flows"].as_array().map(Vec::len),
        base_rows[0]["upstream_flows"].as_array().map(Vec::len),
        "every upstream flow of the selected sink is retained: {selected:#}"
    );

    let none = json(&[
        "--contains",
        "zzz-no-such-text",
        "security",
        ws,
        "sink-analysis",
        "--rules-dir",
        &rules,
        "--profile",
        "all",
        "--sink",
        "^python\\.cmdi\\.",
        "--format",
        "json",
        "--all",
    ]);
    assert_envelope(&none, "unmatched sink-analysis");
    assert_eq!(none["rows"], serde_json::json!([]));
    assert_eq!(none["result_complete"], true);
    assert_eq!(none["summary"]["sink_count"], base["summary"]["sink_count"]);
}

#[test]
fn empty_results_keep_the_same_json_envelope() {
    let ws = workspace();
    let ws = ws.to_str().expect("UTF-8 workspace");
    let rules = rules_dir();

    let inspect = json(&[
        "inspect-graph",
        ws,
        "--query",
        "zzz_no_such_symbol",
        "--format",
        "json",
    ]);
    assert_envelope(&inspect, "empty inspect");
    for key in ["decl_hits", "hits", "taint_flows"] {
        assert_eq!(inspect[key], serde_json::json!([]), "{inspect:#}");
    }
    assert_eq!(inspect["result_complete"], true);

    let defs = json(&["defs", ws, "--name", "zzz_no_such_symbol", "--format", "json"]);
    assert_envelope(&defs, "empty defs");
    assert_eq!(defs["rows"], serde_json::json!([]));

    let sources = json(&[
        "security",
        ws,
        "sources",
        "--rules-dir",
        &rules,
        "--rule",
        "zzz.no.such.rule",
        "--format",
        "json",
    ]);
    assert_envelope(&sources, "empty sources");
    assert_eq!(sources["rows"], serde_json::json!([]));

    let sinks = json(&[
        "security",
        ws,
        "sink-analysis",
        "--rules-dir",
        &rules,
        "--sink",
        "^zzz\\.",
        "--format",
        "json",
    ]);
    assert_envelope(&sinks, "empty sink-analysis");
    assert_eq!(sinks["rows"], serde_json::json!([]));

    let flows = json(&[
        "security",
        ws,
        "source-analysis",
        "--rules-dir",
        &rules,
        "--source",
        "^zzz\\.",
        "--format",
        "json",
    ]);
    assert_envelope(&flows, "empty source-analysis");
    assert_eq!(flows["rows"], serde_json::json!([]));
}

#[test]
fn html_output_renders_the_canonical_result_not_terminal_text() {
    let ws = workspace();
    let ws = ws.to_str().expect("UTF-8 workspace");
    let out_path = temp_path("defs-html").with_extension("html");
    let output = run(&[
        "defs",
        ws,
        "--html-output",
        out_path.to_str().expect("UTF-8 output path"),
    ]);
    assert!(
        output.status.success(),
        "defs --html-output failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "stdout must stay empty under --html-output:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let html = std::fs::read_to_string(&out_path).expect("read HTML report");
    let canonical = json(&["defs", ws, "--format", "json"]);
    let names = canonical["rows"]
        .as_array()
        .expect("defs rows")
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&"verify_token"), "{canonical:#}");
    for required in [
        "<!doctype html>",
        "<title>bonsai-ninja defs</title>",
        "analysis complete",
        "<table>",
        "</body></html>",
    ] {
        assert!(html.contains(required), "HTML report lacks `{required}`:\n{html}");
    }
    for name in &names {
        assert!(html.contains(name), "HTML report lacks definition `{name}`");
    }
    assert!(!html.contains("\u{1b}["), "HTML must not contain ANSI escapes");
    assert!(
        !html.contains("\"rows\": ["),
        "HTML must render the canonical object, not dump JSON text"
    );
    assert!(
        !html.contains("</pre></main>"),
        "HTML must not be an escaped terminal transcript"
    );
    let _ = std::fs::remove_file(&out_path);

    let export = run(&[
        "export",
        ws,
        "--html-output",
        temp_path("export-html").to_str().expect("UTF-8"),
    ]);
    assert!(!export.status.success(), "export cannot produce an HTML report");
    assert!(
        String::from_utf8_lossy(&export.stderr).contains("--html-output is not supported for `export`"),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
}

#[test]
fn parser_failures_make_analysis_incomplete_while_paging_does_not() {
    let workspace = temp_path("parser-completeness-workspace");
    let cache = temp_path("parser-completeness-cache");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    std::fs::write(
        workspace.join("good.py"),
        "def alpha():\n    return 1\n\ndef beta():\n    return alpha()\n",
    )
    .expect("write good fixture");
    std::fs::write(workspace.join("broken.py"), "def gamma(:\n    return (\n").expect("write broken fixture");
    let workspace_text = workspace.to_str().expect("UTF-8 workspace");
    let run_defs = |extra: &[&str]| {
        let output = Command::new(binary())
            .args(["defs", workspace_text])
            .args(extra)
            .env("BONSAI_WORKSPACE_DIR", &cache)
            .env("NO_COLOR", "1")
            .env("NO_PROGRESS", "1")
            .env_remove("BONSAI_CONTEXT")
            .output()
            .expect("run defs");
        assert!(
            output.status.success(),
            "defs failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8 defs output")
    };

    let json: serde_json::Value = serde_json::from_str(&run_defs(&["--format", "json"])).expect("defs JSON");
    assert_eq!(
        json["analysis_complete"], false,
        "a syntax error must mark the analysis incomplete: {json:#}"
    );
    assert!(
        json["analysis_incomplete_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.iter().any(|reason| reason
                .as_str()
                .is_some_and(|reason| reason.starts_with("syntax-error-files:")))),
        "{json:#}"
    );
    assert_eq!(
        json["result_complete"], true,
        "an unpaged result is complete even when analysis is not"
    );
    let text = run_defs(&[]);
    assert!(text.contains("analysis incomplete"), "{text}");
    assert!(text.contains("syntax-error-files:"), "{text}");

    // Paging touches result completeness only; the analysis facts are
    // unchanged and a warm rerun reports the same parser coverage.
    let paged: serde_json::Value =
        serde_json::from_str(&run_defs(&["--format", "json", "--context", "1k"])).expect("paged defs JSON");
    assert_eq!(paged["analysis_complete"], false, "{paged:#}");
    assert_eq!(
        paged["analysis_incomplete_reasons"], json["analysis_incomplete_reasons"],
        "{paged:#}"
    );

    let _ = std::fs::remove_dir_all(&cache);
    let _ = std::fs::remove_dir_all(&workspace);
}
