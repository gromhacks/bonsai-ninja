//! CLI/SDK parity tests for command-independent analysis surfaces.
//!
//! The CLI owns rendering, paging, colors, and progress. The SDK owns
//! analysis semantics. These tests run the CLI with every security
//! analysis narrower and compare the machine-readable result to the
//! corresponding `bonsai_sdk` facade call.

use bonsai_sdk::{Severity, SourceAnalysisOptions, SourceLineageLimits, TaintAnalysisOptions};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const LANGS: &[&str] = &[
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
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return PathBuf::from(path);
    }
    let debug = repo_root().join("target/debug/bonsai-ninja");
    if debug.exists() {
        return debug;
    }
    repo_root().join("target/release/bonsai-ninja")
}

fn workspace_path() -> PathBuf {
    repo_root().join("examples/python/micro")
}

fn temp_workspace(name: &str) -> PathBuf {
    let dst = std::env::temp_dir().join(format!(
        "bonsai-cli-sdk-parity-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dst);
    copy_dir(&workspace_path(), &dst);
    dst
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create temp fixture dir");
    for entry in std::fs::read_dir(src).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let name = entry.file_name();
        if name == ".bonsai" {
            continue;
        }
        let target = dst.join(name);
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            std::fs::copy(&path, &target).expect("copy fixture file");
        }
    }
}

fn lang_workspace_path(lang: &str) -> PathBuf {
    repo_root().join(format!("examples/{lang}/micro"))
}

fn lang_workspace_arg(lang: &str) -> String {
    format!("examples/{lang}/micro")
}

fn rules_dir() -> PathBuf {
    repo_root().join("security-patterns")
}

fn run_cli(args: &[&str]) -> Value {
    let out = Command::new(bin_path())
        .args(args)
        .arg("--no-color")
        .current_dir(repo_root())
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .expect("run bonsai-ninja");
    assert!(
        out.status.success(),
        "bonsai-ninja {:?} exited with {}:\nstdout={}\nstderr={}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|err| {
        panic!(
            "invalid JSON for {args:?}: {err}\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn run_cli_text(args: &[&str]) -> String {
    let out = Command::new(bin_path())
        .args(args)
        .arg("--no-color")
        .current_dir(repo_root())
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .expect("run bonsai-ninja");
    assert!(
        out.status.success(),
        "bonsai-ninja {:?} exited with {}:\nstdout={}\nstderr={}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn run_cli_stdout_no_dataflow(args: &[&str]) -> String {
    let out = Command::new(bin_path())
        .args(args)
        .arg("--no-color")
        .current_dir(repo_root())
        .env("COLUMNS", "200")
        .env("BONSAI_NO_DATAFLOW", "1")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .expect("run bonsai-ninja");
    assert!(
        out.status.success(),
        "bonsai-ninja {:?} exited with {}:\nstdout={}\nstderr={}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn sdk() -> bonsai_sdk::Bonsai {
    bonsai_sdk::Bonsai::new()
        .with_rulepack(rules_dir())
        .expect("load SDK rulepack")
}

fn security_project() -> bonsai_sdk::Project {
    sdk().open_query(workspace_path()).expect("open SDK project")
}

fn security_project_for_lang(lang: &str) -> bonsai_sdk::Project {
    sdk()
        .open_query(lang_workspace_path(lang))
        .unwrap_or_else(|err| panic!("open {lang} SDK project: {err}"))
}

fn no_dataflow_project_for_lang(lang: &str) -> bonsai_sdk::Project {
    bonsai_sdk::Bonsai::new()
        .open_with_options(lang_workspace_path(lang), bonsai_sdk::OpenOptions::parse_only())
        .unwrap_or_else(|err| panic!("open {lang} SDK no-dataflow project: {err}"))
}

fn basic_project_for_lang(lang: &str) -> bonsai_sdk::Project {
    bonsai_sdk::Bonsai::new()
        .open_query(lang_workspace_path(lang))
        .unwrap_or_else(|err| panic!("open {lang} SDK project: {err}"))
}

fn security_cli_args<'a>(workspace: &'a str, subcommand: &'a str, extra: &'a [&'a str]) -> Vec<&'a str> {
    // `--rules-dir` is per-subcommand — it lives under
    // `security <workspace> <subcommand> --rules-dir ...`, not on
    // the parent `security` command.
    let mut args = vec![
        "security",
        workspace,
        subcommand,
        "--rules-dir",
        "security-patterns",
        "--format",
        "json",
    ];
    args.extend_from_slice(extra);
    args
}

fn normalize_json_files(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if matches!(
                    key.as_str(),
                    "file"
                        | "module_path"
                        | "path"
                        | "caller_file"
                        | "callee_file"
                        | "call_file"
                        | "candidate_file"
                        | "module"
                        | "workspace_root"
                        | "evidence_files"
                ) {
                    if let Value::String(path) = child {
                        *path = normalize_path(path);
                    } else if child.is_number() {
                        *child = Value::from(0);
                    } else if let Value::Array(values) = child {
                        for value in values {
                            if let Value::String(path) = value {
                                *path = normalize_path(path);
                            } else {
                                normalize_json_files(value);
                            }
                        }
                    } else {
                        normalize_json_files(child);
                    }
                } else if matches!(
                    key.as_str(),
                    "edge_id" | "node_id" | "candidate_id" | "taint_id" | "trace_id"
                ) {
                    if child.is_string() {
                        *child = Value::String(format!("<{key}>"));
                    }
                } else if matches!(key.as_str(), "generated_at_unix_ms") {
                    if child.is_number() {
                        *child = Value::from(0);
                    }
                } else if matches!(key.as_str(), "seeds" | "sanitizers") {
                    normalize_json_files(child);
                    if let Value::Array(values) = child {
                        values.sort_by_key(|value| value.to_string());
                    }
                } else {
                    normalize_json_files(child);
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                normalize_json_files(child);
            }
        }
        _ => {}
    }
}

fn normalize_path(path: &str) -> String {
    // Strip the absolute prefix the SDK emits when running off
    // an absolute rulepack root, so we compare relative paths
    // (which the CLI prints natively). Both `examples/` and
    // `security-patterns/` are repo-relative anchors.
    for anchor in ["examples/", "security-patterns/"] {
        if let Some(idx) = path.find(anchor) {
            return path[idx..].to_string();
        }
    }
    path.to_string()
}

fn with_cli_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

fn sorted_json_array(mut value: Value) -> Value {
    normalize_json_files(&mut value);
    if let Value::Array(rows) = &mut value {
        rows.sort_by_key(|row| row.to_string());
    }
    value
}

fn normalized_json(mut value: Value) -> Value {
    normalize_json_files(&mut value);
    value
}

fn sorted_rows(value: Value) -> Value {
    sorted_json_array(value)
}

fn json_string_field_values(value: &Value, field: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(text)) = map.get(field) {
                out.push(text.clone());
            }
            for child in map.values() {
                json_string_field_values(child, field, out);
            }
        }
        Value::Array(values) => {
            for child in values {
                json_string_field_values(child, field, out);
            }
        }
        _ => {}
    }
}

fn json_contains_string_field(value: &Value, field: &str, expected: &str) -> bool {
    let mut values = Vec::new();
    json_string_field_values(value, field, &mut values);
    values.iter().any(|value| value == expected)
}

fn assert_json_eq(label: &str, cli: Value, sdk: Value) {
    let cli = normalized_json(cli);
    let sdk = normalized_json(sdk);
    if cli != sdk {
        let diff = json_first_diff(&cli, &sdk, "$")
            .unwrap_or_else(|| "values differ but no first diff was found".to_string());
        panic!("CLI/SDK JSON mismatch for {label}: {diff}");
    }
}

fn assert_json_rows_eq(label: &str, cli: Value, sdk: Value) {
    assert_eq!(
        sorted_rows(cli),
        sorted_rows(sdk),
        "CLI/SDK JSON row mismatch for {label}"
    );
}

fn json_first_diff(left: &Value, right: &Value, path: &str) -> Option<String> {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys = BTreeSet::new();
            keys.extend(left.keys().map(String::as_str));
            keys.extend(right.keys().map(String::as_str));
            for key in keys {
                let child_path = format!("{path}.{key}");
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => {
                        if let Some(diff) = json_first_diff(left, right, &child_path) {
                            return Some(diff);
                        }
                    }
                    (Some(value), None) => {
                        return Some(format!(
                            "{child_path}: only in CLI, value={}",
                            summarize_json(value)
                        ));
                    }
                    (None, Some(value)) => {
                        return Some(format!(
                            "{child_path}: only in SDK, value={}",
                            summarize_json(value)
                        ));
                    }
                    (None, None) => {}
                }
            }
            None
        }
        (Value::Array(left), Value::Array(right)) => {
            let common = left.len().min(right.len());
            for idx in 0..common {
                let child_path = format!("{path}[{idx}]");
                if let Some(diff) = json_first_diff(&left[idx], &right[idx], &child_path) {
                    return Some(diff);
                }
            }
            if left.len() != right.len() {
                return Some(format!(
                    "{path}: array length differs, CLI={} SDK={}",
                    left.len(),
                    right.len()
                ));
            }
            None
        }
        _ if left == right => None,
        _ => Some(format!(
            "{path}: CLI={} SDK={}",
            summarize_json(left),
            summarize_json(right)
        )),
    }
}

fn summarize_json(value: &Value) -> String {
    let text = value.to_string();
    let mut chars = text.chars();
    let summary: String = chars.by_ref().take(400).collect();
    if chars.next().is_some() {
        format!("{summary}...")
    } else {
        summary
    }
}

fn normalized_index_stats(mut value: Value) -> Value {
    // These fields report process-local cache occupancy, not semantic index
    // results. A fresh retrieval/dataflow sidecar can hydrate one process
    // while another computes the same exact facts on demand, so parity
    // compares the stable workspace stats here.
    if let Value::Object(obj) = &mut value {
        obj.remove("cached_cfgs");
        obj.remove("cached_decl_indexes");
    }
    normalized_json(value)
}

fn assert_index_stats_eq(label: &str, cli: Value, sdk: Value) {
    assert_eq!(
        normalized_index_stats(cli),
        normalized_index_stats(sdk),
        "CLI/SDK index stats mismatch for {label}"
    );
}

fn entry_symbol(lang: &str) -> &'static str {
    match lang {
        "csharp" => "HandleRequest",
        "dart" | "java" | "javascript" | "kotlin" | "lua" | "scala" | "solidity" | "swift" | "typescript" => {
            "handleRequest"
        }
        "go" => "HandleRequest",
        "objc" => "handleRequestWithToken",
        _ => "handle_request",
    }
}

fn trace_source_symbol(lang: &str) -> &'static str {
    entry_symbol(lang)
}

fn slice_site(lang: &str) -> (&'static str, u32, &'static str) {
    match lang {
        "c" => ("result", 13, "gateway.c"),
        "cpp" => ("result", 12, "gateway.cpp"),
        "csharp" => ("result", 19, "Gateway.cs"),
        "dart" => ("result", 5, "gateway.dart"),
        "elixir" => ("result", 6, "gateway.ex"),
        "erlang" => ("Result", 6, "gateway.erl"),
        "go" => ("result", 19, "gateway.go"),
        "java" => ("result", 25, "Gateway.java"),
        "javascript" => ("result", 18, "gateway.js"),
        "kotlin" => ("result", 17, "Gateway.kt"),
        "lua" => ("result", 7, "gateway.lua"),
        "objc" => ("result", 12, "Gateway.m"),
        "perl" => ("result", 8, "gateway.pl"),
        "php" => ("$result", 10, "gateway.php"),
        "python" => ("result", 15, "gateway.py"),
        "ruby" => ("result", 16, "gateway.rb"),
        "rust" => ("result", 12, "gateway.rs"),
        "scala" => ("result", 17, "Gateway.scala"),
        "solidity" => ("action", 15, "Gateway.sol"),
        "swift" => ("result", 11, "Gateway.swift"),
        "typescript" => ("result", 18, "gateway.ts"),
        other => panic!("missing slice fixture site for {other}"),
    }
}

fn sdk_taint_json(project: &bonsai_sdk::Project, options: TaintAnalysisOptions) -> Value {
    let report = project
        .security()
        .taint_analysis(options)
        .expect("sdk taint-analysis");
    let mut value = serde_json::to_value(report.findings).expect("serialize SDK findings");
    normalize_json_files(&mut value);
    sorted_json_array(value)
}

fn cli_taint_json(workspace: &str, extra: &[&str]) -> Value {
    let value = run_cli(&security_cli_args(workspace, "taint-analysis", extra));
    sorted_json_array(rows_or_array(value))
}

fn wrapped_rows(value: Value) -> Vec<Value> {
    value
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| panic!("expected paged JSON wrapper, got {value:#}"))
}

fn rows_or_array(value: Value) -> Value {
    match value {
        Value::Object(mut map) => map
            .remove("rows")
            .unwrap_or_else(|| panic!("expected JSON rows or array, got {}", Value::Object(map))),
        other => other,
    }
}

#[test]
fn taint_analysis_cli_flags_map_one_to_one_to_sdk_options() {
    let project = security_project();
    let workspace = "examples/python/micro";

    let cases = [
        ("default/all", vec!["--all"], TaintAnalysisOptions::default()),
        (
            "source regex",
            vec!["--all", "--source", "^python\\.flask\\.request_args_get$"],
            TaintAnalysisOptions {
                source: Some("^python\\.flask\\.request_args_get$".to_string()),
                ..Default::default()
            },
        ),
        (
            "trust",
            vec!["--all", "--trust", "remote"],
            TaintAnalysisOptions {
                trust: Some("remote".to_string()),
                ..Default::default()
            },
        ),
        (
            "category",
            vec!["--all", "--category", "http-input"],
            TaintAnalysisOptions {
                category: Some("http-input".to_string()),
                ..Default::default()
            },
        ),
        (
            "sink regex",
            vec!["--all", "--sink", "^python\\.cmdi\\."],
            TaintAnalysisOptions {
                sink: Some("^python\\.cmdi\\.".to_string()),
                ..Default::default()
            },
        ),
        (
            "severity",
            vec!["--all", "--severity", "critical"],
            TaintAnalysisOptions {
                severity: Some(Severity::Critical),
                ..Default::default()
            },
        ),
        (
            "tag",
            vec!["--all", "--tag", "command-injection"],
            TaintAnalysisOptions {
                tag: Some("command-injection".to_string()),
                ..Default::default()
            },
        ),
        (
            "file include",
            vec!["--all", "--file", "auth_service.py"],
            TaintAnalysisOptions {
                files: vec!["auth_service.py".to_string()],
                ..Default::default()
            },
        ),
        (
            "file exclude",
            vec!["--all", "--exclude-file", "auth_service.py"],
            TaintAnalysisOptions {
                exclude_files: vec!["auth_service.py".to_string()],
                ..Default::default()
            },
        ),
        (
            "rendering no-compact does not affect JSON analysis",
            vec!["--all", "--no-compact"],
            TaintAnalysisOptions::default(),
        ),
    ];

    for (name, cli_extra, sdk_options) in cases {
        let cli = cli_taint_json(workspace, &cli_extra);
        let sdk = sdk_taint_json(&project, sdk_options);
        assert_eq!(cli, sdk, "taint-analysis CLI/SDK mismatch for {name}");
    }
}

#[test]
fn taint_analysis_paged_cli_json_is_a_window_over_sdk_results() {
    let project = security_project();
    let sdk = sdk_taint_json(&project, Default::default());
    let sdk_finding_ids: BTreeSet<String> = sdk
        .as_array()
        .expect("SDK rows")
        .iter()
        .filter_map(|row| row.get("finding_id").and_then(Value::as_str).map(str::to_string))
        .collect();

    for page in ["1", "2"] {
        let mut cli = run_cli(&security_cli_args(
            "examples/python/micro",
            "taint-analysis",
            &["--context", "4k", "--page", page],
        ));
        normalize_json_files(&mut cli);
        for row in wrapped_rows(cli) {
            let finding_id = row
                .get("finding_id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("paged taint-analysis row missing finding_id:\n{row:#}"));
            assert!(
                sdk_finding_ids.contains(finding_id),
                "paged taint-analysis row on page {page} was not present in SDK report:\n{row:#}"
            );
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SourceFlowSig {
    source_rule: String,
    source_file: String,
    source_line: u64,
    source_column: u64,
    chain: Vec<String>,
    additional_sources: Vec<(String, String, u64, u64)>,
}

fn source_site_sig(value: &Value) -> (String, String, u64, u64) {
    (
        value
            .get("rule_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        normalize_path(value.get("file").and_then(Value::as_str).unwrap_or_default()),
        value.get("line").and_then(Value::as_u64).unwrap_or_default(),
        value.get("column").and_then(Value::as_u64).unwrap_or_default(),
    )
}

fn cli_source_sigs(mut value: Value) -> BTreeSet<SourceFlowSig> {
    normalize_json_files(&mut value);
    let rows = value.as_array().expect("source-analysis JSON array");
    rows.iter()
        .map(|row| {
            let source = row.get("source").expect("source");
            let chain = row
                .get("flow")
                .and_then(|flow| flow.get("chain"))
                .and_then(Value::as_array)
                .expect("flow.chain")
                .iter()
                .map(|name| name.as_str().unwrap_or_default().to_string())
                .collect();
            let mut additional_sources: Vec<_> = row
                .get("additional_sources")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(source_site_sig)
                .collect();
            additional_sources.sort();
            SourceFlowSig {
                source_rule: source
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                source_file: normalize_path(source.get("file").and_then(Value::as_str).unwrap_or_default()),
                source_line: source.get("line").and_then(Value::as_u64).unwrap_or_default(),
                source_column: source.get("column").and_then(Value::as_u64).unwrap_or_default(),
                chain,
                additional_sources,
            }
        })
        .collect()
}

fn sdk_source_sigs(project: &bonsai_sdk::Project, options: SourceAnalysisOptions) -> BTreeSet<SourceFlowSig> {
    let report = project
        .security()
        .source_analysis(options)
        .expect("sdk source-analysis");
    report
        .candidates
        .into_iter()
        .map(|candidate| {
            let mut additional_sources: Vec<_> = candidate
                .additional_sources
                .iter()
                .map(|source| {
                    (
                        source.rule_id.clone(),
                        normalize_path(&source.file),
                        u64::from(source.line),
                        u64::from(source.column),
                    )
                })
                .collect();
            additional_sources.sort();
            SourceFlowSig {
                source_rule: candidate.source.rule_id,
                source_file: normalize_path(&candidate.source.file),
                source_line: u64::from(candidate.source.line),
                source_column: u64::from(candidate.source.column),
                chain: candidate.chain_names,
                additional_sources,
            }
        })
        .collect()
}

fn source_analysis_all_options() -> SourceAnalysisOptions {
    SourceAnalysisOptions {
        lineage_limits: SourceLineageLimits::unbounded(),
        ..Default::default()
    }
}

fn cli_source_json(workspace: &str, extra: &[&str]) -> Value {
    rows_or_array(run_cli(&security_cli_args(workspace, "source-analysis", extra)))
}

#[test]
fn index_and_diagnostics_cli_json_match_sdk_for_every_language() {
    for &lang in LANGS {
        let project = basic_project_for_lang(lang);
        let ws_arg = lang_workspace_arg(lang);
        let ws_arg = ws_arg.as_str();

        assert_index_stats_eq(
            &format!("{lang} index"),
            run_cli(&["index", ws_arg]),
            serde_json::to_value(
                bonsai_sdk::Bonsai::new()
                    .index(lang_workspace_path(lang))
                    .unwrap_or_else(|err| panic!("index {lang} SDK project: {err}"))
                    .stats(),
            )
            .expect("stats json"),
        );

        assert_json_eq(
            &format!("{lang} context"),
            run_cli(&["context", ws_arg]),
            serde_json::to_value(project.semantic_context()).expect("context json"),
        );

        for file in project.workspace().vfs().all_files() {
            project
                .workspace()
                .db()
                .parse(file)
                .unwrap_or_else(|err| panic!("{lang} parse diagnostic input: {err}"));
        }
        assert_json_eq(
            &format!("{lang} diagnostics"),
            run_cli(&["diagnostics", ws_arg]),
            serde_json::to_value(project.diagnostics_report()).expect("diagnostics json"),
        );
    }
}

#[test]
fn slice_cli_json_matches_sdk_facade() {
    for &lang in LANGS {
        let project = basic_project_for_lang(lang);
        let ws_arg = lang_workspace_arg(lang);
        let (symbol, line, file) = slice_site(lang);
        let line_s = line.to_string();
        let cli = run_cli(&[
            "slice", &ws_arg, "--symbol", symbol, "--line", &line_s, "--file", file, "--format", "json",
        ]);
        let sdk = serde_json::to_value(project.browse().slices(bonsai_sdk::SliceFilters {
            symbol,
            line,
            file: Some(file),
            ..Default::default()
        }))
        .expect("slice json");
        assert_json_eq(&format!("{lang} slice"), cli.clone(), sdk);
        let slices = cli
            .get("slices")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{lang} slice JSON missing slices array:\n{cli:#}"));
        assert!(
            slices.iter().any(|slice| slice
                .get("step_count")
                .and_then(Value::as_u64)
                .unwrap_or_default()
                > 0),
            "{lang} slice parity must exercise a non-empty syntax-derived slice:\n{cli:#}"
        );
    }
}

#[test]
fn cache_commands_cli_json_match_sdk_facade() {
    let root = temp_workspace("cache");
    let root_arg = root.to_str().expect("temp workspace path utf8");
    let bonsai = sdk();

    let project = bonsai.open_query(&root).expect("open temp project");
    project
        .cache()
        .rebuild_dataflow()
        .expect("write dataflow sidecar");
    let stats = project.cache().stats().expect("SDK cache stats");
    assert!(
        stats.dataflow_factstore_sidecar_exists && !stats.dataflow_sidecar_exists,
        "fixture should have only the canonical dataflow factstore before clear: {stats:#?}"
    );
    assert_json_eq(
        "cache stats after SDK dataflow rebuild",
        run_cli(&["cache", "stats", root_arg, "--format", "json"]),
        serde_json::to_value(stats).expect("cache stats json"),
    );

    run_cli_text(&["cache", "clear", root_arg, "--dataflow-only"]);
    let stats = bonsai
        .cache(&root)
        .stats()
        .expect("SDK cache stats after dataflow clear");
    assert!(
        !stats.dataflow_sidecar_exists && !stats.dataflow_factstore_sidecar_exists,
        "CLI cache clear --dataflow-only should remove only dataflow sidecars: {stats:#?}"
    );

    run_cli_text(&["cache", "rebuild", root_arg]);
    let stats = bonsai
        .cache(&root)
        .stats()
        .expect("SDK cache stats after CLI rebuild");
    assert!(
        stats.callgraph_sidecar_exists && stats.callgraph_sidecar_bytes > 0,
        "CLI cache rebuild should write the callgraph sidecar visible to SDK: {stats:#?}"
    );
    assert!(
        stats.idg_sidecar_exists && stats.idg_sidecar_bytes > 0,
        "CLI cache rebuild should write the IDG sidecar visible to SDK: {stats:#?}"
    );
    assert!(
        !stats.dataflow_sidecar_exists && !stats.dataflow_factstore_sidecar_exists,
        "CLI cache rebuild should not run full dataflow prewarm: {stats:#?}"
    );
    assert!(
        !stats.export_sidecar_exists,
        "CLI cache rebuild should warm export only with --export: {stats:#?}"
    );
    assert_json_eq(
        "cache stats after CLI rebuild",
        run_cli(&["cache", "stats", root_arg, "--format", "json"]),
        serde_json::to_value(&stats).expect("cache stats json"),
    );

    run_cli_text(&["cache", "clear", root_arg]);
    let stats = bonsai
        .cache(&root)
        .stats()
        .expect("SDK cache stats after CLI clear");
    assert!(
        !stats.bonsai_dir_exists,
        "CLI cache clear should remove the SDK-visible .bonsai directory: {stats:#?}"
    );
    assert_json_eq(
        "cache stats after CLI clear",
        run_cli(&["cache", "stats", root_arg, "--format", "json"]),
        serde_json::to_value(&stats).expect("cache stats json"),
    );

    let stats = bonsai
        .rebuild_structural_cache(&root, true)
        .expect("SDK structural cache rebuild with export");
    assert!(
        stats.callgraph_sidecar_exists && stats.idg_sidecar_exists && stats.export_sidecar_exists,
        "SDK rebuild with export should write the bounded sidecars CLI reports: {stats:#?}"
    );
    assert!(
        !stats.dataflow_sidecar_exists && !stats.dataflow_factstore_sidecar_exists,
        "SDK structural rebuild should match CLI rebuild and avoid full dataflow prewarm: {stats:#?}"
    );
    assert_json_eq(
        "cache stats after SDK rebuild",
        run_cli(&["cache", "stats", root_arg, "--format", "json"]),
        serde_json::to_value(stats).expect("cache stats json"),
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn source_analysis_cli_flags_map_one_to_one_to_sdk_options() {
    let project = security_project();
    let workspace = "examples/python/micro";

    let cases = [
        ("default/all", vec!["--all"], source_analysis_all_options()),
        (
            "source regex",
            vec!["--all", "--source", "^python\\.flask\\."],
            SourceAnalysisOptions {
                source: Some("^python\\.flask\\.".to_string()),
                ..source_analysis_all_options()
            },
        ),
        (
            "trust",
            vec!["--all", "--trust", "remote"],
            SourceAnalysisOptions {
                trust: Some("remote".to_string()),
                ..source_analysis_all_options()
            },
        ),
        (
            "category",
            vec!["--all", "--category", "inferred"],
            SourceAnalysisOptions {
                category: Some("inferred".to_string()),
                ..source_analysis_all_options()
            },
        ),
        (
            "tag",
            vec!["--all", "--tag", "http-input"],
            SourceAnalysisOptions {
                tag: Some("http-input".to_string()),
                ..source_analysis_all_options()
            },
        ),
        (
            "file include",
            vec!["--all", "--file", "gateway.py"],
            SourceAnalysisOptions {
                files: vec!["gateway.py".to_string()],
                ..source_analysis_all_options()
            },
        ),
        (
            "file exclude",
            vec!["--all", "--exclude-file", "gateway.py"],
            SourceAnalysisOptions {
                exclude_files: vec!["gateway.py".to_string()],
                ..source_analysis_all_options()
            },
        ),
        (
            "rendering no-compact does not affect JSON analysis",
            vec!["--all", "--no-compact"],
            source_analysis_all_options(),
        ),
    ];

    for (name, cli_extra, sdk_options) in cases {
        let cli = cli_source_sigs(cli_source_json(workspace, &cli_extra));
        if name == "file include" {
            assert_eq!(
                cli.len(),
                1,
                "source-analysis CLI file include should render one path-scoped source row"
            );
            let row = cli.iter().next().expect("one source row");
            assert_eq!(row.source_file, "examples/python/micro/gateway.py");
            assert_eq!(row.chain, vec!["handle_request".to_string()]);
            continue;
        }
        let sdk = match name {
            "file exclude" => {
                let filtered = sdk()
                    .open_query_filtered_paths(workspace_path(), &[], &["gateway.py".to_string()])
                    .expect("open SDK filtered source-analysis exclude project");
                sdk_source_sigs(&filtered, sdk_options)
            }
            _ => sdk_source_sigs(&project, sdk_options),
        };
        assert_eq!(cli, sdk, "source-analysis CLI/SDK mismatch for {name}");
    }
}

#[test]
fn source_analysis_paged_cli_json_is_a_window_over_sdk_results() {
    let project = security_project();
    let sdk = sdk_source_sigs(&project, Default::default());

    for page in ["1", "2"] {
        let cli = run_cli(&security_cli_args(
            "examples/python/micro",
            "source-analysis",
            &["--context", "4k", "--page", page],
        ));
        let wrapped = Value::Array(wrapped_rows(cli));
        for row in cli_source_sigs(wrapped) {
            assert!(
                sdk.contains(&row),
                "paged source-analysis row on page {page} was not present in SDK report:\n{row:#?}"
            );
        }
    }
}

#[test]
fn security_analysis_cli_json_matches_sdk_for_every_language() {
    for &lang in LANGS {
        let project = security_project_for_lang(lang);
        let workspace = lang_workspace_arg(lang);

        let cli_taint = cli_taint_json(&workspace, &["--all"]);
        let sdk_taint = sdk_taint_json(&project, Default::default());
        assert_eq!(cli_taint, sdk_taint, "{lang} taint-analysis CLI/SDK mismatch");

        let cli_source = cli_source_sigs(cli_source_json(&workspace, &["--all"]));
        let sdk_source = sdk_source_sigs(&project, Default::default());
        assert_eq!(cli_source, sdk_source, "{lang} source-analysis CLI/SDK mismatch");
    }
}

#[test]
fn security_inventory_cli_json_matches_sdk_for_every_language() {
    for &lang in LANGS {
        let project = security_project_for_lang(lang);
        let workspace = lang_workspace_arg(lang);

        assert_json_rows_eq(
            &format!("{lang} security sources"),
            rows_or_array(run_cli(&security_cli_args(&workspace, "sources", &["--all"]))),
            serde_json::to_value(
                project
                    .security()
                    .source_rows(Default::default())
                    .unwrap_or_else(|err| panic!("{lang} sdk sources: {err}")),
            )
            .expect("sources json"),
        );

        assert_json_rows_eq(
            &format!("{lang} security sinks"),
            rows_or_array(run_cli(&security_cli_args(&workspace, "sinks", &["--all"]))),
            serde_json::to_value(
                project
                    .security()
                    .sink_rows(Default::default())
                    .unwrap_or_else(|err| panic!("{lang} sdk sinks: {err}")),
            )
            .expect("sinks json"),
        );

        assert_json_rows_eq(
            &format!("{lang} security sanitizers"),
            rows_or_array(run_cli(&security_cli_args(&workspace, "sanitizers", &["--all"]))),
            serde_json::to_value(
                project
                    .security()
                    .sanitizer_rows(Default::default())
                    .unwrap_or_else(|err| panic!("{lang} sdk sanitizers: {err}")),
            )
            .expect("sanitizers json"),
        );

        assert_json_rows_eq(
            &format!("{lang} security deps"),
            rows_or_array(run_cli(&security_cli_args(&workspace, "deps", &["--all"]))),
            serde_json::to_value(
                project
                    .security()
                    .deps(Default::default())
                    .unwrap_or_else(|err| panic!("{lang} sdk deps: {err}"))
                    .rows,
            )
            .expect("deps json"),
        );
    }
}

#[test]
fn security_pack_cli_json_matches_sdk() {
    let sdk = sdk();
    let pack = sdk.security_pack().expect("SDK security pack");
    let workspace = "examples/python/micro";

    assert_json_rows_eq(
        "security pack",
        rows_or_array(run_cli(&security_cli_args(workspace, "pack", &["--all"]))),
        serde_json::to_value(pack.inventory(Default::default()).expect("pack inventory")).expect("pack json"),
    );

    assert_json_eq(
        "security pack --audit",
        run_cli(&security_cli_args(workspace, "pack", &["--audit"])),
        serde_json::to_value(pack.audit(None).expect("pack audit")).expect("audit json"),
    );

    assert_json_eq(
        "security pack --tree",
        run_cli(&security_cli_args(workspace, "pack", &["--tree", "--all"])),
        serde_json::to_value(pack.tree(Default::default()).expect("pack tree")).expect("tree json"),
    );

    assert_json_eq(
        "security pack --validate",
        run_cli(&security_cli_args(workspace, "pack", &["--validate"])),
        serde_json::to_value(pack.validate(Default::default()).expect("pack validation"))
            .expect("validation json"),
    );
}

#[test]
fn browse_fact_commands_cli_json_match_sdk_for_every_language() {
    for &lang in LANGS {
        let project = security_project_for_lang(lang);
        let ws_arg = lang_workspace_arg(lang);
        let ws_arg = ws_arg.as_str();

        let cases: Vec<(&str, Vec<&str>, Value)> = vec![
            (
                "defs",
                vec!["defs", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(project.browse().defs(Default::default()).expect("sdk defs"))
                    .expect("defs json"),
            ),
            (
                "calls",
                vec!["calls", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(project.browse().calls(Default::default()).expect("sdk calls"))
                    .expect("calls json"),
            ),
            (
                "entrypoints",
                vec!["entrypoints", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(
                    project
                        .browse()
                        .entrypoints(Default::default())
                        .expect("sdk entrypoints"),
                )
                .expect("entrypoints json"),
            ),
            (
                "imports",
                vec!["imports", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(project.browse().imports(Default::default()).expect("sdk imports"))
                    .expect("imports json"),
            ),
            (
                "vars",
                vec!["vars", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(project.browse().vars(Default::default()).expect("sdk vars"))
                    .expect("vars json"),
            ),
            (
                "strings",
                vec!["strings", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(project.browse().strings(Default::default()).expect("sdk strings"))
                    .expect("strings json"),
            ),
            (
                "comments",
                vec!["comments", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(
                    project
                        .browse()
                        .comments(Default::default())
                        .expect("sdk comments"),
                )
                .expect("comments json"),
            ),
            (
                "args",
                vec!["args", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(project.browse().args(Default::default()).expect("sdk args"))
                    .expect("args json"),
            ),
            (
                "operations",
                vec!["operations", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(
                    project
                        .browse()
                        .operations(Default::default())
                        .expect("sdk operations"),
                )
                .expect("operations json"),
            ),
            (
                "classes",
                vec!["classes", ws_arg, "--format", "json", "--all"],
                serde_json::to_value(project.browse().classes(Default::default()).expect("sdk classes"))
                    .expect("classes json"),
            ),
            (
                "refs --regex",
                vec![
                    "refs",
                    ws_arg,
                    "(?i)token",
                    "--regex",
                    "--format",
                    "json",
                    "--all",
                ],
                serde_json::to_value(
                    project
                        .browse()
                        .refs(
                            "(?i)token",
                            bonsai_sdk::RefsFilters {
                                regex: true,
                                ..Default::default()
                            },
                        )
                        .expect("sdk refs"),
                )
                .expect("refs json"),
            ),
            (
                "search",
                vec!["search", ws_arg, "token", "--format", "json", "--all"],
                serde_json::to_value(
                    project
                        .browse()
                        .search("token", Default::default(), usize::MAX)
                        .expect("sdk search"),
                )
                .expect("search json"),
            ),
        ];

        for (name, args, sdk) in cases {
            let cli = run_cli(&args);
            assert_json_rows_eq(&format!("{lang} {name}"), cli, sdk);
        }
    }
}

#[test]
fn navigation_cli_json_matches_sdk_facade() {
    let project = security_project();
    let workspace = "examples/python/micro";

    assert_json_eq(
        "python semantic tree",
        run_cli(&[
            "tree",
            workspace,
            "--rules-dir",
            "security-patterns",
            "--all",
            "--format",
            "json",
        ]),
        serde_json::to_value(
            project
                .browse()
                .tree(bonsai_sdk::TreeFilters {
                    limit: 0,
                    max_finding_ids_per_file: Some(0),
                    max_flow_ids_per_file: Some(0),
                    max_cross_file_edges_per_file: Some(0),
                    ..Default::default()
                })
                .expect("sdk tree"),
        )
        .expect("tree json"),
    );

    assert_json_eq(
        "python read-file",
        run_cli(&[
            "read-file",
            workspace,
            "gateway.py",
            "--rules-dir",
            "security-patterns",
            "--all",
            "--format",
            "json",
        ]),
        serde_json::to_value(
            project
                .browse()
                .read_file(bonsai_sdk::ReadFileFilters {
                    path: "gateway.py",
                    max_inlined_bodies: Some(0),
                    ..Default::default()
                })
                .expect("sdk read-file"),
        )
        .expect("read-file json"),
    );
}

fn inspect_decl_flow_ids(value: &Value, target: &str) -> BTreeSet<String> {
    value
        .get("decl_hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|hit| hit.get("symbol").and_then(Value::as_str) == Some(target))
        .flat_map(|hit| hit.get("flows").and_then(Value::as_array).into_iter().flatten())
        .filter_map(|flow| flow.get("flow_id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

fn inspect_decl_group_ids(value: &Value, target: &str) -> BTreeSet<String> {
    value
        .get("decl_hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|hit| hit.get("symbol").and_then(Value::as_str) == Some(target))
        .flat_map(|hit| hit.get("groups").and_then(Value::as_array).into_iter().flatten())
        .filter_map(|group| group.get("group_id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

#[test]
fn inspect_structural_flow_ids_match_sdk_facade() {
    let project = basic_project_for_lang("python");
    let workspace = "examples/python/micro";
    let target = "run_admin_command";
    let cli = run_cli(&[
        "inspect", workspace, "--query", target, "--format", "json", "--all",
    ]);
    let sdk_targets = project
        .inspect()
        .chains(bonsai_sdk::InspectQuery {
            pattern: Some(target),
            max_chains: usize::MAX,
            max_probes: usize::MAX,
            ..Default::default()
        })
        .expect("sdk inspect chains");
    let sdk_target = sdk_targets
        .iter()
        .find(|item| item.target == target)
        .unwrap_or_else(|| panic!("SDK inspect target `{target}` missing: {sdk_targets:#?}"));
    let sdk_flow_ids: BTreeSet<String> = sdk_target
        .chains
        .iter()
        .map(|chain| chain.flow_id.clone())
        .collect();
    let sdk_group_ids: BTreeSet<String> = sdk_target
        .groups
        .iter()
        .map(|group| group.group_id.clone())
        .collect();

    assert_eq!(
        inspect_decl_flow_ids(&cli, target),
        sdk_flow_ids,
        "CLI inspect structural flow ids must match SDK inspect chains:\n{cli:#}"
    );
    assert_eq!(
        inspect_decl_group_ids(&cli, target),
        sdk_group_ids,
        "CLI inspect grouped flow ids must match SDK inspect groups:\n{cli:#}"
    );
}

#[test]
fn show_structural_ids_roundtrip_through_cli_and_sdk() {
    let project = security_project();
    let workspace = "examples/python/micro";
    let edge = project
        .dump()
        .edges(Default::default())
        .into_iter()
        .next()
        .expect("fixture should emit at least one edge");
    match project
        .show()
        .by_id(&edge.edge_id, Default::default())
        .expect("sdk show E:")
    {
        bonsai_sdk::ShowOutcome::Edge(row) => assert_eq!(row.edge_id, edge.edge_id),
        other => panic!("expected SDK Edge outcome, got {other:?}"),
    }
    let cli_edge = run_cli(&["show", workspace, &edge.edge_id, "--format", "json", "--all"]);
    assert!(
        json_contains_string_field(&cli_edge, "edge_id", &edge.edge_id),
        "CLI show E: JSON should contain reopened edge id {}; got:\n{cli_edge:#}",
        edge.edge_id
    );

    let ast_root = match project.dump().ast(bonsai_sdk::AstFilters {
        function: Some("handle_request"),
        max_depth: Some(0),
        ..Default::default()
    }) {
        bonsai_sdk::AstOutcome::Dumps(mut dumps) => dumps.pop().expect("AST dump"),
        bonsai_sdk::AstOutcome::NodeIdNotFound => panic!("function AST should exist"),
    };
    let node_id = ast_root.root.node_id.clone();
    match project
        .show()
        .by_id(
            &node_id,
            bonsai_sdk::ShowOptions {
                ast_function: Some("handle_request"),
                ast_max_depth: Some(0),
                ..Default::default()
            },
        )
        .expect("sdk show N:")
    {
        bonsai_sdk::ShowOutcome::AstNode(row) => assert_eq!(row.root.node_id, node_id),
        other => panic!("expected SDK AstNode outcome, got {other:?}"),
    }
    let cli_node = run_cli(&["show", workspace, &node_id, "--format", "json", "--all"]);
    assert!(
        json_contains_string_field(&cli_node, "node_id", &node_id),
        "CLI show N: JSON should contain reopened node id {node_id}; got:\n{cli_node:#}"
    );

    let candidate_id = match project.dump().resolve("handle_request", Default::default()) {
        bonsai_sdk::ResolveOutcome::Trace(trace) => trace
            .candidates
            .first()
            .expect("resolver candidate")
            .candidate_id
            .clone(),
        other => panic!("expected resolver trace, got {other:?}"),
    };
    match project
        .show()
        .by_id(
            &candidate_id,
            bonsai_sdk::ShowOptions {
                query: Some("handle_request"),
                ..Default::default()
            },
        )
        .expect("sdk show R:")
    {
        bonsai_sdk::ShowOutcome::ResolverCandidate(trace) => {
            assert_eq!(trace.candidates.len(), 1);
            assert_eq!(trace.candidates[0].candidate_id, candidate_id);
        }
        other => panic!("expected SDK ResolverCandidate outcome, got {other:?}"),
    }
    let cli_candidate = run_cli(&[
        "show",
        workspace,
        &candidate_id,
        "--query",
        "handle_request",
        "--format",
        "json",
    ]);
    assert!(
        json_contains_string_field(&cli_candidate, "candidate_id", &candidate_id),
        "CLI show R: JSON should contain reopened candidate id {candidate_id}; got:\n{cli_candidate:#}"
    );

    let targets = project
        .inspect()
        .chains(bonsai_sdk::InspectQuery {
            pattern: Some("handle_request"),
            max_chains: usize::MAX,
            max_probes: usize::MAX,
            ..Default::default()
        })
        .expect("sdk inspect chains");
    let target = targets
        .iter()
        .find(|target| !target.chains.is_empty() && !target.groups.is_empty())
        .expect("fixture should emit inspect chains and groups");

    let flow_id = target.chains[0].flow_id.clone();
    match project
        .show()
        .by_id(&flow_id, Default::default())
        .expect("sdk show F:")
    {
        bonsai_sdk::ShowOutcome::InspectFlow(flow) => {
            assert_eq!(flow.flow_id, flow_id);
            assert!(flow
                .matches
                .iter()
                .any(|matched| matched.chain.flow_id == flow_id));
        }
        other => panic!("expected SDK InspectFlow outcome, got {other:?}"),
    }
    let cli_flow = run_cli(&["show", workspace, &flow_id, "--format", "json", "--all"]);
    assert!(
        json_contains_string_field(&cli_flow, "flow_id", &flow_id),
        "CLI show F: JSON should contain reopened flow id {flow_id}; got:\n{cli_flow:#}"
    );

    let group = &target.groups[0];
    let group_id = group.group_id.clone();
    let expected_member = group
        .member_flow_ids
        .first()
        .expect("group should have member flow ids")
        .clone();
    match project
        .show()
        .by_id(&group_id, Default::default())
        .expect("sdk show G:")
    {
        bonsai_sdk::ShowOutcome::InspectFlowGroup(group) => {
            assert_eq!(group.group_id, group_id);
            assert!(group.matches.iter().any(|matched| {
                matched.group.group_id == group_id
                    && matched
                        .chains
                        .iter()
                        .any(|chain| chain.flow_id == expected_member)
            }));
        }
        other => panic!("expected SDK InspectFlowGroup outcome, got {other:?}"),
    }
    let cli_group = run_cli(&["show", workspace, &group_id, "--format", "json", "--all"]);
    assert!(
        json_contains_string_field(&cli_group, "group_id", &group_id),
        "CLI show G: JSON should contain reopened group id {group_id}; got:\n{cli_group:#}"
    );
    assert!(
        json_contains_string_field(&cli_group, "flow_id", &expected_member),
        "CLI show G: JSON should contain member flow id {expected_member}; got:\n{cli_group:#}"
    );

    let taint = match project.dump().taint(bonsai_sdk::TaintFilters {
        source: "update_user",
        seeds: vec!["token".into(), "action".into()],
        ..Default::default()
    }) {
        bonsai_sdk::TaintOutcome::Report(report) => report,
        other => panic!("expected taint report, got {other:?}"),
    };
    let taint_id = taint
        .records
        .first()
        .expect("fixture should emit a T: propagation id")
        .taint_id
        .clone();
    match project
        .show()
        .by_id(
            &taint_id,
            bonsai_sdk::ShowOptions {
                taint_source: Some("update_user"),
                taint_seeds: &["token", "action"],
                ..Default::default()
            },
        )
        .expect("sdk show T:")
    {
        bonsai_sdk::ShowOutcome::TaintPropagation(report) => {
            assert_eq!(report.records.len(), 1);
            assert_eq!(report.records[0].taint_id, taint_id);
        }
        other => panic!("expected SDK TaintPropagation outcome, got {other:?}"),
    }
    let cli_taint = run_cli(&[
        "show",
        workspace,
        &taint_id,
        "--taint-source",
        "update_user",
        "--taint-seed",
        "token",
        "--taint-seed",
        "action",
        "--format",
        "json",
        "--all",
    ]);
    assert!(
        json_contains_string_field(&cli_taint, "taint_id", &taint_id),
        "CLI show T: JSON should contain reopened taint id {taint_id}; got:\n{cli_taint:#}"
    );

    let security = project
        .security()
        .taint_analysis(bonsai_sdk::TaintAnalysisOptions {
            include_pattern_only: true,
            show_sanitized: true,
            ..Default::default()
        })
        .expect("security findings");
    let finding_id = security
        .findings
        .first()
        .expect("fixture should emit at least one security finding")
        .finding
        .finding_id
        .clone();
    let security_group_id = security
        .findings
        .first()
        .and_then(|finding| finding.finding.group_id.clone())
        .expect("fixture should emit a security group id");
    match project
        .show()
        .by_id(&finding_id, Default::default())
        .expect("sdk show S:")
    {
        bonsai_sdk::ShowOutcome::SecurityFinding(finding) => {
            assert_eq!(finding.finding.finding_id, finding_id);
        }
        other => panic!("expected SDK SecurityFinding outcome, got {other:?}"),
    }
    let cli_finding = run_cli(&[
        "show",
        workspace,
        &finding_id,
        "--rules-dir",
        "security-patterns",
        "--format",
        "json",
        "--all",
    ]);
    assert!(
        json_contains_string_field(&cli_finding, "finding_id", &finding_id),
        "CLI show S: JSON should contain reopened finding id {finding_id}; got:\n{cli_finding:#}"
    );

    match project
        .show()
        .by_id(&security_group_id, Default::default())
        .expect("sdk show security G:")
    {
        bonsai_sdk::ShowOutcome::SecurityFindingGroup(group) => {
            assert_eq!(group.group_id, security_group_id.as_str());
        }
        other => panic!("expected SDK SecurityFindingGroup outcome, got {other:?}"),
    }
    let cli_group = run_cli(&[
        "show",
        workspace,
        &security_group_id,
        "--rules-dir",
        "security-patterns",
        "--format",
        "json",
        "--all",
    ]);
    assert!(
        json_contains_string_field(&cli_group, "group_id", &security_group_id),
        "CLI show G: JSON should contain reopened security group id {security_group_id}; got:\n{cli_group:#}"
    );
}

#[test]
fn dump_and_trace_commands_cli_json_match_sdk_for_every_language() {
    for &lang in LANGS {
        let project = security_project_for_lang(lang);
        let ws_arg = lang_workspace_arg(lang);
        let ws_arg = ws_arg.as_str();
        let entry = entry_symbol(lang);

        assert_json_eq(
            &format!("{lang} dump-hir"),
            run_cli(&["dump-hir", ws_arg, entry]),
            serde_json::to_value(
                project
                    .dump()
                    .hir(entry)
                    .expect("sdk dump-hir")
                    .expect("sdk dump-hir found"),
            )
            .expect("hir json"),
        );
        assert_json_eq(
            &format!("{lang} dump-cfg"),
            run_cli(&["dump-cfg", ws_arg, entry]),
            serde_json::to_value(
                project
                    .dump()
                    .cfg(entry)
                    .expect("sdk dump-cfg")
                    .expect("sdk dump-cfg found"),
            )
            .expect("cfg json"),
        );
        assert_json_rows_eq(
            &format!("{lang} dump-callgraph"),
            run_cli(&["dump-callgraph", ws_arg, "--format", "json", "--all"]),
            serde_json::to_value(project.dump().callgraph()).expect("callgraph json"),
        );
        assert_json_rows_eq(
            &format!("{lang} dump-edges"),
            run_cli(&["dump-edges", ws_arg, "--format", "json", "--all"]),
            serde_json::to_value(project.dump().edges(Default::default())).expect("edges json"),
        );
        assert_json_rows_eq(
            &format!("{lang} dump-resolution"),
            run_cli(&["dump-resolution", ws_arg, "--format", "json", "--all"]),
            serde_json::to_value(project.dump().resolution_coverage(Default::default()))
                .expect("resolution coverage json"),
        );
        assert_json_eq(
            &format!("{lang} path"),
            run_cli(&[
                "path", ws_arg, "--from", entry, "--to", "verify", "--format", "json",
            ]),
            serde_json::to_value(
                project
                    .browse()
                    .paths(bonsai_sdk::PathFilters {
                        from: entry,
                        to: "verify",
                        ..Default::default()
                    })
                    .expect("sdk path"),
            )
            .expect("path json"),
        );
        let ast = match project.dump().ast(bonsai_sdk::AstFilters {
            function: Some(entry),
            max_depth: Some(3),
            ..Default::default()
        }) {
            bonsai_sdk::AstOutcome::Dumps(dumps) => dumps,
            bonsai_sdk::AstOutcome::NodeIdNotFound => panic!("{lang} sdk dump-ast node not found"),
        };
        assert_json_rows_eq(
            &format!("{lang} dump-ast"),
            run_cli(&[
                "dump-ast",
                ws_arg,
                "--function",
                entry,
                "--max-depth",
                "3",
                "--format",
                "json",
                "--all",
            ]),
            serde_json::to_value(ast).expect("ast json"),
        );

        let resolve =
            match project
                .dump()
                .resolve_with_suggestions(entry, Default::default(), |workspace, query| {
                    let matcher = bonsai_sdk::Matcher::build(Some(query), false).expect("matcher");
                    bonsai_sdk::matching_decls(workspace, &matcher)
                        .into_iter()
                        .take(5)
                        .map(|decl| decl.name)
                        .collect()
                }) {
                bonsai_sdk::ResolveOutcome::Trace(trace) => trace,
                bonsai_sdk::ResolveOutcome::FileContextNotFound { needle } => {
                    panic!("{lang} sdk dump-resolve file context not found: {needle}")
                }
                bonsai_sdk::ResolveOutcome::CandidateNotFound => {
                    panic!("{lang} sdk dump-resolve candidate not found")
                }
            };
        assert_json_eq(
            &format!("{lang} dump-resolve"),
            run_cli(&["dump-resolve", ws_arg, entry, "--format", "json"]),
            serde_json::to_value(resolve).expect("resolve json"),
        );

        let taint = match project.dump().taint(bonsai_sdk::TaintFilters {
            source: entry,
            ..Default::default()
        }) {
            bonsai_sdk::TaintOutcome::Report(report) => report,
            bonsai_sdk::TaintOutcome::SourceNotFound => panic!("{lang} sdk dump-taint source not found"),
            bonsai_sdk::TaintOutcome::SourceAmbiguous { candidates, .. } => {
                panic!(
                    "{lang} sdk dump-taint source ambiguous: {} candidates",
                    candidates.len()
                )
            }
            bonsai_sdk::TaintOutcome::TaintIdNotFound => panic!("{lang} sdk dump-taint id not found"),
        };
        assert_json_eq(
            &format!("{lang} dump-taint"),
            run_cli(&["dump-taint", ws_arg, "--source", entry, "--format", "json"]),
            serde_json::to_value(taint).expect("taint json"),
        );

        let trace_symbol = trace_source_symbol(lang);
        assert_json_eq(
            &format!("{lang} trace"),
            run_cli(&["trace", ws_arg, trace_symbol, "--format", "json"]),
            serde_json::to_value(
                project
                    .trace()
                    .from(trace_symbol)
                    .unwrap_or_else(|err| panic!("{lang} sdk trace_from {trace_symbol}: {err}")),
            )
            .expect("trace json"),
        );
    }
}

#[test]
fn export_graph_database_formats_cli_match_sdk_for_every_language() {
    for &lang in LANGS {
        let project = no_dataflow_project_for_lang(lang);
        let ws_path = lang_workspace_path(lang);
        let ws_arg = ws_path.to_str().expect("workspace path utf8");

        let cases = [
            ("networkx", bonsai_sdk::GraphExportFormat::Networkx),
            ("graphml", bonsai_sdk::GraphExportFormat::Graphml),
            ("cypher", bonsai_sdk::GraphExportFormat::Cypher),
        ];
        for (cli_format, sdk_format) in cases {
            let cli = run_cli_stdout_no_dataflow(&["export", ws_arg, "--format", cli_format]);
            let sdk = with_cli_newline(
                project
                    .export()
                    .graph(sdk_format)
                    .unwrap_or_else(|err| panic!("{lang} sdk export --format {cli_format}: {err}")),
            );
            assert_eq!(cli, sdk, "{lang} export --format {cli_format} CLI/SDK mismatch");

            if cli_format == "networkx" {
                let parsed: Value = serde_json::from_str(&cli)
                    .unwrap_or_else(|err| panic!("{lang} invalid networkx JSON: {err}"));
                assert_eq!(parsed["directed"], true);
                assert_eq!(parsed["multigraph"], true);
                assert!(
                    parsed["nodes"].as_array().is_some_and(|nodes| !nodes.is_empty()),
                    "{lang} networkx export has no nodes"
                );
                assert!(
                    parsed["links"].as_array().is_some_and(|links| !links.is_empty()),
                    "{lang} networkx export has no links"
                );
            } else if cli_format == "graphml" {
                assert!(
                    cli.starts_with("<?xml"),
                    "{lang} graphml export missing XML header"
                );
                assert!(
                    cli.contains("<graphml"),
                    "{lang} graphml export missing graphml root"
                );
                assert!(cli.contains("<node "), "{lang} graphml export missing nodes");
                assert!(cli.contains("<edge "), "{lang} graphml export missing edges");
            } else {
                assert!(
                    cli.contains("CREATE CONSTRAINT bonsai_node_id"),
                    "{lang} cypher export missing constraint"
                );
                assert!(
                    cli.contains("MERGE (n:"),
                    "{lang} cypher export missing node merges"
                );
                assert!(
                    cli.contains("MERGE (a)-[r:"),
                    "{lang} cypher export missing edge merges"
                );
            }
        }
    }
}

#[test]
fn native_export_json_cli_matches_sdk_for_every_language() {
    for &lang in LANGS {
        let project = security_project_for_lang(lang);
        let ws_path = lang_workspace_path(lang);
        let ws_arg = ws_path.to_str().expect("workspace path utf8");

        let cli = run_cli(&["export", ws_arg]);
        let sdk = project
            .export()
            .native_json(bonsai_sdk::NativeExportOptions {
                full_propagations: false,
                complete_chains: false,
                compiled_propagations: false,
            })
            .unwrap_or_else(|err| panic!("{lang} sdk native export: {err}"));
        assert_json_eq(&format!("{lang} native export"), cli, sdk);
    }
}

#[test]
fn bundled_sdk_registry_matches_cli_supported_language_surface() {
    let adapters = bonsai_adapters::all_adapters();
    let languages: BTreeSet<_> = adapters
        .iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect();
    assert_eq!(
        languages,
        BTreeSet::from([
            "c".to_string(),
            "cpp".to_string(),
            "csharp".to_string(),
            "dart".to_string(),
            "elixir".to_string(),
            "erlang".to_string(),
            "go".to_string(),
            "java".to_string(),
            "javascript".to_string(),
            "kotlin".to_string(),
            "lua".to_string(),
            "objc".to_string(),
            "perl".to_string(),
            "php".to_string(),
            "python".to_string(),
            "ruby".to_string(),
            "rust".to_string(),
            "scala".to_string(),
            "solidity".to_string(),
            "swift".to_string(),
            "typescript".to_string(),
        ])
    );
}
