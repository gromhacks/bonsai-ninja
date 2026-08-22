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
    repo_root().join("examples/python/micro")
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

#[test]
fn leaf_help_names_the_full_command_and_documents_global_options() {
    let top_level = [
        "index",
        "context",
        "trace",
        "path",
        "slice",
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
        "inspect",
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
            "trace",
            "USAGE: bonsai-ninja trace [OPTIONS] <WORKSPACE> [TARGET]",
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
        vec!["--memory-budget", "1024", "inspect", "--help"],
        vec!["--theme=dracula", "search", "--help"],
        vec!["inspect", "--query", "target", "--help"],
    ] {
        let help = stdout(&args);
        let command = if args.contains(&"search") {
            "search"
        } else {
            "inspect"
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
    let help = stdout(&["inspect", "--help"]);
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
        serde_json::from_str(&stdout(&["index", root_text])).expect("default index JSON");
    assert_eq!(default_index["files"], 1);
    assert_eq!(default_index["include_minified_sources"], false);
    let inclusive_index: serde_json::Value =
        serde_json::from_str(&stdout(&["index", root_text, "--minified-js"])).expect("inclusive index JSON");
    assert_eq!(inclusive_index["files"], 2);
    assert_eq!(inclusive_index["include_minified_sources"], true);
    let inclusive_warm: serde_json::Value =
        serde_json::from_str(&stdout(&["index", root_text, "--minified-js"]))
            .expect("warm inclusive index JSON");
    assert_eq!(inclusive_warm["compiler_cache"], "hit");
    assert_eq!(inclusive_warm["files"], 2);
    assert_eq!(inclusive_warm["include_minified_sources"], true);

    let inclusive_semantic: serde_json::Value =
        serde_json::from_str(&stdout(&["index", root_text, "--semantic", "--minified-js"]))
            .expect("inclusive semantic index JSON");
    assert_eq!(inclusive_semantic["files"], 2);
    assert_eq!(inclusive_semantic["include_minified_sources"], true);
    assert_eq!(inclusive_semantic["semantic_ready"], true);

    let tree = stdout(&["tree", root_text, "--all"]);
    assert!(tree.contains("vendor.min.js"), "{tree}");

    let default_defs = stdout(&["defs", root_text, "--format", "json", "--all"]);
    assert!(default_defs.contains("maintainedEntry"), "{default_defs}");
    assert!(!default_defs.contains("minifiedEntry"), "{default_defs}");
    let inclusive_defs = stdout(&["defs", root_text, "--minified-js", "--format", "json", "--all"]);
    assert!(inclusive_defs.contains("maintainedEntry"), "{inclusive_defs}");
    assert!(inclusive_defs.contains("minifiedEntry"), "{inclusive_defs}");

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
        &["trace", workspace, "handle", "--symbol", "request"],
        &["read-file", workspace, "gateway.py", "--symbol", "handle_request"],
        &["trace", workspace, "--from", "handle_request"],
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
        assert!(stderr.contains("Usage:"), "{args:?} omitted usage:\n{stderr}");
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
            "trace",
            workspace,
            "--symbol",
            "handle_request",
            "--format",
            "json",
        ],
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
