//! Selector regressions found by the navigation/debug/export runtime audit.
//! Tests use isolated tiny workspaces and the exact Cargo-provided executable.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const LANGUAGES: &[&str] = &[
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
    "swift",
    "typescript",
];

struct Fixture {
    temp: tempfile::TempDir,
    workspace: PathBuf,
    cache: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary fixture");
        let workspace = temp.path().join("workspace");
        let cache = temp.path().join("cache");
        std::fs::create_dir(&workspace).expect("workspace directory");
        Self {
            temp,
            workspace,
            cache,
        }
    }

    fn language(language: &str) -> Self {
        let fixture = Self::new();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-fixtures/languages")
            .join(language)
            .join("micro");
        copy_tree(&source, &fixture.workspace);
        fixture
    }

    fn write(&self, relative: &str, source: &str) {
        let path = self.workspace.join(relative);
        std::fs::create_dir_all(path.parent().expect("source parent")).expect("source directories");
        std::fs::write(path, source).expect("fixture source");
    }

    fn run(&self, command: &str, flags: &[&str]) -> Output {
        self.run_env(command, flags, &[])
    }

    fn run_env(&self, command: &str, flags: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bonsai-ninja"));
        cmd.arg(command);
        if command == "cache" {
            cmd.arg("rebuild");
        }
        cmd.arg(&self.workspace)
            .args(flags)
            .args(["--no-color", "--no-progress"])
            .env("BONSAI_WORKSPACE_DIR", &self.cache)
            .env_remove("BONSAI_NO_CACHE")
            .env_remove("BONSAI_RULES_DIR")
            .env_remove("BONSAI_CONTEXT")
            .env_remove("BONSAI_PARSE_TIMEOUT_MS")
            .env_remove("BONSAI_DEBUG");
        for (key, value) in env {
            cmd.env(key, value);
        }
        // File-backed output avoids pipe deadlocks while enforcing a real
        // deadline on each tiny CLI invocation.
        let stdout = tempfile::NamedTempFile::new().expect("stdout file");
        let stderr = tempfile::NamedTempFile::new().expect("stderr file");
        cmd.stdout(Stdio::from(stdout.reopen().expect("stdout handle")))
            .stderr(Stdio::from(stderr.reopen().expect("stderr handle")));
        let mut child = cmd.spawn().expect("spawn CLI");
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll CLI") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("CLI exceeded 120 seconds: {command} {flags:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: std::fs::read(stdout.path()).expect("read stdout"),
            stderr: std::fs::read(stderr.path()).expect("read stderr"),
        }
    }

    fn json(&self, command: &str, flags: &[&str]) -> Value {
        let mut args = flags.to_vec();
        args.extend(["--format", "json"]);
        let result = self.run(command, &args);
        assert_success(&result);
        serde_json::from_slice(&result.stdout).expect("canonical JSON")
    }
}

fn copy_tree(source: &Path, target: &Path) {
    for entry in std::fs::read_dir(source).expect("micro fixture directory") {
        let entry = entry.expect("fixture entry");
        let destination = target.join(entry.file_name());
        if entry.file_type().expect("fixture entry type").is_dir() {
            std::fs::create_dir_all(&destination).expect("fixture subdirectory");
            copy_tree(&entry.path(), &destination);
        } else {
            std::fs::copy(entry.path(), destination).expect("copy fixture source");
        }
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "CLI failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_ast_ids_in_text(node: &Value, text: &str, language: &str) {
    let id = node["node_id"].as_str().expect("AST identity");
    assert!(
        text.contains(id),
        "{language}: text omitted selected AST node {id}"
    );
    for child in node["children"].as_array().expect("AST children") {
        assert_ast_ids_in_text(child, text, language);
    }
}

fn cap_expected_ast(node: &mut Value, depth: usize) -> usize {
    if depth == 0 {
        let omitted = node["children"].as_array().unwrap().len();
        node["children_omitted"] = serde_json::json!(omitted);
        node["children"] = serde_json::json!([]);
        omitted
    } else {
        node["children"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .map(|child| cap_expected_ast(child, depth - 1))
            .sum()
    }
}

fn callable_anchor(fixture: &Fixture) -> (String, String, u64) {
    let graph = fixture.json("dump-callgraph", &["--all"]);
    let row = graph["rows"]
        .as_array()
        .expect("callgraph rows")
        .iter()
        .find(|row| {
            row["file"].as_str().is_some_and(|file| !file.contains('/'))
                && row["function"]
                    .as_str()
                    .is_some_and(|name| !name.is_empty() && !name.starts_with('<') && !name.contains(':'))
        })
        .expect("root-file callable");
    (
        row["file"].as_str().unwrap().to_string(),
        row["function"].as_str().unwrap().to_string(),
        row["line"].as_u64().unwrap(),
    )
}

#[test]
fn all_languages_hir_cfg_basename_selectors_match_exact_locations() {
    for language in LANGUAGES {
        let fixture = Fixture::language(language);
        let (file, name, line) = callable_anchor(&fixture);
        let exact = format!("{file}:{line}:{name}");
        let basename = format!("{file}:{name}");
        let relative = format!("./{file}:{name}");
        for command in ["dump-hir", "dump-cfg"] {
            let expected = fixture.json(command, &["--symbol", &exact]);
            for selector in [&basename, &relative] {
                assert_eq!(
                    fixture.json(command, &["--symbol", selector]),
                    expected,
                    "{language} {command} {selector} must preserve the exact callable"
                );
            }
        }
    }
}

#[test]
fn all_languages_ast_node_depth_is_relative_to_the_selected_subtree() {
    for language in LANGUAGES {
        let fixture = Fixture::language(language);
        let (file, _, _) = callable_anchor(&fixture);
        let whole = fixture.json("dump-ast", &["--file", &file, "--all"]);
        let child = &whole["rows"][0]["root"]["children"][0];
        let id = child["node_id"].as_str().expect("non-root named node");
        let selected = fixture.json("dump-ast", &["--file", &file, "--node", id, "--all"]);
        assert_eq!(selected["rows"][0]["root"], *child, "{language} node identity");
        let filtered = fixture.json("dump-ast", &["--file", &file, "--contains", id, "--all"]);
        assert_eq!(
            filtered["rows"], whole["rows"],
            "{language} complete AST filter unit"
        );
        let text = fixture.run(
            "dump-ast",
            &["--file", &file, "--contains", id, "--all", "--format", "text"],
        );
        assert_success(&text);
        assert_ast_ids_in_text(
            &whole["rows"][0]["root"],
            &String::from_utf8_lossy(&text.stdout),
            language,
        );
        for depth in ["0", "1"] {
            let capped = fixture.json(
                "dump-ast",
                &["--file", &file, "--node", id, "--max-depth", depth, "--all"],
            );
            let mut expected = child.clone();
            let omitted = cap_expected_ast(&mut expected, depth.parse().unwrap());
            assert_eq!(capped["rows"][0]["root"], expected, "{language} depth {depth}");
            assert_eq!(capped["analysis_complete"], whole["analysis_complete"]);
            assert_eq!(
                capped["analysis_incomplete_reasons"],
                whole["analysis_incomplete_reasons"]
            );
            assert_eq!(capped["result_complete"], omitted == 0);
            assert_eq!(
                capped["result_incomplete_reasons"]
                    .to_string()
                    .contains("--max-depth"),
                omitted > 0
            );
            for compact in [false, true] {
                let mut flags = vec![
                    "--file",
                    &file,
                    "--node",
                    id,
                    "--max-depth",
                    depth,
                    "--all",
                    "--format",
                    "text",
                ];
                if compact {
                    flags.push("--compact");
                }
                let text = fixture.run("dump-ast", &flags);
                assert_success(&text);
                let text = String::from_utf8_lossy(&text.stdout);
                assert_eq!(
                    text.contains("dump-ast result incomplete: --max-depth"),
                    omitted > 0
                );
                assert_eq!(
                    text.contains("child subtree(s) omitted by --max-depth"),
                    omitted > 0
                );
            }
        }
        // A depth limit on a genuine leaf is not an elision.
        let mut leaf = &whole["rows"][0]["root"];
        while let Some(child) = leaf["children"].as_array().unwrap().first() {
            leaf = child;
        }
        let leaf_id = leaf["node_id"].as_str().unwrap();
        let leaf_dump = fixture.json(
            "dump-ast",
            &["--file", &file, "--node", leaf_id, "--max-depth", "0", "--all"],
        );
        assert_eq!(leaf_dump["rows"][0]["root"], *leaf);
        assert_eq!(leaf_dump["result_complete"], true);
        assert_eq!(leaf_dump["result_incomplete_reasons"], serde_json::json!([]));
    }
}

#[test]
fn ast_depth_elision_and_pagination_report_independent_result_limits() {
    let fixture = Fixture::new();
    for file in ["a.py", "b.py", "c.py"] {
        fixture.write(file, "def example(value):\n    return value\n");
    }
    let all = fixture.json("dump-ast", &["--max-depth", "0", "--all"]);
    assert_eq!(all["analysis_complete"], true);
    assert_eq!(all["analysis_incomplete_reasons"], serde_json::json!([]));
    assert_eq!(all["result_complete"], false);
    assert_eq!(all["result_incomplete_reasons"].as_array().unwrap().len(), 1);
    let mut page = fixture.json("dump-ast", &["--max-depth", "0", "--context", "1"]);
    assert!(page["page"]["total_pages"].as_u64().unwrap() > 1);
    let mut seen = Vec::new();
    let mut cursors = std::collections::HashSet::new();
    loop {
        assert!(
            cursors.insert(page["page"]["cursor"].as_str().unwrap().to_owned()),
            "pagination repeated a cursor"
        );
        assert_eq!(page["analysis_complete"], true);
        assert_eq!(page["result_complete"], false);
        let reasons = page["result_incomplete_reasons"].to_string();
        assert!(reasons.contains("paged dump-ast") && reasons.contains("--max-depth"));
        seen.extend(page["rows"].as_array().unwrap().iter().cloned());
        let Some(cursor) = page["page"]["next_cursor"].as_str().map(str::to_owned) else {
            break;
        };
        page = fixture.json(
            "dump-ast",
            &["--max-depth", "0", "--context", "1", "--page", &cursor],
        );
    }
    assert_eq!(seen, *all["rows"].as_array().unwrap());

    // A filter selecting no trees has no hidden children to display.
    let absent = fixture.json(
        "dump-ast",
        &["--max-depth", "0", "--all", "--contains", "__absent_ast__"],
    );
    assert_eq!(absent["rows"], serde_json::json!([]));
    assert_eq!(absent["analysis_complete"], true);
    assert_eq!(absent["result_complete"], true);
}

#[test]
fn show_resolver_line_context_round_trips_exact_call_site_evidence() {
    let fixture = Fixture::new();
    fixture.write(
        "resolve.py",
        "class Left:\n    def send(self, value):\n        return value\n\nclass Right:\n    def send(self, value):\n        return value\n\ndef left_use(value):\n    obj = Left()\n    return obj.send(value)\n\ndef right_use(value):\n    obj = Right()\n    return obj.send(value)\n",
    );
    for line in ["11", "15"] {
        let expected = fixture.json(
            "dump-resolve",
            &["--name", "obj.send", "--in-file", "resolve.py", "--line", line],
        );
        let id = expected["candidates"][0]["candidate_id"].as_str().unwrap();
        assert_eq!(expected["matched_call_sites"], 1);
        assert_eq!(expected["analysis_complete"], true);
        let shown = fixture.json(
            "show",
            &[
                "--id",
                id,
                "--query",
                "obj.send",
                "--in-file",
                "resolve.py",
                "--line",
                line,
            ],
        );
        assert_eq!(shown, expected);
        let direct_text = fixture.run(
            "dump-resolve",
            &[
                "--name",
                "obj.send",
                "--in-file",
                "resolve.py",
                "--line",
                line,
                "--format",
                "text",
            ],
        );
        let shown_text = fixture.run(
            "show",
            &[
                "--id",
                id,
                "--query",
                "obj.send",
                "--in-file",
                "resolve.py",
                "--line",
                line,
                "--format",
                "text",
            ],
        );
        assert_success(&direct_text);
        assert_success(&shown_text);
        assert_eq!(shown_text.stdout, direct_text.stdout);
    }
}

#[test]
fn show_rejects_context_that_the_selected_id_family_cannot_use() {
    let fixture = Fixture::new();
    fixture.write("app.py", "def example(value):\n    return value\n");
    // Validation precedes analysis/ID lookup. Use well-formed IDs without
    // relying on a security run or an accidental cached breadcrumb.
    for (prefix, body) in [
        ("F", "0000000000000000"),
        ("G", "0000000000000000"),
        ("S", "0000000000000000"),
        ("T", "00000000"),
        ("E", "00000000"),
        ("N", "00000000"),
        ("R", "00000000"),
    ] {
        let id = format!("{prefix}:{body}");
        for (flag, value, allowed) in [
            ("--query", "example", matches!(prefix, "F" | "G" | "R")),
            ("--in-file", "app.py", prefix == "R"),
            (
                "--rules-dir",
                "__missing_pack__",
                matches!(prefix, "S" | "F" | "G"),
            ),
        ] {
            if allowed {
                continue;
            }
            let output = fixture.run("show", &["--id", &id, flag, value]);
            assert!(!output.status.success());
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains(flag) && error.contains("only applies"),
                "{id} {flag}: {error}"
            );
        }
        if prefix != "R" {
            let output = fixture.run("show", &["--id", &id, "--line", "1", "--in-file", "app.py"]);
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("only applies to resolver R:"));
        }
    }
    for id in ["F:0000000000000000", "G:0000000000000000"] {
        let output = fixture.run(
            "show",
            &[
                "--id",
                id,
                "--query",
                "example",
                "--rules-dir",
                "__missing_pack__",
            ],
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--rules-dir cannot be combined with --query")
        );
        let missing_pack = fixture.temp.path().join("missing-pack");
        let output = fixture.run(
            "show",
            &["--id", id, "--rules-dir", missing_pack.to_str().unwrap()],
        );
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("rulepack"), "{error}");
        assert!(
            !error.contains("SDK structural"),
            "explicit rulepack context fell through: {error}"
        );
    }
    for flags in [
        vec!["--id", "R:00000000", "--query", "example", "--line", "1"],
        vec![
            "--id",
            "R:00000000",
            "--query",
            "example",
            "--line",
            "0",
            "--in-file",
            "app.py",
        ],
    ] {
        let output = fixture.run("show", &flags);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--line"));
    }
}

#[test]
fn dump_taint_seed_argument_boundaries_survive_cached_analysis_in_both_orders() {
    for split_first in [true, false] {
        let fixture = Fixture::new();
        fixture.write(
            "app.py",
            "def target(value):\n    return value\n\ndef other(value):\n    return value\n\ndef entry(x, y):\n    return target(x) + other(y)\n",
        );
        let split = ["--source", "entry", "--seed", "x", "--seed", "y", "--all"];
        let combined = ["--source", "entry", "--seed", "x,y", "--all"];
        let ordered: [&[&str]; 2] = if split_first {
            [&split, &combined]
        } else {
            [&combined, &split]
        };
        for flags in ordered {
            let warm = fixture.json("dump-taint", flags);
            let mut cold_flags = flags.to_vec();
            cold_flags.push("--no-cache");
            let cold = fixture.json("dump-taint", &cold_flags);
            assert_eq!(warm["seeds"], cold["seeds"]);
            assert_eq!(warm["records"], cold["records"]);
            if flags == combined.as_slice() {
                assert_eq!(warm["seeds"], serde_json::json!(["x,y"]));
                assert_eq!(warm["records"], serde_json::json!([]));
            } else {
                assert_eq!(warm["seeds"], serde_json::json!(["x", "y"]));
                assert!(!warm["records"].as_array().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn dump_resolve_rejects_ambiguous_file_context_and_prefers_exact_paths() {
    let fixture = Fixture::new();
    fixture.write("lib.py", "def target(value):\n    return value\n");
    fixture.write("a/app.py", "def unrelated(value):\n    return value\n");
    fixture.write(
        "b/app.py",
        "from lib import target\n\ndef entry(value):\n    return target(value)\n",
    );
    let ambiguous = fixture.run("dump-resolve", &["--name", "target", "--in-file", "app.py"]);
    assert!(!ambiguous.status.success());
    let error = String::from_utf8_lossy(&ambiguous.stderr);
    for expected in ["ambiguous", "a/app.py", "b/app.py"] {
        assert!(error.contains(expected), "missing {expected}: {error}");
    }
    let selected = fixture.json("dump-resolve", &["--name", "target", "--in-file", "b/app.py"]);
    assert_eq!(selected["in_file"], "b/app.py");
    assert_eq!(selected["candidates"][0]["name"], "target");

    // An exact root-file path takes precedence over matching nested suffixes.
    fixture.write(
        "app.py",
        "from lib import target\n\ndef root_entry(value):\n    return target(value)\n",
    );
    let exact = fixture.json("dump-resolve", &["--name", "target", "--in-file", "app.py"]);
    assert_eq!(exact["in_file"], "app.py");
    assert_eq!(exact["candidates"][0]["name"], "target");
}

#[test]
fn tree_file_filter_does_not_disable_the_explicit_depth_limit() {
    let fixture = Fixture::new();
    fixture.write("nested/app.py", "def example():\n    return 1\n");
    let bounded = fixture.json("tree", &["--files-only", "--file", "app.py", "--max-depth", "1"]);
    assert_eq!(bounded["summary"]["total_files"], 0);
    let reachable = fixture.json("tree", &["--files-only", "--file", "app.py", "--max-depth", "2"]);
    assert_eq!(reachable["summary"]["total_files"], 1);
}

#[test]
fn tree_secondary_filters_select_the_complete_tree_in_both_formats() {
    let fixture = Fixture::new();
    fixture.write("selected.py", "def selected():\n    return 1\n");
    fixture.write("neighbor.py", "def neighbor():\n    return 2\n");
    let whole = fixture.json("tree", &["--files-only", "--all"]);
    let matched = fixture.json("tree", &["--files-only", "--all", "--contains", "selected.py"]);
    assert_eq!(matched["roots"], whole["roots"]);
    let text = fixture.run(
        "tree",
        &[
            "--files-only",
            "--all",
            "--contains",
            "selected.py",
            "--format",
            "text",
        ],
    );
    assert_success(&text);
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("selected.py") && text.contains("neighbor.py"));
    for selectors in [
        ["--contains", "__absent_tree_selector__"],
        ["--not-contains", "selected.py"],
    ] {
        let mut flags = vec!["--files-only", "--all"];
        flags.extend(selectors);
        let json = fixture.json("tree", &flags);
        assert_eq!(json["matched"], false);
        assert!(json["value"].is_null());
        flags.extend(["--format", "text"]);
        let text = fixture.run("tree", &flags);
        assert_success(&text);
        let text = String::from_utf8_lossy(&text.stdout);
        assert!(text.contains("no tree result matches"));
        assert!(!text.contains("selected.py") && !text.contains("neighbor.py"));
    }
}

#[test]
fn dump_resolve_secondary_filters_select_the_complete_trace() {
    let fixture = Fixture::new();
    fixture.write("app.py", "def target(value):\n    return value\n");
    let whole = fixture.json("dump-resolve", &["--name", "target"]);
    let id = whole["candidates"][0]["candidate_id"]
        .as_str()
        .expect("candidate ID");
    let matched = fixture.json("dump-resolve", &["--name", "target", "--contains", id]);
    assert_eq!(matched, whole);
    for selectors in [
        ["--contains", "__absent_resolver_selector__"],
        ["--not-contains", id],
    ] {
        let mut flags = vec!["--name", "target"];
        flags.extend(selectors);
        let json = fixture.json("dump-resolve", &flags);
        assert_eq!(json["matched"], false);
        assert!(json["value"].is_null());
        flags.extend(["--format", "text"]);
        let text = fixture.run("dump-resolve", &flags);
        assert_success(&text);
        let text = String::from_utf8_lossy(&text.stdout);
        assert!(text.contains("no resolver trace matches"));
        assert!(!text.contains(id));
    }
}

#[test]
fn export_no_cache_flag_and_environment_bypass_the_warmed_export_artifact() {
    let fixture = Fixture::new();
    fixture.write(
        "app.py",
        "def target(value):\n    return value\n\ndef entry(value):\n    return target(value)\n",
    );
    assert_success(&fixture.run("cache", &["--export"]));
    let mut expected = fixture.json("export", &[]);
    expected
        .as_object_mut()
        .expect("native export object")
        .remove("generated_at_unix_ms");
    for (flags, env) in [
        (vec!["--no-cache"], Vec::<(&str, &str)>::new()),
        (Vec::new(), vec![("BONSAI_NO_CACHE", "1")]),
    ] {
        let mut flags = flags;
        flags.extend(["--format", "json", "--debug", "workspace-open"]);
        let output = fixture.run_env("export", &flags, &env);
        assert_success(&output);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("workspace construction:"),
            "no-cache export bypassed the compiler open: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut actual: Value = serde_json::from_slice(&output.stdout).expect("export JSON");
        // Regeneration changes only the creation timestamp, not graph facts.
        actual
            .as_object_mut()
            .expect("native export object")
            .remove("generated_at_unix_ms");
        assert_eq!(actual, expected);
    }
}

// These two integration regressions cover main-owned page-cache dispatch.
// Production subprocesses are necessary: its cfg(test) rulepack classifier
// otherwise masks the read-file omission.
#[test]
fn tree_cached_listing_refreshes_when_non_source_files_are_added_or_renamed() {
    let fixture = Fixture::new();
    fixture.write("app.py", "def example():\n    return 1\n");
    let flags = ["--files-only", "--all"];
    let before = fixture.json("tree", &flags);
    fixture.write("new-file.txt", "not a compiler input\n");
    let after = fixture.json("tree", &flags);
    assert_eq!(
        after["summary"]["total_files"],
        before["summary"]["total_files"].as_u64().unwrap() + 1
    );
    std::fs::rename(
        fixture.workspace.join("new-file.txt"),
        fixture.workspace.join("renamed.txt"),
    )
    .expect("rename fixture entry");
    let renamed = fixture.json("tree", &flags);
    let cold = fixture.json("tree", &["--files-only", "--all", "--no-cache"]);
    assert_eq!(renamed["roots"], cold["roots"]);
    assert!(!renamed.to_string().contains("new-file.txt"));
}

#[test]
fn read_file_cached_report_does_not_hide_an_invalid_explicit_rulepack() {
    let fixture = Fixture::new();
    fixture.write("app.py", "def example():\n    return 1\n");
    let pack = fixture.temp.path().join("pack");
    std::fs::create_dir(&pack).expect("empty valid rulepack");
    let pack_arg = pack.to_str().unwrap();
    let flags = ["--file", "app.py", "--rules-dir", pack_arg, "--all"];
    fixture.json("read-file", &flags);
    std::fs::rename(&pack, fixture.temp.path().join("saved-pack")).expect("rename rulepack");
    let warm = fixture.run(
        "read-file",
        &[
            "--file",
            "app.py",
            "--rules-dir",
            pack_arg,
            "--all",
            "--format",
            "json",
        ],
    );
    let cold = fixture.run(
        "read-file",
        &[
            "--file",
            "app.py",
            "--rules-dir",
            pack_arg,
            "--all",
            "--format",
            "json",
            "--no-cache",
        ],
    );
    assert!(!warm.status.success(), "cached report hid missing rules");
    assert_eq!(warm.status.code(), cold.status.code());
    assert_eq!(warm.stderr, cold.stderr);
}
