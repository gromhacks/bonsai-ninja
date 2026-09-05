//! Large-repo regression tests against a real Elasticsearch checkout.
//!
//! These tests are intentionally integration-level. They run the compiled
//! release binary against `../elasticsearch` and assert that broad code
//! intelligence and security commands keep working on the same production
//! sized repo we use manually. If the checkout is absent, the tests skip
//! so normal CI remains portable.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn elasticsearch_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn release_bin() -> Option<PathBuf> {
    // Cargo sets CARGO_BIN_EXE_* to the current test-profile executable.
    // For this production-scale corpus that is normally a debug binary:
    // using it makes the same exact analysis an order of magnitude slower
    // and materially more memory hungry. This gate intentionally validates
    // production behavior, so never silently substitute the debug artifact.
    let path = repo_root().join("target/release/bonsai-ninja");
    if !path.exists() {
        assert!(
            !large_repo_gate_required(),
            "required Elasticsearch gate has no release binary ({}); run `cargo build --release --locked -p bonsai-ninja`",
            path.display()
        );
        eprintln!(
            "skipping elasticsearch large-repo test: release binary not built ({})",
            path.display()
        );
        return None;
    }
    match release_binary_is_fresh(&path, &repo_root()) {
        Ok(true) => Some(path),
        Ok(false) => {
            assert!(
                !large_repo_gate_required(),
                "required Elasticsearch gate release binary is stale; run `cargo build --release --locked -p bonsai-ninja`"
            );
            eprintln!(
                "skipping elasticsearch large-repo test: release binary is stale; \
                 run `cargo build --release --locked -p bonsai-ninja`"
            );
            None
        }
        Err(error) => {
            assert!(
                !large_repo_gate_required(),
                "required Elasticsearch gate cannot verify release binary freshness: {error}"
            );
            eprintln!(
                "skipping elasticsearch large-repo test: cannot verify release binary freshness: {error}"
            );
            None
        }
    }
}

fn large_repo_gate_required() -> bool {
    std::env::var("BONSAI_REQUIRE_ELASTICSEARCH_GATE")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
}

fn release_binary_is_fresh(binary: &Path, root: &Path) -> std::io::Result<bool> {
    let binary_modified = binary.metadata()?.modified()?;
    let mut newest_input = UNIX_EPOCH;
    for input in [
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("crates"),
    ] {
        record_newest_release_input(&input, &mut newest_input)?;
    }
    Ok(binary_modified >= newest_input)
}

fn record_newest_release_input(path: &Path, newest: &mut SystemTime) -> std::io::Result<()> {
    let metadata = path.symlink_metadata()?;
    if metadata.is_file() {
        let is_release_input = matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("Cargo.toml" | "Cargo.lock" | "build.rs")
        ) || path.extension().and_then(|extension| extension.to_str()) == Some("rs");
        if is_release_input {
            *newest = (*newest).max(metadata.modified()?);
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    if matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("tests" | "benches" | "examples")
    ) {
        // Integration/benchmark/example sources do not participate in the
        // production CLI binary. Treating this test file as a release input
        // would make editing the gate itself mark an otherwise current binary
        // stale, and `cargo build --release` could never repair the timestamp.
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        record_newest_release_input(&entry?.path(), newest)?;
    }
    Ok(())
}

fn elasticsearch_root() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("BONSAI_ELASTICSEARCH_ROOT") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    let path = repo_root().join("../elasticsearch");
    if path.exists() {
        Some(path.canonicalize().unwrap_or(path))
    } else {
        assert!(
            !large_repo_gate_required(),
            "required Elasticsearch gate corpus is unavailable; set BONSAI_ELASTICSEARCH_ROOT to a checkout"
        );
        eprintln!(
            "skipping elasticsearch large-repo test: checkout not found ({})",
            path.display()
        );
        None
    }
}

#[test]
fn elasticsearch_fresh_and_warm_structural_index_do_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    let cache = temp_output_path("structural-index-cache");
    std::fs::create_dir_all(&cache).expect("create isolated structural cache");
    let args = es_args(&es, &["index", "{es}", "--format", "json"]);

    let cold_started = Instant::now();
    let mut cold_command = bonsai_command(&bin, &args);
    cold_command.env("BONSAI_WORKSPACE_DIR", &cache);
    let cold_output = run_command_with_watchdog(&mut cold_command, "cold Elasticsearch structural index");
    let cold = assert_success_output(&args, cold_output);
    let cold_elapsed = cold_started.elapsed();
    assert_performance(
        "Elasticsearch fresh-cache structural index",
        cold_elapsed,
        "BONSAI_ES_COLD_STRUCTURAL_INDEX_MAX_SECS",
        100,
    );
    let cold: serde_json::Value = serde_json::from_str(&cold).expect("cold structural index JSON");
    assert_eq!(cold["compiler_cache"], "rebuilt", "{cold}");
    assert!(
        cold["files"].as_u64().is_some_and(|files| files >= 30_000) && cold["parsed_files"] == cold["files"],
        "cold structural index must compile the complete Elasticsearch source set: {cold}"
    );

    let warm_started = Instant::now();
    let mut warm_command = bonsai_command(&bin, &args);
    warm_command.env("BONSAI_WORKSPACE_DIR", &cache);
    let warm_output = run_command_with_watchdog(&mut warm_command, "warm Elasticsearch structural index");
    let warm = assert_success_output(&args, warm_output);
    let warm_elapsed = warm_started.elapsed();
    assert_performance(
        "Elasticsearch warm structural index",
        warm_elapsed,
        "BONSAI_ES_WARM_STRUCTURAL_INDEX_MAX_SECS",
        12,
    );
    let warm: serde_json::Value = serde_json::from_str(&warm).expect("warm structural index JSON");
    assert_eq!(warm["compiler_cache"], "hit", "{warm}");
    assert_eq!(warm["files"], cold["files"], "{warm}");
    assert_eq!(warm["parsed_files"], 0, "{warm}");

    let _ = std::fs::remove_dir_all(cache);
}

fn rules_dir() -> PathBuf {
    repo_root().join("security-patterns")
}

/// Every leaf command advertised by the curated root menu. Each entry is
/// exercised on Elasticsearch in this file, except `cache rebuild`, which is
/// covered by the always-on synthetic scale gate: rebuilding the same complete
/// Elasticsearch semantic generation twice would add several minutes without
/// reaching a distinct compiler path. Keep this list in sync with the menu;
/// the invariant below fails when a public command is added without scale
/// ownership.
const LARGE_REPO_COMMAND_COVERAGE: &[&str] = &[
    "inspect-graph",
    "show",
    "index",
    "export",
    "cache stats",
    "cache clear",
    "cache rebuild",
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
    "tree",
    "read-file",
    "security sources",
    "security sinks",
    "security sanitizers",
    "security deps",
    "security dependency-analysis",
    "security taint-analysis",
    "security source-analysis",
    "security sink-analysis",
    "security pack",
    "dump-ast",
    "dump-hir",
    "dump-cfg",
    "dump-callgraph",
    "dump-edges",
    "dump-resolution",
    "dump-resolve",
    "dump-taint",
    "diagnostics",
];

fn temp_output_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "bonsai-es-large-repo-{name}-{}-{nanos}.json",
        std::process::id()
    ))
}

fn bonsai_command(bin: &Path, args: &[String]) -> Command {
    let mut command = Command::new(bin);
    command
        .args(args)
        .arg("--no-color")
        .arg("--no-progress")
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT");
    // Keep the scale gate reproducible on shared development/CI hosts. This
    // budget controls compiler concurrency and cache retention only; it does
    // not cap files, graph closure, iterations, or emitted facts. Callers may
    // set a lower value to exercise a smaller machine.
    if std::env::var_os("BONSAI_MEMORY_BUDGET_MB").is_none() {
        command.env("BONSAI_MEMORY_BUDGET_MB", "3072");
    }
    if std::env::var_os("MIMALLOC_PURGE_DELAY").is_none() {
        command.env("MIMALLOC_PURGE_DELAY", "0");
    }
    command
}

fn run_bonsai(bin: &Path, args: &[String]) -> Output {
    run_command_with_watchdog(&mut bonsai_command(bin, args), &format!("bonsai-ninja {args:?}"))
}

fn run_command_with_watchdog(command: &mut Command, label: &str) -> Output {
    let watchdog = performance_limit("BONSAI_ES_PROCESS_WATCHDOG_SECS", 900);
    let stdout_path = temp_output_path("process-stdout");
    let stderr_path = temp_output_path("process-stderr");
    let stdout_file = std::fs::File::create(&stdout_path).expect("create process stdout capture");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create process stderr capture");
    command
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("run {label}: {error}"));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() <= watchdog => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let status = child.wait().expect("reap timed-out bonsai process");
                let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
                let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
                let _ = std::fs::remove_file(&stdout_path);
                let _ = std::fs::remove_file(&stderr_path);
                panic!(
                    "{label} exceeded the {watchdog:.2?} scale-test watchdog and was terminated as a probable hang (status {status})\nstdout:\n{stdout}\nstderr:\n{stderr}"
                );
            }
            Err(error) => panic!("poll {label}: {error}"),
        }
    };
    let stdout = std::fs::read(&stdout_path).expect("read process stdout capture");
    let stderr = std::fs::read(&stderr_path).expect("read process stderr capture");
    let _ = std::fs::remove_file(stdout_path);
    let _ = std::fs::remove_file(stderr_path);
    Output {
        status,
        stdout,
        stderr,
    }
}

fn assert_success_output(args: &[String], output: Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "bonsai-ninja {args:?} exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(
        !stderr.contains("disabled to avoid OOM")
            && !stderr.contains("BONSAI_ALLOW_BROAD_TAINT")
            && !stdout.contains("disabled to avoid OOM")
            && !stdout.contains("BONSAI_ALLOW_BROAD_TAINT"),
        "large-repo command regressed to the old guard/error path: {args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout
}

fn assert_success(bin: &Path, args: &[String]) -> String {
    assert_success_output(args, run_bonsai(bin, args))
}

fn performance_limit(variable: &str, default_seconds: u64) -> Duration {
    let seconds = std::env::var(variable)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_seconds);
    Duration::from_secs(seconds)
}

fn assert_performance(label: &str, elapsed: Duration, variable: &str, default_seconds: u64) {
    let limit = performance_limit(variable, default_seconds);
    assert!(
        elapsed <= limit,
        "{label} completed correctly but took {elapsed:.2?}, exceeding {limit:.2?}; \
         production analysis is uncapped, while the separate test-only watchdog catches hangs. Set {variable} only when \
         intentionally calibrating a slower performance host"
    );
    eprintln!("{label} completed in {elapsed:.2?} (SLO {limit:.2?})");
}

fn assert_success_timed(bin: &Path, args: &[String]) -> (String, Duration) {
    let started = Instant::now();
    let output = assert_success(bin, args);
    (output, started.elapsed())
}

#[test]
fn elasticsearch_scale_matrix_tracks_every_public_menu_command() {
    let bin = option_env!("CARGO_BIN_EXE_bonsai-ninja")
        .map(PathBuf::from)
        .or_else(release_bin)
        .expect("current CLI binary for command-coverage invariant");
    let output = Command::new(bin)
        .args(["--help", "--no-color", "--no-progress"])
        .output()
        .expect("render root help for scale coverage invariant");
    assert!(output.status.success(), "root help failed: {output:?}");
    let help = String::from_utf8_lossy(&output.stdout);
    let mut in_groups = false;
    let mut public = BTreeSet::new();
    for line in help.lines() {
        if line == "COMMAND GROUPS" {
            in_groups = true;
            continue;
        }
        if in_groups && line == "OPTIONS:" {
            break;
        }
        if !in_groups || !line.starts_with("    ") || line.starts_with("      ") {
            continue;
        }
        let trimmed = line.trim_start();
        if let Some((name, _)) = trimmed.split_once("  ") {
            public.insert(name.trim().to_string());
        }
    }

    let declared: BTreeSet<_> = LARGE_REPO_COMMAND_COVERAGE
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    assert_eq!(
        declared.len(),
        LARGE_REPO_COMMAND_COVERAGE.len(),
        "large-repo command coverage contains a duplicate"
    );
    assert_eq!(
        declared, public,
        "every public menu command must have an owned production-scale gate"
    );
}

fn ensure_elasticsearch_semantic_cache(bin: &Path, es: &Path) {
    static PREWARM: OnceLock<Result<(), String>> = OnceLock::new();
    PREWARM
        .get_or_init(|| {
            let started = Instant::now();
            let args = es_args(es, &["index", "--semantic", "{es}", "--format", "json"]);
            let output = run_bonsai(bin, &args);
            if !output.status.success() {
                return Err(format!(
                    "semantic prewarm failed with {}\nstdout:\n{}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            let stats = run_bonsai(bin, &es_args(es, &["cache", "stats", "{es}", "--format", "json"]));
            if !stats.status.success() {
                return Err(format!(
                    "cache stats failed after semantic prewarm with {}\nstdout:\n{}\nstderr:\n{}",
                    stats.status,
                    String::from_utf8_lossy(&stats.stdout),
                    String::from_utf8_lossy(&stats.stderr)
                ));
            }
            let parsed: serde_json::Value = serde_json::from_slice(&stats.stdout)
                .map_err(|error| format!("invalid cache stats JSON after prewarm: {error}"))?;
            if parsed
                .pointer("/validation/semantic_ready")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            {
                return Err(format!(
                    "semantic prewarm did not publish a reusable complete generation: {parsed}"
                ));
            }
            let cold_elapsed = started.elapsed();
            let cold_limit = performance_limit("BONSAI_ES_COLD_SEMANTIC_INDEX_MAX_SECS", 600);
            if cold_elapsed > cold_limit {
                return Err(format!(
                    "Elasticsearch complete semantic generation finished correctly but took \
                     {cold_elapsed:.2?}, exceeding {cold_limit:.2?}; this gate never caps or \
                     skips compiler, linkage, callgraph, retrieval, or IDG work"
                ));
            }
            eprintln!(
                "Elasticsearch semantic generation ready in {cold_elapsed:.2?} \
                 (cold SLO {cold_limit:.2?})"
            );

            // A stale exact generation may take real compiler work. The next
            // fresh process must validate and reuse it quickly. This measures
            // completed work; it never kills analysis, narrows files, or caps
            // graph closure/results.
            let warm_args = es_args(es, &["index", "--semantic", "{es}", "--format", "json"]);
            let warm_started = Instant::now();
            let warm_output = run_bonsai(bin, &warm_args);
            if !warm_output.status.success() {
                return Err(format!(
                    "warm semantic reuse failed with {}\nstdout:\n{}\nstderr:\n{}",
                    warm_output.status,
                    String::from_utf8_lossy(&warm_output.stdout),
                    String::from_utf8_lossy(&warm_output.stderr)
                ));
            }
            let warm_elapsed = warm_started.elapsed();
            let warm_limit = performance_limit("BONSAI_ES_WARM_INDEX_MAX_SECS", 18);
            if warm_elapsed > warm_limit {
                return Err(format!(
                    "warm semantic index completed correctly but took {warm_elapsed:.2?}, \
                     exceeding {warm_limit:.2?}; cache validation or reuse regressed"
                ));
            }
            eprintln!("Elasticsearch warm semantic reuse completed in {warm_elapsed:.2?}");
            Ok(())
        })
        .as_ref()
        .unwrap_or_else(|error| panic!("{error}"));
}

fn es_args(es: &Path, rest: &[&str]) -> Vec<String> {
    let rules = rules_dir();
    let mut args = Vec::with_capacity(rest.len() + 1);
    for part in rest {
        match *part {
            "{es}" => args.push(es.to_string_lossy().into_owned()),
            "{rules}" => args.push(rules.to_string_lossy().into_owned()),
            _ => args.push((*part).to_string()),
        }
    }
    args
}

#[test]
fn elasticsearch_navigation_commands_do_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    ensure_elasticsearch_semantic_cache(&bin, &es);
    let commands: &[&[&str]] = &[
        &["tree", "{es}", "--max-depth", "1", "--context", "4k"],
        &["search", "{es}", "execute", "--context", "4k"],
        &["defs", "{es}", "--kind", "function", "--context", "4k"],
        &["imports", "{es}", "--context", "4k"],
        &["classes", "{es}", "--context", "4k"],
        &["entrypoints", "{es}", "--context", "4k"],
        &["calls", "{es}", "--callee", "execute", "--context", "4k"],
        &["args", "{es}", "--callee", "execute", "--context", "4k"],
        &[
            "read-file",
            "{es}",
            "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
            "--lines",
            "280:310",
            "--context",
            "4k",
        ],
    ];
    for command in commands {
        let args = es_args(&es, command);
        let (out, elapsed) = assert_success_timed(&bin, &args);
        assert_performance(
            &format!("Elasticsearch navigation command {command:?}"),
            elapsed,
            "BONSAI_ES_NAVIGATION_MAX_SECS",
            35,
        );
        assert!(
            !out.trim().is_empty(),
            "bonsai-ninja {command:?} produced empty stdout"
        );
    }
}

#[test]
fn elasticsearch_remaining_compiler_command_surfaces_do_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    ensure_elasticsearch_semantic_cache(&bin, &es);
    let commands: &[(&str, &[&str])] = &[
        (
            "inspect-graph corridor",
            &[
                "inspect-graph",
                "{es}",
                "--from",
                "performRequestAsync",
                "--to",
                "nextNodes",
                "--format",
                "json",
                "--context",
                "4k",
            ],
        ),
        ("diagnostics", &["diagnostics", "{es}"]),
        (
            "dump-hir",
            &[
                "dump-hir",
                "{es}",
                "--symbol",
                "client.rest.org.elasticsearch.client.RestClient.convertResponse",
            ],
        ),
        (
            "dump-cfg",
            &[
                "dump-cfg",
                "{es}",
                "--symbol",
                "client.rest.org.elasticsearch.client.RestClient.convertResponse",
            ],
        ),
        (
            "dump-callgraph",
            &["dump-callgraph", "{es}", "--format", "json", "--context", "4k"],
        ),
        (
            "dump-resolution",
            &[
                "dump-resolution",
                "{es}",
                "--file",
                "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
                "--format",
                "json",
                "--all",
            ],
        ),
        (
            "dump-ast",
            &[
                "dump-ast",
                "{es}",
                "--file",
                "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
                "--function",
                "convertResponse",
                "--compact",
                "--format",
                "json",
                "--all",
            ],
        ),
        (
            "dump-resolve",
            &[
                "dump-resolve",
                "{es}",
                "--name",
                "nextNodes",
                "--in-file",
                "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
                "--line",
                "292",
                "--format",
                "json",
            ],
        ),
        (
            "dump-taint",
            &[
                "dump-taint",
                "{es}",
                "--source",
                "client.rest.org.elasticsearch.client.RestClient.convertResponse",
                "--seed",
                "request",
                "--format",
                "json",
                "--context",
                "4k",
            ],
        ),
        (
            "vars",
            &[
                "vars",
                "{es}",
                "--file",
                "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
                "--name",
                "internalRequest",
                "--format",
                "json",
                "--context",
                "4k",
            ],
        ),
        (
            "strings",
            &[
                "strings",
                "{es}",
                "--file",
                "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
                "--contains",
                "unexpected",
                "--format",
                "json",
                "--context",
                "4k",
            ],
        ),
        (
            "comments",
            &[
                "comments",
                "{es}",
                "--file",
                "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
                "--contains",
                "request",
                "--format",
                "json",
                "--context",
                "4k",
            ],
        ),
        (
            "operations",
            &[
                "operations",
                "{es}",
                "--file",
                "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
                "--in-fn",
                "convertResponse",
                "--format",
                "json",
                "--context",
                "4k",
            ],
        ),
        (
            "refs",
            &[
                "refs",
                "{es}",
                "--symbol",
                "nextNodes",
                "--file",
                "client/rest/src/main/java/org/elasticsearch/client/RestClient.java",
                "--format",
                "json",
                "--context",
                "4k",
            ],
        ),
    ];

    for (name, command) in commands {
        let args = es_args(&es, command);
        let (out, elapsed) = assert_success_timed(&bin, &args);
        assert_performance(
            &format!("Elasticsearch compiler command {name}"),
            elapsed,
            "BONSAI_ES_COMMAND_MAX_SECS",
            35,
        );
        assert!(
            !out.trim().is_empty(),
            "Elasticsearch compiler command {name} returned empty output"
        );
    }

    let edge_args = es_args(
        &es,
        &[
            "dump-edges",
            "{es}",
            "--from",
            "convertResponse",
            "--to",
            "onResponse",
            "--format",
            "json",
            "--all",
        ],
    );
    let (edge_out, edge_elapsed) = assert_success_timed(&bin, &edge_args);
    assert_performance(
        "Elasticsearch dump-edges",
        edge_elapsed,
        "BONSAI_ES_COMMAND_MAX_SECS",
        35,
    );
    let edge_envelope: serde_json::Value = serde_json::from_str(&edge_out).expect("Elasticsearch edge JSON");
    let edges: Vec<serde_json::Value> = edge_envelope["rows"]
        .as_array()
        .cloned()
        .expect("Elasticsearch edge rows");
    let edge_id = edges
        .first()
        .and_then(|edge| edge["edge_id"].as_str())
        .expect("pinned RestClient edge");
    let show_args = vec![
        "show".to_string(),
        es.to_string_lossy().into_owned(),
        "--id".to_string(),
        edge_id.to_string(),
        "--context".to_string(),
        "4k".to_string(),
    ];
    let (show, show_elapsed) = assert_success_timed(&bin, &show_args);
    assert_performance(
        "Elasticsearch show stable edge id",
        show_elapsed,
        "BONSAI_ES_COMMAND_MAX_SECS",
        35,
    );
    assert!(show.contains(edge_id), "show did not reopen {edge_id}: {show}");
}

#[test]
fn elasticsearch_inspect_modes_do_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    ensure_elasticsearch_semantic_cache(&bin, &es);
    let (default_out, default_elapsed) = assert_success_timed(
        &bin,
        &es_args(
            &es,
            &["inspect-graph", "{es}", "--query", "execute", "--context", "8k"],
        ),
    );
    assert_performance(
        "Elasticsearch default inspect",
        default_elapsed,
        // Git/CI hosts can have materially slower checkout and page-cache
        // behavior than the development machine. Keep the watchdog around
        // the complete exact command, but leave enough variance for the
        // compiler-backed inspect modes to avoid false performance failures.
        "BONSAI_ES_INSPECT_MAX_SECS",
        60,
    );
    assert!(
        default_out.contains("inspect-graph `execute`"),
        "default inspect output lost query header:\n{default_out}"
    );
    assert!(
        default_out.contains("TAINT FLOWS") || default_out.contains("taint flow"),
        "inspect-graph did not render taint-flow evidence:\n{default_out}"
    );
}

#[test]
fn elasticsearch_security_inventory_commands_do_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    ensure_elasticsearch_semantic_cache(&bin, &es);
    let commands: &[&[&str]] = &[
        &[
            "security",
            "{es}",
            "sources",
            "--rule",
            "java.source.spring_request_param",
            "--format",
            "json",
            "--rules-dir",
            "{rules}",
        ],
        &[
            "security",
            "{es}",
            "sinks",
            "--severity",
            "high",
            "--context",
            "4k",
            "--rules-dir",
            "{rules}",
        ],
        &[
            "security",
            "{es}",
            "sanitizers",
            "--context",
            "4k",
            "--rules-dir",
            "{rules}",
        ],
        &[
            "security",
            "{es}",
            "deps",
            "--severity",
            "high",
            "--context",
            "4k",
            "--rules-dir",
            "{rules}",
        ],
    ];
    for command in commands {
        let args = es_args(&es, command);
        // The first run builds the complete cached inventory for the scope
        // (every rule, then the selectors as a view); it is the only run
        // that scans.
        let (out, elapsed) = assert_success_timed(&bin, &args);
        assert_performance(
            &format!("Elasticsearch security inventory command (cold) {command:?}"),
            elapsed,
            "BONSAI_ES_SECURITY_INVENTORY_COLD_MAX_SECS",
            60,
        );
        assert!(
            !out.trim().is_empty(),
            "bonsai-ninja {command:?} produced empty stdout"
        );
        // Every later view over the same scope replays the cached object:
        // this is the contract that sub-command filters never re-scan.
        let (warm, elapsed) = assert_success_timed(&bin, &args);
        assert_performance(
            &format!("Elasticsearch security inventory command (warm view) {command:?}"),
            elapsed,
            "BONSAI_ES_SECURITY_INVENTORY_MAX_SECS",
            15,
        );
        assert_eq!(
            warm, out,
            "a replayed inventory view must render exactly what the cold run rendered: {command:?}"
        );
    }
    // `dependency-analysis` renders the taint findings each package appears
    // in from the cached complete taint report, so its budget follows the
    // warm taint-analysis budget rather than the inventory scan budget.
    let args = es_args(
        &es,
        &[
            "security",
            "{es}",
            "dependency-analysis",
            "--severity",
            "high",
            "--context",
            "4k",
            "--rules-dir",
            "{rules}",
        ],
    );
    let (out, elapsed) = assert_success_timed(&bin, &args);
    assert_performance(
        "Elasticsearch security dependency-analysis",
        elapsed,
        "BONSAI_ES_DEPENDENCY_ANALYSIS_MAX_SECS",
        135,
    );
    assert!(
        !out.trim().is_empty(),
        "Elasticsearch security dependency-analysis produced no output"
    );
}

#[test]
fn elasticsearch_source_analysis_and_rulepack_audit_do_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    ensure_elasticsearch_semantic_cache(&bin, &es);

    // Pin one real source-bearing production file while retaining the complete
    // workspace linkage/IDG. This makes the asserted downstream set stable and
    // still exercises source-root scheduling on the production-size graph.
    let source_args = es_args(
        &es,
        &[
            "security",
            "{es}",
            "source-analysis",
            "--profile",
            "all",
            "--source",
            "^java\\.source\\.system_getproperty$",
            "--file",
            "client/rest/src/main/java/org/elasticsearch/client/RestClientBuilder.java",
            "--format",
            "json",
            "--all",
            "--rules-dir",
            "{rules}",
        ],
    );
    let (source_out, source_elapsed) = assert_success_timed(&bin, &source_args);
    assert_performance(
        "Elasticsearch source-centric analysis",
        source_elapsed,
        "BONSAI_ES_SOURCE_ANALYSIS_MAX_SECS",
        35,
    );
    let source: serde_json::Value =
        serde_json::from_str(&source_out).expect("Elasticsearch source-analysis JSON");
    assert_eq!(source["analysis_complete"], true, "{source}");
    assert!(
        source["summary"]["source_flow_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "pinned Elasticsearch source must retain downstream compiler flow: {source}"
    );

    let pack_args = es_args(
        &es,
        &[
            "security",
            "{es}",
            "pack",
            "--validate",
            "--format",
            "json",
            "--rules-dir",
            "{rules}",
        ],
    );
    let (pack_out, pack_elapsed) = assert_success_timed(&bin, &pack_args);
    assert_performance(
        "complete embedded rulepack validation",
        pack_elapsed,
        "BONSAI_ES_PACK_MAX_SECS",
        70,
    );
    let pack: serde_json::Value = serde_json::from_str(&pack_out).expect("rulepack validation JSON");
    assert_eq!(pack["valid"], true, "{pack}");
    assert_eq!(pack["errors"].as_u64(), Some(0), "{pack}");
    assert_eq!(pack["warnings"].as_u64(), Some(0), "{pack}");
}

#[test]
fn elasticsearch_native_export_streams_the_complete_graph_without_regressing() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    ensure_elasticsearch_semantic_cache(&bin, &es);
    let output = temp_output_path("native-export");
    let args = es_args(
        &es,
        &[
            "export",
            "{es}",
            "--format",
            "json",
            "--output-path",
            output.to_str().expect("temp output path utf8"),
        ],
    );
    let (stdout, elapsed) = assert_success_timed(&bin, &args);
    assert_performance(
        "Elasticsearch exact native export",
        elapsed,
        "BONSAI_ES_EXPORT_MAX_SECS",
        300,
    );
    assert!(
        stdout.trim().is_empty(),
        "streamed export must keep stdout empty: {stdout}"
    );

    // The document is several GiB. Validate its streaming envelope without
    // materializing it again in the test process and doubling peak memory.
    let mut file = std::fs::File::open(&output).expect("open native export");
    let len = file.metadata().expect("native export metadata").len();
    assert!(
        len >= 1_000_000_000,
        "production export unexpectedly small ({len} bytes)"
    );
    let mut prefix = vec![0_u8; 4096];
    let prefix_len = file.read(&mut prefix).expect("read native export prefix");
    let prefix = String::from_utf8_lossy(&prefix[..prefix_len]);
    assert!(
        prefix.starts_with("{\"schema\":\"bonsai-native-export\""),
        "{prefix}"
    );
    assert!(prefix.contains("\"schema_version\":"), "{prefix}");
    let file_count = prefix
        .split_once("\"file_count\":")
        .and_then(|(_, tail)| tail.split(|ch: char| !ch.is_ascii_digit()).next())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("file_count in export prefix");
    assert!(
        file_count >= 30_000,
        "native export omitted compiler inputs: {file_count}"
    );

    let tail_len = len.min(1024) as usize;
    file.seek(SeekFrom::End(-(tail_len as i64)))
        .expect("seek native export tail");
    let mut tail = vec![0_u8; tail_len];
    file.read_exact(&mut tail).expect("read native export tail");
    let tail = String::from_utf8_lossy(&tail);
    assert!(tail.trim_end().ends_with('}'), "truncated export tail: {tail}");
    assert!(
        tail.contains("\"propagations_mode\":\"compiled_idg\""),
        "export tail lost exact compiled-IDG contract: {tail}"
    );
    drop(file);
    let _ = std::fs::remove_file(output);
}

#[test]
fn elasticsearch_production_taint_analysis_does_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    ensure_elasticsearch_semantic_cache(&bin, &es);
    let output = temp_output_path("taint-summary");
    let args = es_args(
        &es,
        &[
            "security",
            "{es}",
            "taint-analysis",
            "--profile",
            "production",
            "--summary",
            "--format",
            "json",
            "--output-path",
            output.to_str().expect("temp output path utf8"),
            "--rules-dir",
            "{rules}",
        ],
    );
    // The product runs to its exact semantic fixed point. This integration
    // process has a generous test-only watchdog so a scheduler deadlock fails
    // the gate instead of occupying a CI runner indefinitely.
    let (stdout, elapsed) = assert_success_timed(&bin, &args);
    assert_performance(
        "Elasticsearch warm production taint analysis",
        elapsed,
        "BONSAI_ES_TAINT_MAX_SECS",
        135,
    );
    assert!(
        stdout.trim().is_empty(),
        "taint-analysis with --output-path should keep stdout empty, got:\n{stdout}"
    );
    let written = std::fs::read_to_string(&output).expect("read taint summary output");
    let parsed: serde_json::Value = serde_json::from_str(&written)
        .unwrap_or_else(|err| panic!("valid taint summary JSON ({err}):\n{written}"));
    assert!(
        parsed.get("total_findings").and_then(|v| v.as_u64()).is_some(),
        "taint summary missing total_findings: {parsed}"
    );
    assert_eq!(
        parsed.get("analysis_complete").and_then(|value| value.as_bool()),
        Some(true),
        "production taint summary must report exact completed analysis: {parsed}"
    );
    assert_eq!(
        parsed
            .get("analysis_incomplete_reasons")
            .and_then(|value| value.as_array())
            .map(Vec::len),
        Some(0),
        "production taint summary must not hide incomplete compiler work: {parsed}"
    );
    for field in ["source_rule_count", "sink_rule_count", "sanitizer_rule_count"] {
        assert!(
            parsed
                .get(field)
                .and_then(|value| value.as_u64())
                .is_some_and(|count| count > 0),
            "production taint summary lost `{field}` inventory: {parsed}"
        );
    }
    let _ = std::fs::remove_file(output);
}

#[test]
fn elasticsearch_sink_analysis_keeps_source_independent_lineage_at_scale() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    ensure_elasticsearch_semantic_cache(&bin, &es);
    let output = temp_output_path("sink-analysis");
    let args = es_args(
        &es,
        &[
            "security",
            "{es}",
            "sink-analysis",
            "--profile",
            "production",
            "--sink",
            "^java\\.ssrf\\.apache_httpget_ctor$",
            "--format",
            "json",
            "--all",
            "--output-path",
            output.to_str().expect("temp output path utf8"),
            "--rules-dir",
            "{rules}",
        ],
    );
    let (stdout, elapsed) = assert_success_timed(&bin, &args);
    assert_performance(
        "Elasticsearch sink-centric upstream analysis",
        elapsed,
        // Sink lineage is an exact source-independent closure over the
        // persisted IDG. Its cold path is especially sensitive to shared
        // runner I/O; widen the default gate without adding any analysis cap.
        "BONSAI_ES_SINK_ANALYSIS_MAX_SECS",
        120,
    );
    assert!(
        stdout.trim().is_empty(),
        "sink-analysis with --output-path should keep stdout empty, got:\n{stdout}"
    );
    let written = std::fs::read_to_string(&output).expect("read sink-analysis output");
    let parsed: serde_json::Value = serde_json::from_str(&written)
        .unwrap_or_else(|error| panic!("valid sink-analysis JSON ({error}):\n{written}"));
    let rows = parsed
        .get("rows")
        .and_then(serde_json::Value::as_array)
        .expect("sink-analysis rows");
    assert!(
        !rows.is_empty(),
        "pinned Elasticsearch sink rule must match: {parsed}"
    );
    assert!(
        rows.iter().all(|row| {
            row.get("upstream_flows")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|flows| {
                    flows.iter().any(|flow| {
                        flow.get("endpoint_only").and_then(serde_json::Value::as_bool) == Some(false)
                            && flow
                                .get("taint_path")
                                .and_then(serde_json::Value::as_array)
                                .is_some_and(|path| !path.is_empty())
                    })
                })
        }),
        "every matched sink must retain a nontrivial source-independent compiler lineage: {parsed}"
    );
    assert!(
        parsed
            .pointer("/summary/upstream_flow_count")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|count| count >= rows.len() as u64),
        "sink-analysis summary lost upstream flow accounting: {parsed}"
    );
    let _ = std::fs::remove_file(output);
}

#[test]
fn elasticsearch_fresh_cache_taint_planning_does_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    let cache = temp_output_path("cold-cache");
    std::fs::create_dir_all(&cache).expect("create isolated Elasticsearch cache");
    let output = temp_output_path("cold-taint-summary");
    let args = es_args(
        &es,
        &[
            "security",
            "{es}",
            "taint-analysis",
            "--profile",
            "production",
            "--summary",
            "--format",
            "json",
            "--output-path",
            output.to_str().expect("temp output path utf8"),
            "--rules-dir",
            "{rules}",
        ],
    );
    let started = Instant::now();
    let mut command = bonsai_command(&bin, &args);
    command.env("BONSAI_WORKSPACE_DIR", &cache);
    let command_output = run_command_with_watchdog(&mut command, "cold Elasticsearch taint analysis");
    let stdout = assert_success_output(&args, command_output);
    let elapsed = started.elapsed();
    // The SLO assertion runs after exact completion; the independent test-only
    // watchdog exists solely to turn a scheduler hang into a bounded failure.
    assert_performance(
        "Elasticsearch fresh-cache production taint analysis",
        elapsed,
        "BONSAI_ES_COLD_TAINT_MAX_SECS",
        170,
    );
    assert!(
        stdout.trim().is_empty(),
        "cold taint-analysis with --output-path should keep stdout empty, got:\n{stdout}"
    );
    let written = std::fs::read_to_string(&output).expect("read cold taint summary output");
    let parsed: serde_json::Value = serde_json::from_str(&written)
        .unwrap_or_else(|error| panic!("valid cold taint summary JSON ({error}):\n{written}"));
    assert_eq!(
        parsed
            .get("analysis_complete")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "fresh-cache taint summary must report exact completed analysis: {parsed}"
    );
    assert_eq!(
        parsed
            .get("analysis_incomplete_reasons")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0),
        "fresh-cache taint summary must not hide unchecked compiler work: {parsed}"
    );
    let _ = std::fs::remove_file(output);
    let _ = std::fs::remove_dir_all(cache);
}
