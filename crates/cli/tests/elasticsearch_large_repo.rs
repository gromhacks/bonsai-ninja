//! Large-repo regression tests against a real Elasticsearch checkout.
//!
//! These tests are intentionally integration-level. They run the compiled
//! release binary against `../elasticsearch` and assert that broad code
//! intelligence and security commands keep working on the same production
//! sized repo we use manually. If the checkout is absent, the tests skip
//! so normal CI remains portable.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
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
    let args = es_args(&es, &["index", "{es}"]);

    let cold_started = Instant::now();
    let cold_output = bonsai_command(&bin, &args)
        .env("BONSAI_WORKSPACE_DIR", &cache)
        .output()
        .unwrap_or_else(|error| panic!("run cold Elasticsearch structural index: {error}"));
    let cold = assert_success_output(&args, cold_output);
    let cold_elapsed = cold_started.elapsed();
    assert_performance(
        "Elasticsearch fresh-cache structural index",
        cold_elapsed,
        "BONSAI_ES_COLD_STRUCTURAL_INDEX_MAX_SECS",
        90,
    );
    let cold: serde_json::Value = serde_json::from_str(&cold).expect("cold structural index JSON");
    assert_eq!(cold["compiler_cache"], "rebuilt", "{cold}");
    assert!(
        cold["files"].as_u64().is_some_and(|files| files >= 30_000) && cold["parsed_files"] == cold["files"],
        "cold structural index must compile the complete Elasticsearch source set: {cold}"
    );

    let warm_started = Instant::now();
    let warm_output = bonsai_command(&bin, &args)
        .env("BONSAI_WORKSPACE_DIR", &cache)
        .output()
        .unwrap_or_else(|error| panic!("run warm Elasticsearch structural index: {error}"));
    let warm = assert_success_output(&args, warm_output);
    let warm_elapsed = warm_started.elapsed();
    assert_performance(
        "Elasticsearch warm structural index",
        warm_elapsed,
        "BONSAI_ES_WARM_STRUCTURAL_INDEX_MAX_SECS",
        10,
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
    bonsai_command(bin, args)
        .output()
        .unwrap_or_else(|err| panic!("run bonsai-ninja {args:?}: {err}"))
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
         this gate never terminates or caps analysis. Set {variable} only when \
         intentionally calibrating a slower performance host"
    );
    eprintln!("{label} completed in {elapsed:.2?} (SLO {limit:.2?})");
}

fn assert_success_timed(bin: &Path, args: &[String]) -> (String, Duration) {
    let started = Instant::now();
    let output = assert_success(bin, args);
    (output, started.elapsed())
}

fn ensure_elasticsearch_semantic_cache(bin: &Path, es: &Path) {
    static PREWARM: OnceLock<Result<(), String>> = OnceLock::new();
    PREWARM
        .get_or_init(|| {
            let started = Instant::now();
            let args = es_args(es, &["index", "--semantic", "{es}"]);
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
            eprintln!(
                "Elasticsearch semantic generation ready in {:.2?}",
                started.elapsed()
            );

            // A stale exact generation may take real compiler work. The next
            // fresh process must validate and reuse it quickly. This measures
            // completed work; it never kills analysis, narrows files, or caps
            // graph closure/results.
            let warm_args = es_args(es, &["index", "--semantic", "{es}"]);
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
            let warm_limit = performance_limit("BONSAI_ES_WARM_INDEX_MAX_SECS", 15);
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
            30,
        );
        assert!(
            !out.trim().is_empty(),
            "bonsai-ninja {command:?} produced empty stdout"
        );
    }
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
        &es_args(&es, &["inspect", "{es}", "--query", "execute", "--context", "8k"]),
    );
    assert_performance(
        "Elasticsearch default inspect",
        default_elapsed,
        "BONSAI_ES_INSPECT_MAX_SECS",
        30,
    );
    assert!(
        default_out.contains("inspect `execute`"),
        "default inspect output lost query header:\n{default_out}"
    );
    let (taint_out, taint_elapsed) = assert_success_timed(
        &bin,
        &es_args(
            &es,
            &[
                "inspect",
                "{es}",
                "--query",
                "execute",
                "--taint-flow",
                "--context",
                "8k",
            ],
        ),
    );
    assert_performance(
        "Elasticsearch inspect --taint-flow",
        taint_elapsed,
        "BONSAI_ES_INSPECT_MAX_SECS",
        30,
    );
    assert!(
        taint_out.contains("TAINT FLOWS") || taint_out.contains("taint flow"),
        "explicit inspect --taint-flow did not render taint-flow evidence:\n{taint_out}"
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
        let (out, elapsed) = assert_success_timed(&bin, &args);
        assert_performance(
            &format!("Elasticsearch security inventory command {command:?}"),
            elapsed,
            "BONSAI_ES_SECURITY_INVENTORY_MAX_SECS",
            30,
        );
        assert!(
            !out.trim().is_empty(),
            "bonsai-ninja {command:?} produced empty stdout"
        );
    }
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
    // Correctness is not time-bounded: the command first runs to its semantic
    // fixed point. The performance assertion is evaluated only after that
    // completed result, so it cannot kill or silently truncate analysis.
    let (stdout, elapsed) = assert_success_timed(&bin, &args);
    assert_performance(
        "Elasticsearch warm production taint analysis",
        elapsed,
        "BONSAI_ES_TAINT_MAX_SECS",
        30,
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
    let command_output = bonsai_command(&bin, &args)
        .env("BONSAI_WORKSPACE_DIR", &cache)
        .output()
        .unwrap_or_else(|error| panic!("run cold Elasticsearch taint analysis: {error}"));
    let stdout = assert_success_output(&args, command_output);
    let elapsed = started.elapsed();
    // This assertion runs only after the exact command exits. It cannot time
    // out, cap, or truncate semantic work.
    assert_performance(
        "Elasticsearch fresh-cache production taint analysis",
        elapsed,
        "BONSAI_ES_COLD_TAINT_MAX_SECS",
        45,
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
