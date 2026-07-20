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
use std::time::{SystemTime, UNIX_EPOCH};

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
    if path.exists() {
        Some(path)
    } else {
        eprintln!(
            "skipping elasticsearch large-repo test: release binary not built ({})",
            path.display()
        );
        None
    }
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
        eprintln!(
            "skipping elasticsearch large-repo test: checkout not found ({})",
            path.display()
        );
        None
    }
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

fn run_bonsai(bin: &Path, args: &[String]) -> Output {
    Command::new(bin)
        .args(args)
        .arg("--no-color")
        .arg("--no-progress")
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .unwrap_or_else(|err| panic!("run bonsai-ninja {args:?}: {err}"))
}

fn assert_success(bin: &Path, args: &[String]) -> String {
    let output = run_bonsai(bin, args);
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
    let commands: &[&[&str]] = &[
        &["tree", "{es}", "--max-depth", "1", "--compact", "--context", "4k"],
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
        let out = assert_success(&bin, &es_args(&es, command));
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
    let default_out = assert_success(
        &bin,
        &es_args(&es, &["inspect", "{es}", "--query", "execute", "--context", "8k"]),
    );
    assert!(
        default_out.contains("inspect `execute`"),
        "default inspect output lost query header:\n{default_out}"
    );
    let taint_out = assert_success(
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
        let out = assert_success(&bin, &es_args(&es, command));
        assert!(
            !out.trim().is_empty(),
            "bonsai-ninja {command:?} produced empty stdout"
        );
    }
}

#[test]
fn elasticsearch_full_taint_analysis_does_not_regress() {
    let _guard = elasticsearch_test_lock();
    let (Some(bin), Some(es)) = (release_bin(), elasticsearch_root()) else {
        return;
    };
    let output = temp_output_path("taint-summary");
    let args = es_args(
        &es,
        &[
            "security",
            "{es}",
            "taint-analysis",
            "--summary",
            "--format",
            "json",
            "--output-path",
            output.to_str().expect("temp output path utf8"),
            "--rules-dir",
            "{rules}",
        ],
    );
    // Correctness is not time-bounded: a large real workspace must run to a
    // semantic fixed point. Dedicated benchmark gates record wall time and
    // peak RSS without killing analysis or returning an incomplete result.
    let stdout = assert_success(&bin, &args);
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
    let _ = std::fs::remove_file(output);
}
