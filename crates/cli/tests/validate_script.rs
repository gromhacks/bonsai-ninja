//! Release-binary validator bridge.
//!
//! `scripts/validate-mega-cli.py` is the canonical exhaustive
//! command/switch matrix: every supported language's `mega_flow`
//! fixture, every command family, every public switch family, stable
//! id drilldowns, and cache clear/rebuild. This integration test keeps
//! that controlled language matrix inside `cargo test` instead of
//! letting the Python script drift as a separate manual-only check.
//!
//! The script's default standalone mode also runs the Redis realworld
//! header/footer stress sweep. That sweep is intentionally left out of
//! this cargo bridge with `--skip-realworld`: cold realworld caches can
//! turn it into a benchmark-length run, while focused paging tests cover
//! the footer contract on normal test fixtures.
//!
//! The test skips when the release binary has not been built. The
//! intended full gate is:
//!
//! ```text
//! cargo build --release -p bonsai-ninja
//! cargo test -p bonsai-ninja
//! ```

use std::path::PathBuf;
use std::process::Command;
use std::{
    fs,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

// Both validators fan out into large command matrices. Running them in
// parallel competes for the same process and filesystem resources without
// testing any supported concurrency contract, so keep this bridge serial.
static VALIDATOR_LOCK: Mutex<()> = Mutex::new(());

fn validator_guard() -> MutexGuard<'static, ()> {
    VALIDATOR_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn validator_bin() -> Option<PathBuf> {
    let bin = repo_root().join("target/release/bonsai-ninja");
    if bin.exists() {
        return Some(bin);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    eprintln!(
        "skipping validator integration test: release binary not built ({})",
        bin.display()
    );
    None
}

#[test]
fn validate_mega_cli_script_language_matrix() {
    let _guard = validator_guard();
    let Some(bin) = validator_bin() else { return };
    let root = repo_root();
    let script = root.join("scripts/validate-mega-cli.py");
    let output = Command::new(&script)
        .arg("--bin")
        .arg(&bin)
        .arg("--skip-realworld")
        .current_dir(&root)
        .env("COLUMNS", "240")
        .output()
        .expect("run validate-mega-cli.py");

    assert!(
        output.status.success(),
        "validate-mega-cli.py failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn validate_pattern_pack_enforces_zero_collisions_and_example_drift() {
    let _guard = validator_guard();
    let Some(bin) = validator_bin() else {
        return;
    };
    let root = repo_root();
    let script = root.join("scripts/validate-pattern-pack.py");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis();
    let report_path = root
        .join("build")
        .join(format!("pattern-pack-validator-test-{stamp}.json"));

    let output = Command::new("python3")
        .arg(&script)
        .arg("--binary")
        .arg(&bin)
        .arg("--json-out")
        .arg(&report_path)
        .current_dir(&root)
        .env("COLUMNS", "240")
        .output()
        .expect("run validate-pattern-pack.py");

    let report_raw = fs::read_to_string(&report_path).unwrap_or_default();
    fs::remove_file(&report_path).ok();

    assert!(
        output.status.success(),
        "validate-pattern-pack.py failed with {}\nstdout:\n{}\nstderr:\n{}\nreport:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        report_raw
    );

    assert!(!report_raw.is_empty(), "validator did not write its JSON report");
    let report: serde_json::Value = serde_json::from_str(&report_raw).expect("validator report json");
    let failed = report
        .get("failed")
        .and_then(|v| v.as_array())
        .expect("failed array present");
    assert!(
        failed.is_empty(),
        "validator reported failed sections: {failed:?}"
    );

    let sections = report
        .get("sections")
        .and_then(|v| v.as_array())
        .expect("sections array present");
    let collisions = sections
        .iter()
        .find(|s| s.get("name").and_then(|v| v.as_str()) == Some("match-example-collisions"))
        .expect("match-example-collisions section present");
    let details = collisions.get("details").expect("collision details present");
    let count = |k: &str| -> usize {
        details
            .get(k)
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0)
    };
    assert_eq!(count("collisions"), 0, "expected zero match_example collisions");
    assert_eq!(count("owner_misses"), 0, "expected zero owner misses");
    assert_eq!(
        count("expected_text_misses"),
        0,
        "expected zero expected-text misses"
    );
    assert!(
        details.get("merge_candidates").is_some(),
        "collision report missing machine-readable merge_candidates"
    );
}
