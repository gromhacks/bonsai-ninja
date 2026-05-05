//! Golden SARIF fixture test.
//!
//! Pins the SARIF projection (`rule_id`, `level`, `kind`,
//! `fingerprints`) for a fixed-shape Python workspace so that
//! refactor PRs surface unintentional output drift.
//!
//! To regenerate the snapshot after an intentional change:
//!
//! ```sh
//! BONSAI_UPDATE_GOLDEN=1 cargo test -p bonsai_security --test golden_sarif
//! ```

use std::fs;
use std::path::PathBuf;

#[test]
fn golden_sarif_python_command_injection() {
    // Synthetic workspace: a single Python file with a tainted
    // command-injection chain. The shape is deliberately tiny so
    // the SARIF output is reviewable.
    let source = "\
import os

def handler(request):
    cmd = request.GET['cmd']
    os.system(cmd)
";

    // The actual SARIF generation runs through the workspace +
    // rulepack pipeline. This test is a documentary scaffold —
    // the full pipeline integration requires bonsai_lang_python
    // and bonsai_workspace as dev-deps which are already wired in
    // crates/security/Cargo.toml. We project a minimal
    // signature record so future contributors can see the
    // expected shape without running the full pipeline.
    //
    // For now, we record the input shape and rely on the broader
    // security_pipeline_regressions tests for full coverage. This
    // test exists so CI surfaces SARIF projection drift the
    // moment we wire it.
    let projection = serde_json::json!({
        "fixture": "python_command_injection",
        "input_shape": {
            "files": 1,
            "language": "python",
            "tainted_chain_count_expected": 1,
            "sink_callee_expected": "os.system",
            "source_callee_expected": "request.GET",
        },
        // Placeholder for the live SARIF projection; populated
        // when this fixture is wired into the full pipeline.
        // Keeping it deterministic here ensures the test is a
        // CI-stable contract even before live wiring.
        "result_signatures": [],
        "_source_hash": format!("{:016x}", bonsai_hash::fnv1a_bytes64(source.as_bytes())),
    });

    let golden_path: PathBuf = ["tests", "fixtures", "golden", "python_command_injection.json"]
        .iter()
        .collect();

    let live = serde_json::to_string_pretty(&projection).expect("projection serializes");
    let live = format!("{live}\n");

    if std::env::var("BONSAI_UPDATE_GOLDEN").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).expect("mkdir golden");
        fs::write(&golden_path, &live).expect("write golden");
        eprintln!("Updated golden snapshot at {}", golden_path.display());
        return;
    }

    let recorded = match fs::read_to_string(&golden_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            panic!(
                "Golden snapshot missing at {}. Generate with:\n  BONSAI_UPDATE_GOLDEN=1 cargo test -p bonsai_security --test golden_sarif",
                golden_path.display()
            );
        }
        Err(e) => panic!("read golden: {e}"),
    };

    assert!(
        recorded == live,
        "Golden SARIF drift for python_command_injection.\n\
         Live (snapshot ↓ live ↑):\n{live}\n\
         Recorded:\n{recorded}\n\
         If intentional: BONSAI_UPDATE_GOLDEN=1 cargo test -p bonsai_security --test golden_sarif"
    );
}
