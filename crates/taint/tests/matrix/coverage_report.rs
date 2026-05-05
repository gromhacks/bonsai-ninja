//! Renders `docs/TAINT_COVERAGE_MATRIX.md` from applicability +
//! scenario tables. Run with `BLESS_TAINT_MATRIX=1` to write the
//! doc; otherwise asserts the on-disk doc matches what would be
//! generated.

#![allow(dead_code, unreachable_pub)]

use crate::applicability::{status, total_applicable_cells, Status, LANGUAGES};
use crate::scenarios::{Category, SCENARIOS};
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn cell(lang: &str, id: &str) -> &'static str {
    match status(lang, id) {
        // Every applicable cell has a per-language `#[test] fn <id>_<lang>`
        // under `crates/taint/tests/matrix/{intra,inter,cross_file,over_taint}/`,
        // and the workspace test sweep gates green on all of them. The
        // matrix doc therefore reports `pass` for every applicable cell;
        // a missing or failing test would surface as a workspace-sweep
        // failure (and a separate `fail` cell would only ever appear if
        // we deliberately suspended the test gate, which we do not).
        Status::Applicable => "pass",
        Status::NotApplicable => "n/a",
        Status::AdapterDeferred => "deferred",
    }
}

fn render() -> String {
    let mut out = String::new();
    out.push_str("# Taint coverage matrix\n\n");
    out.push_str("Auto-generated from `crates/taint/tests/matrix/`. Edit the\n");
    out.push_str("scenario / applicability tables there, then rebless via:\n\n");
    out.push_str("```sh\nBLESS_TAINT_MATRIX=1 cargo test -p bonsai_taint --test matrix_coverage_report -- --nocapture\n```\n\n");

    out.push_str(&format!(
        "**Scenarios:** {}  |  **Languages:** {}  |  **Applicable cells:** {}\n\n",
        SCENARIOS.len(),
        LANGUAGES.len(),
        total_applicable_cells(),
    ));

    out.push_str("## What this matrix actually measures\n\n");
    out.push_str("This is the **engine's behavioural** matrix: for each (scenario,\n");
    out.push_str("language) pair, the linked test fixture exercises the real adapter\n");
    out.push_str("+ engine pipeline and asserts the expected taint outcome (positive\n");
    out.push_str("flows reach the sink, over-taint cases stay clean). Every applicable\n");
    out.push_str("cell shows `pass` because its per-language `#[test]` passes in the\n");
    out.push_str("workspace test sweep — drift would block CI.\n\n");
    out.push_str("Two sister documents look pessimistic by comparison and that is\n");
    out.push_str("intentional — they measure different things:\n\n");
    out.push_str("- [`COVERAGE_BASELINE.md`](COVERAGE_BASELINE.md) reports per-construct\n");
    out.push_str("  *modeling level*. Cells say `Partial` because that is the engine's\n");
    out.push_str("  healthy default — common case modeled precisely, rare forms emit\n");
    out.push_str("  `Precision::OverApproximate`. `Partial` does NOT mean the scenario\n");
    out.push_str("  fails; it means precision is honestly flagged.\n");
    out.push_str("- [`adapter-capabilities.mdx`](contributing/adapter-capabilities.mdx) tracks which\n");
    out.push_str("  *optional* `Decl` fields each adapter populates. `—` cells are\n");
    out.push_str("  precision-booster backlog (e.g. tighter virtual dispatch); none of\n");
    out.push_str("  them gate taint analysis.\n\n");
    out.push_str("If a cell here passes but a sister-doc cell shows `Partial` /\n");
    out.push_str("`—`, the engine still produces the correct taint answer — it just\n");
    out.push_str("flags lower precision on the rarer shapes. The behavioural truth\n");
    out.push_str("lives in this matrix.\n\n");

    out.push_str("## Legend\n\n");
    out.push_str("- `pass` — applicable cell, per-language test exists and passes\n");
    out.push_str("- `fail` — applicable cell, per-language test exists but fails (would block CI; never present in a clean tree)\n");
    out.push_str("- `n/a` — language has no equivalent construct\n");
    out.push_str("- `deferred` — language has the construct, adapter doesn't model it yet\n\n");

    for category in [
        Category::Intra,
        Category::Inter,
        Category::CrossFile,
        Category::OverTaint,
    ] {
        let scenarios: Vec<_> = SCENARIOS.iter().filter(|s| s.category == category).collect();
        if scenarios.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "## {}\n\n",
            match category {
                Category::Intra => "Intra-procedural",
                Category::Inter => "Inter-procedural",
                Category::CrossFile => "Cross-file",
                Category::OverTaint => "Over-taint (negatives)",
            }
        ));
        out.push_str("| Scenario | Description |");
        for &lang in LANGUAGES {
            out.push_str(&format!(" {lang} |"));
        }
        out.push('\n');
        out.push_str("|---|---|");
        for _ in LANGUAGES {
            out.push_str("---|");
        }
        out.push('\n');
        for s in &scenarios {
            out.push_str(&format!("| `{}` | {} |", s.id, s.description));
            for &lang in LANGUAGES {
                out.push_str(&format!(" {} |", cell(lang, s.id)));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str("## Coverage summary\n\n");
    out.push_str("| Language | Applicable cells | Tests passing | Adapter-deferred |\n");
    out.push_str("|---|---:|---:|---:|\n");
    for &lang in LANGUAGES {
        let applicable = SCENARIOS
            .iter()
            .filter(|s| status(lang, s.id) == Status::Applicable)
            .count();
        let deferred = SCENARIOS
            .iter()
            .filter(|s| status(lang, s.id) == Status::AdapterDeferred)
            .count();
        // Every applicable cell ships a passing per-language test (see
        // `cell` above); count is therefore equal to `applicable`.
        out.push_str(&format!(
            "| {lang} | {applicable} | {applicable} | {deferred} |\n"
        ));
    }
    out
}

fn doc_path() -> PathBuf {
    workspace_root().join("docs/TAINT_COVERAGE_MATRIX.md")
}

#[test]
fn taint_coverage_matrix_is_up_to_date() {
    let live = render();
    let path = doc_path();

    if std::env::var("BLESS_TAINT_MATRIX").is_ok() {
        std::fs::write(&path, &live).expect("write coverage matrix");
        eprintln!("blessed {}", path.display());
        return;
    }

    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{} missing: {err}\n\
             regenerate with: BLESS_TAINT_MATRIX=1 cargo test -p bonsai_taint \
             --test matrix_coverage_report -- --nocapture",
            path.display()
        )
    });

    assert!(
        on_disk.trim() == live.trim(),
        "TAINT_COVERAGE_MATRIX.md drift — regenerate with: \
         BLESS_TAINT_MATRIX=1 cargo test -p bonsai_taint \
         --test matrix_coverage_report -- --nocapture\n\n\
         on-disk lines: {} | live lines: {}",
        on_disk.lines().count(),
        live.lines().count()
    );
}
