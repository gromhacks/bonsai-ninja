//! language but our adapter doesn't model it yet. The cell is
//! skipped with an explicit follow-up note in the coverage report.
//!
//! Edits here change the matrix shape: re-bless the rendered doc
//! after touching this file.

#![allow(dead_code, unreachable_pub)]

use crate::scenarios::SCENARIOS;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Applicable,
    NotApplicable,
    AdapterDeferred,
}

pub const LANGUAGES: &[&str] = &[
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

/// Returns the applicability status for `(lang, scenario_id)`.
///
/// Default policy: every cell is `Applicable` unless explicitly
/// listed below as `NotApplicable` (language doesn't have the
/// construct) or `AdapterDeferred` (construct exists but adapter
/// doesn't model it yet).
pub fn status(lang: &str, scenario_id: &str) -> Status {
    for table in [OVERRIDES, COVERAGE_GAP_OVERRIDES] {
        for &(l, ids, status) in table {
            if l == lang && ids.contains(&scenario_id) {
                return status;
            }
        }
    }
    Status::Applicable
}

/// Per-language overrides. Each entry is `(language, &[scenario_id, ...], Status)`.
/// Curated based on language semantics; defensible per-cell.
const OVERRIDES: &[(&str, &[&str], Status)] = &[
    // --- C: minimal language; no OO, no async, no exceptions, no generics, no pattern match.
    (
        "c",
        &[
            "I_05", "I_13", "I_14", "I_15", "I_16", "I_17", "I_18", "I_19", "R_03", "R_04", "R_05", "R_06",
            "R_11", "R_12", "R_14", "R_19", "R_20", "X_05", "X_06", "X_07", "X_08", "X_10", "X_11", "X_12",
            "X_13", "X_14",
        ],
        Status::NotApplicable,
    ),
    (
        "c",
        &["OT_18"],
        Status::NotApplicable, // type annotation - declarations are types, not annotations
    ),
    // --- C++: has templates/generics, RAII, but no async/await language keyword (std::async is library)
    (
        "cpp",
        &["R_11", "R_12", "I_16", "I_17", "X_07", "X_08"],
        Status::NotApplicable,
    ),
    // --- C#: full OO, async, generics, attributes. No macros.
    ("csharp", &["I_20", "X_07", "X_08"], Status::NotApplicable),
    // --- Dart: async/await, generics, futures. No macros, no reflection.
    ("dart", &["X_07", "X_08", "OT_05", "OT_06"], Status::NotApplicable),
    // --- Elixir: functional, pattern-match, no exceptions per se, no generics.
    (
        "elixir",
        &[
            "I_03", "I_05", "I_13", "I_14", "I_15", "R_05", "R_06", "R_08", "R_11", "R_14", "R_18", "X_05",
            "X_07", "X_08", "X_10", "X_11", "X_12", "X_13", "X_14", "OT_05", "OT_06",
        ],
        Status::NotApplicable,
    ),
    // --- Erlang: similar functional shape, even fewer constructs than Elixir.
    (
        "erlang",
        &[
            "I_03", "I_05", "I_13", "I_14", "I_15", "I_18", "I_19", "I_20", "R_03", "R_04", "R_05", "R_06",
            "R_08", "R_11", "R_12", "R_14", "R_18", "X_05", "X_07", "X_08", "X_10", "X_11", "X_12", "X_13",
            "X_14", "OT_05", "OT_06",
        ],
        Status::NotApplicable,
    ),
    // --- Go: no exceptions, no async/await (goroutines), no pattern match, no generics pre-1.18 (we model 1.18+)
    (
        "go",
        &[
            "I_13", "I_14", "I_15", "I_16", "I_17", "R_11", "X_05", "X_07", "X_08", "X_10", "OT_18",
        ],
        Status::NotApplicable,
    ),
    // --- Java: full OO, generics, exceptions. No async/await keyword (CompletableFuture is library), no coroutines.
    (
        "java",
        &["R_11", "R_12", "X_05", "X_07", "X_08", "X_10"],
        Status::NotApplicable,
    ),
    // --- JavaScript: dynamic OO, async, generators. No generics, no macros, no pattern match.
    (
        "javascript",
        &["I_16", "OT_05", "OT_06", "OT_18"],
        Status::NotApplicable,
    ),
    (
        "javascript",
        &["R_03"],
        Status::AdapterDeferred, // untyped receiver dispatch needs concrete type evidence, not name fan-out
    ),
    // --- Kotlin: like Java + suspend (coroutines). No macros.
    ("kotlin", &["X_05", "X_07", "X_08", "X_10"], Status::NotApplicable),
    // --- Lua: minimal language. No exceptions per se, no async, no generics.
    (
        "lua",
        &[
            "I_13", "I_14", "I_15", "I_16", "I_17", "R_05", "R_06", "R_11", "R_14", "X_05", "X_06", "X_07",
            "X_08", "X_10", "X_11", "X_12", "X_13", "X_14", "OT_05", "OT_06", "OT_18",
        ],
        Status::NotApplicable,
    ),
    // --- Objective-C: ObjC + C interop. No async/await, no generics on methods.
    (
        "objc",
        &["I_16", "R_11", "R_12", "X_05", "X_07", "X_08", "X_10"],
        Status::NotApplicable,
    ),
    // --- Perl: minimal modern features. No async, no generics, no formal exceptions, no pattern match.
    (
        "perl",
        &[
            "I_05", "I_13", "I_14", "I_15", "I_16", "I_17", "R_05", "R_06", "R_11", "R_12", "R_14", "X_05",
            "X_06", "X_07", "X_08", "X_10", "OT_05", "OT_06", "OT_18",
        ],
        Status::NotApplicable,
    ),
    (
        "perl",
        &["R_03"],
        Status::AdapterDeferred, // Perl5 method dispatch lacks semantic receiver class evidence in this fixture
    ),
    // --- PHP: OO, traits. No async/await keyword (8+ Fibers but distinct). No generics.
    (
        "php",
        &[
            "I_16", "R_11", "R_12", "X_05", "X_07", "X_08", "X_10", "OT_05", "OT_06", "OT_18",
        ],
        Status::NotApplicable,
    ),
    // --- Python: OO, generators, async. PEP 634 match in 3.10+. No formal generics on funcs.
    (
        "python",
        &["X_05", "X_07", "X_08", "X_10", "OT_05", "OT_06"],
        Status::NotApplicable,
    ),
    // --- Ruby: blocks, fibers (coroutines), no async/await, no generics.
    (
        "ruby",
        &["R_11", "X_05", "X_07", "X_08", "X_10", "OT_05", "OT_06", "OT_18"],
        Status::NotApplicable,
    ),
    (
        "ruby",
        &["R_03"],
        Status::AdapterDeferred, // untyped receiver dispatch would otherwise require unsafe method-name fan-out
    ),
    // --- Rust: traits, generics, async. No exceptions (Result), no coroutines (unstable).
    (
        "rust",
        &["I_13", "I_14", "I_15", "R_12", "X_05", "X_07", "X_08", "X_10"],
        Status::NotApplicable,
    ),
    // --- Scala: full FP/OO mix. Generics, pattern match, async via library.
    ("scala", &["X_05", "X_07", "X_08", "X_10"], Status::NotApplicable),
    // --- Solidity: contracts only. No async, no generics, no FFI, very limited stdlib.
    (
        "solidity",
        &[
            "I_05", "I_15", "I_16", "I_17", "I_18", "I_19", "I_20", "R_05", "R_08", "R_11", "R_12", "R_13",
            "R_14", "R_17", "R_19", "R_20", "X_02", "X_03", "X_04", "X_05", "X_06", "X_07", "X_08", "X_09",
            "X_10", "OT_05", "OT_06", "OT_18",
        ],
        Status::NotApplicable,
    ),
    // --- Swift: full OO + protocols + async/await. No macros, no FFI on language level.
    ("swift", &["X_05", "X_07", "X_08", "X_10"], Status::NotApplicable),
    (
        "swift",
        &["X_01", "X_02", "X_03"],
        Status::AdapterDeferred, // needs Swift target/module identity instead of file-stem fallback
    ),
    // --- TypeScript: like JS + generics + decorators. No macros, no pattern match.
    ("typescript", &["I_16", "OT_05", "OT_06"], Status::NotApplicable),
];

/// Cells where the language construct exists but the matrix does not
/// yet ship an executable semantic fixture, plus a few cells that were
/// historically left applicable even though the language has no matching
/// construct. Keeping these separate from the semantic table above makes
/// the current behavioural contract explicit: `Applicable` means there
/// is a concrete per-language test function that runs.
const COVERAGE_GAP_OVERRIDES: &[(&str, &[&str], Status)] = &[
    (
        "cpp",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "csharp",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints delegate value, not sink in body
    ),
    (
        "dart",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "go",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "java",
        &["I_18"],
        Status::AdapterDeferred, // lambda body invocation currently taints functional value, not sink in body
    ),
    (
        "javascript",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "kotlin",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "lua",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "python",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "rust",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "scala",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "swift",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    (
        "typescript",
        &["I_18"],
        Status::AdapterDeferred, // closure body invocation currently taints closure value, not sink in body
    ),
    // Cross-file scenarios below still have single-file placeholder
    // fixtures. They must not count as semantic import/module-flow
    // coverage until each cell has a real multi-file fixture.
    ("c", &["X_04", "X_15", "X_16"], Status::AdapterDeferred),
    ("c", &["X_09"], Status::NotApplicable),
    (
        "cpp",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("cpp", &["X_05", "X_09", "X_10"], Status::NotApplicable),
    (
        "csharp",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("csharp", &["X_05", "X_09", "X_10"], Status::NotApplicable),
    (
        "dart",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("dart", &["X_05", "X_09", "X_10"], Status::NotApplicable),
    (
        "elixir",
        &["X_04", "X_06", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("elixir", &["X_09"], Status::NotApplicable),
    (
        "erlang",
        &["X_04", "X_06", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("erlang", &["X_09"], Status::NotApplicable),
    (
        "go",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("go", &["X_09"], Status::NotApplicable),
    (
        "java",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("java", &["X_09"], Status::NotApplicable),
    (
        "javascript",
        &[
            "X_04", "X_05", "X_06", "X_08", "X_09", "X_10", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16",
        ],
        Status::AdapterDeferred,
    ),
    ("javascript", &["X_07"], Status::NotApplicable),
    (
        "kotlin",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("kotlin", &["X_09"], Status::NotApplicable),
    ("lua", &["X_04", "X_15", "X_16"], Status::AdapterDeferred),
    ("lua", &["X_09"], Status::NotApplicable),
    (
        "objc",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("objc", &["X_09"], Status::NotApplicable),
    (
        "perl",
        &["X_04", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("perl", &["X_02", "X_09"], Status::NotApplicable),
    (
        "php",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("php", &["X_09"], Status::NotApplicable),
    (
        "python",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("python", &["X_09"], Status::NotApplicable),
    (
        "ruby",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("ruby", &["X_09"], Status::NotApplicable),
    (
        "rust",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("rust", &["X_09"], Status::NotApplicable),
    (
        "scala",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("scala", &["X_09"], Status::NotApplicable),
    (
        "solidity",
        &["X_01", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    (
        "swift",
        &["X_04", "X_06", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16"],
        Status::AdapterDeferred,
    ),
    ("swift", &["X_09"], Status::NotApplicable),
    (
        "typescript",
        &[
            "X_04", "X_05", "X_06", "X_08", "X_09", "X_10", "X_11", "X_12", "X_13", "X_14", "X_15", "X_16",
        ],
        Status::AdapterDeferred,
    ),
    ("typescript", &["X_07"], Status::NotApplicable),
    ("c", &["I_11", "R_13", "R_18", "OT_16"], Status::NotApplicable),
    ("c", &["R_09", "R_10"], Status::AdapterDeferred),
    (
        "cpp",
        &["I_14", "I_19", "R_05", "R_06", "R_09", "R_10", "R_18", "R_19"],
        Status::AdapterDeferred,
    ),
    ("cpp", &["R_13", "R_20"], Status::NotApplicable),
    (
        "csharp",
        &["I_14", "I_19", "R_09", "R_10"],
        Status::AdapterDeferred,
    ),
    (
        "dart",
        &["I_14", "R_08", "R_09", "R_10", "R_12"],
        Status::AdapterDeferred,
    ),
    ("dart", &["R_14", "R_19"], Status::NotApplicable),
    (
        "elixir",
        &["I_17", "R_04", "R_12", "R_19", "OT_16"],
        Status::NotApplicable,
    ),
    (
        "elixir",
        &["I_19", "R_09", "R_10", "R_17"],
        Status::AdapterDeferred,
    ),
    (
        "erlang",
        &["I_17", "R_19", "R_20", "OT_16"],
        Status::NotApplicable,
    ),
    ("erlang", &["R_09", "R_10"], Status::AdapterDeferred),
    (
        "go",
        &["R_05", "R_06", "R_12", "R_14", "R_18", "R_20"],
        Status::NotApplicable,
    ),
    (
        "go",
        &["I_19", "R_08", "R_09", "R_10", "R_19"],
        Status::AdapterDeferred,
    ),
    ("java", &["R_13", "R_18", "R_20"], Status::NotApplicable),
    (
        "java",
        &["I_14", "I_16", "I_19", "R_08", "R_09", "R_10", "R_17"],
        Status::AdapterDeferred,
    ),
    ("javascript", &["R_14"], Status::NotApplicable),
    (
        "javascript",
        &["I_19", "R_05", "R_08", "R_20"],
        Status::AdapterDeferred,
    ),
    (
        "kotlin",
        &["I_19", "R_05", "R_08", "R_09", "R_10", "R_17", "R_19", "R_20"],
        Status::AdapterDeferred,
    ),
    ("lua", &["I_03", "R_20"], Status::NotApplicable),
    (
        "lua",
        &["I_19", "R_04", "R_08", "R_09", "R_10", "R_12", "R_19"],
        Status::AdapterDeferred,
    ),
    ("objc", &["R_13", "R_14", "R_18"], Status::NotApplicable),
    (
        "objc",
        &["I_14", "I_19", "R_06", "R_09", "R_10", "R_19", "R_20"],
        Status::AdapterDeferred,
    ),
    ("perl", &["R_20"], Status::NotApplicable),
    (
        "perl",
        &["I_18", "I_19", "R_08", "R_09", "R_10", "R_19"],
        Status::AdapterDeferred,
    ),
    ("php", &["R_14"], Status::NotApplicable),
    (
        "php",
        &["I_19", "R_05", "R_08", "R_09", "R_10", "R_17", "R_19"],
        Status::AdapterDeferred,
    ),
    ("python", &["I_17", "R_14"], Status::NotApplicable),
    ("python", &["R_05", "R_08"], Status::AdapterDeferred),
    ("ruby", &["I_17", "R_14"], Status::NotApplicable),
    (
        "ruby",
        &["I_14", "I_16", "I_19", "R_05", "R_08", "R_09", "R_10", "R_17"],
        Status::AdapterDeferred,
    ),
    (
        "rust",
        &["I_17", "R_14", "R_18", "R_19", "R_20"],
        Status::NotApplicable,
    ),
    ("rust", &["I_19", "R_06", "R_10"], Status::AdapterDeferred),
    ("scala", &["I_17", "R_12"], Status::NotApplicable),
    (
        "scala",
        &["I_19", "R_05", "R_08", "R_09", "R_10", "R_19"],
        Status::AdapterDeferred,
    ),
    ("solidity", &["R_18"], Status::NotApplicable),
    ("solidity", &["I_14", "R_09", "R_10"], Status::AdapterDeferred),
    ("swift", &["R_12"], Status::NotApplicable),
    (
        "swift",
        &["I_14", "I_19", "R_05", "R_08", "R_09", "R_10"],
        Status::AdapterDeferred,
    ),
    (
        "typescript",
        &["R_05", "R_08", "R_14", "R_20"],
        Status::AdapterDeferred,
    ),
];

/// Total scenarios = 76. Used in coverage reporting.
pub const TOTAL_SCENARIOS: usize = 76;

/// Total languages = 21.
pub const TOTAL_LANGUAGES: usize = 21;

/// Computed at runtime: total `Applicable` cells across the matrix.
pub fn total_applicable_cells() -> usize {
    let mut count = 0;
    for &lang in LANGUAGES {
        for s in SCENARIOS {
            if status(lang, s.id) == Status::Applicable {
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
#[path = "applicability_sanity.rs"]
mod sanity;
