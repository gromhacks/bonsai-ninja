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
    for &(l, ids, status) in OVERRIDES {
        if l == lang && ids.contains(&scenario_id) {
            return status;
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
    (
        "php",
        &["R_03"],
        Status::AdapterDeferred, // requires typed receiver evidence; untyped $args->method must not fan out by name
    ),
    // --- Python: OO, generators, async. PEP 634 match in 3.10+. No formal generics on funcs.
    (
        "python",
        &["X_05", "X_07", "X_08", "X_10", "OT_05", "OT_06"],
        Status::NotApplicable,
    ),
    (
        "python",
        &["R_03"],
        Status::AdapterDeferred, // unannotated receiver dispatch is dynamic; exact pass needs a type annotation
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
