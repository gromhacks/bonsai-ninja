//! Driver binary for the taint coverage report.
//!
//! See `crates/taint/tests/matrix/coverage_report.rs` for the
//! generator. This wrapper exists because Rust integration tests are
//! one binary per top-level `tests/*.rs` file.

#[path = "matrix/scenarios.rs"]
pub mod scenarios;

#[path = "matrix/applicability.rs"]
pub mod applicability;

#[path = "matrix/coverage_report.rs"]
mod coverage_report;
