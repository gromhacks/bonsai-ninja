//! Taint test matrix — canonical "what flows do we model" suite.
//!
//! Aggregates 76 scenarios (intra / inter / cross-file / over-taint)
//! × 21 languages = up to 1596 cells; cells flagged `NotApplicable`
//! or `AdapterDeferred` in `applicability.rs` are skipped at runtime.
//! Coverage progress is visible via
//! `cargo test -p bonsai_taint --test matrix_coverage_report`.

#[path = "matrix/scenarios.rs"]
pub mod scenarios;

#[path = "matrix/applicability.rs"]
pub mod applicability;

#[path = "matrix/helpers.rs"]
pub mod helpers;

#[path = "matrix/intra/i_01.rs"]
mod i_01;

#[path = "matrix/intra/i_02.rs"]
mod i_02;

#[path = "matrix/intra/i_03.rs"]
mod i_03;

#[path = "matrix/intra/i_04.rs"]
mod i_04;

#[path = "matrix/intra/i_05.rs"]
mod i_05;

#[path = "matrix/intra/i_06.rs"]
mod i_06;

#[path = "matrix/intra/i_08.rs"]
mod i_08;

#[path = "matrix/intra/i_11.rs"]
mod i_11;

#[path = "matrix/intra/i_07.rs"]
mod i_07;

#[path = "matrix/intra/i_09.rs"]
mod i_09;

#[path = "matrix/intra/i_10.rs"]
mod i_10;

#[path = "matrix/intra/i_12.rs"]
mod i_12;

#[path = "matrix/intra/i_13.rs"]
mod i_13;

#[path = "matrix/intra/i_14.rs"]
mod i_14;

#[path = "matrix/intra/i_15.rs"]
mod i_15;

#[path = "matrix/intra/i_16.rs"]
mod i_16;

#[path = "matrix/intra/i_17.rs"]
mod i_17;

#[path = "matrix/intra/i_18.rs"]
mod i_18;

#[path = "matrix/intra/i_19.rs"]
mod i_19;

#[path = "matrix/intra/i_20.rs"]
mod i_20;

#[path = "matrix/inter/r_01.rs"]
mod r_01;

#[path = "matrix/inter/r_02.rs"]
mod r_02;

#[path = "matrix/inter/r_03.rs"]
mod r_03;

#[path = "matrix/inter/r_04.rs"]
mod r_04;

#[path = "matrix/inter/r_05.rs"]
mod r_05;

#[path = "matrix/inter/r_06.rs"]
mod r_06;

#[path = "matrix/inter/r_07.rs"]
mod r_07;

#[path = "matrix/inter/r_08.rs"]
mod r_08;

#[path = "matrix/inter/r_09.rs"]
mod r_09;

#[path = "matrix/inter/r_11.rs"]
mod r_11;

#[path = "matrix/inter/r_12.rs"]
mod r_12;

#[path = "matrix/inter/r_14.rs"]
mod r_14;

#[path = "matrix/inter/r_10.rs"]
mod r_10;

#[path = "matrix/inter/r_13.rs"]
mod r_13;

#[path = "matrix/inter/r_15.rs"]
mod r_15;

#[path = "matrix/inter/r_16.rs"]
mod r_16;

#[path = "matrix/inter/r_18.rs"]
mod r_18;

#[path = "matrix/inter/r_19.rs"]
mod r_19;

#[path = "matrix/inter/r_20.rs"]
mod r_20;

#[path = "matrix/inter/r_17.rs"]
mod r_17;

#[path = "matrix/cross_file/x_01.rs"]
mod x_01;

#[path = "matrix/cross_file/x_02.rs"]
mod x_02;

#[path = "matrix/cross_file/x_03.rs"]
mod x_03;

#[path = "matrix/over_taint/ot_01.rs"]
mod ot_01;

#[path = "matrix/over_taint/ot_02.rs"]
mod ot_02;

#[path = "matrix/over_taint/ot_03.rs"]
mod ot_03;

#[path = "matrix/over_taint/ot_04.rs"]
mod ot_04;

#[path = "matrix/over_taint/ot_07.rs"]
mod ot_07;

#[path = "matrix/over_taint/ot_12.rs"]
mod ot_12;

#[path = "matrix/over_taint/ot_15.rs"]
mod ot_15;

#[path = "matrix/over_taint/ot_16.rs"]
mod ot_16;

#[path = "matrix/over_taint/ot_17.rs"]
mod ot_17;

#[path = "matrix/over_taint/ot_19.rs"]
mod ot_19;

#[path = "matrix/cross_file/x_04.rs"]
mod x_04;

#[path = "matrix/cross_file/x_05.rs"]
mod x_05;

#[path = "matrix/cross_file/x_06.rs"]
mod x_06;

#[path = "matrix/cross_file/x_07.rs"]
mod x_07;

#[path = "matrix/cross_file/x_08.rs"]
mod x_08;

#[path = "matrix/cross_file/x_09.rs"]
mod x_09;

#[path = "matrix/cross_file/x_10.rs"]
mod x_10;

#[path = "matrix/cross_file/x_11.rs"]
mod x_11;

#[path = "matrix/cross_file/x_12.rs"]
mod x_12;

#[path = "matrix/cross_file/x_13.rs"]
mod x_13;

#[path = "matrix/cross_file/x_14.rs"]
mod x_14;

#[path = "matrix/cross_file/x_15.rs"]
mod x_15;

#[path = "matrix/cross_file/x_16.rs"]
mod x_16;

#[path = "matrix/over_taint/ot_05.rs"]
mod ot_05;

#[path = "matrix/over_taint/ot_06.rs"]
mod ot_06;

#[path = "matrix/over_taint/ot_08.rs"]
mod ot_08;

#[path = "matrix/over_taint/ot_09.rs"]
mod ot_09;

#[path = "matrix/over_taint/ot_10.rs"]
mod ot_10;

#[path = "matrix/over_taint/ot_11.rs"]
mod ot_11;

#[path = "matrix/over_taint/ot_13.rs"]
mod ot_13;

#[path = "matrix/over_taint/ot_14.rs"]
mod ot_14;

#[path = "matrix/over_taint/ot_18.rs"]
mod ot_18;

#[path = "matrix/over_taint/ot_20.rs"]
mod ot_20;
