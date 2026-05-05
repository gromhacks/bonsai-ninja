//! Per-function return-taint summary types and the public
//! [`function_summary`] accessor.
//!
//! The implementation of `compute_function_summary` and its helpers
//! (~900 lines of cross-event analysis) lives in `inter/mod.rs`
//! alongside the rest of the engine because it depends on several
//! private helpers (`assign_chain_taints`, `insert_value_target_taint`,
//! `insert_descendant_target_taint`, `arg_text_is_tainted`). The
//! types themselves are stable and ergonomic to live next to their
//! documentation.
//!
//! Why a separate file: contributors looking for "what is the
//! function summary returning?" should be able to find the field
//! definitions without scrolling past 4500 lines of propagation
//! logic. The implementation is one function-call away (`super::`).

use bonsai_common::{FuncId, SymbolId};
use bonsai_db::AnalyzerDb;

/// Per-function return-taint summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FunctionSummary {
    /// Parameter indices that transit to the function's return value.
    /// `returns_taint_of = {0, 2}` means: tainting param 0 or param 2
    /// on entry produces a tainted return. Other callers use this to
    /// decide whether `y = callee(x)` taints `y` when `x` is at a
    /// matching position.
    pub returns_taint_of: Vec<usize>,
    /// Parameter indices whose explicitly tainted descendants transit
    /// to the return. This is distinct from whole-parameter taint:
    /// `return client.capacity` should not transit from a bare
    /// lifecycle-tainted `client`, but `return repo.data.cmd` should
    /// transit when the caller had proven `repo.*` tainted.
    pub returns_descendant_taint_of: Vec<usize>,
    /// Parameter indices whose direct value is embedded into a newly
    /// returned container. `return {"value": param0}` should make the
    /// caller's LHS carry descendant taint (`lhs.*`) without making every
    /// ordinary `param0.field` read tainted.
    pub returns_container_taint_of: Vec<usize>,
    /// Exact parameter access paths returned by the function.
    /// `(0, "cmd")` means `return param0.cmd` or an alias of it.
    /// This lets callers propagate `arg.cmd` without promoting
    /// sibling taint such as `arg.user`.
    pub returns_access_paths: Vec<ReturnAccessPath>,
    /// Parameter-to-parameter side effects. `(3, 0)` means taint in
    /// param 3 can be written into param 0 before the function
    /// returns, e.g. C-style `join(dst, cap, sep, tok)` writing
    /// `tok` into `dst`.
    pub taints_params_from: Vec<ParamSideEffect>,
}

/// One field-of-parameter access path that the function returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnAccessPath {
    pub param: usize,
    pub path: String,
}

/// One parameter-to-parameter side effect: tainting `source_param` on
/// entry can taint `target_param` by the time the function returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamSideEffect {
    pub source_param: usize,
    pub target_param: usize,
}

/// Public accessor: return-taint summary for one function.
/// Computed on demand; the result is cheap enough that caching is
/// left to the caller (the inter pass builds its own per-run map).
#[must_use]
pub fn function_summary(db: &AnalyzerDb, func: FuncId) -> FunctionSummary {
    let global = db.global_index();
    // Missing decl → conservative default (no transit, no side effects).
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
        return FunctionSummary::default();
    };
    super::compute_function_summary(decl)
}
