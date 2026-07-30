//! IDG-derived per-function return-taint summary types and the public
//! [`function_summary`] accessor.
//!
//! Summaries are derived from the same IDG used by every taint query. The
//! compiler composes function-local CSRs over exact call-site boundaries to a
//! recursive least fixed point, then evaluates symbolic access paths through
//! the same context-matched closure as public taint queries.

use bonsai_common::{FuncId, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_idg::IdgQueryService;
use bonsai_index::GlobalIndex;

/// Per-function return-taint summary.
///
/// `returns_taint_of` is derived from the canonical IDG. The remaining fields
/// are retained for source compatibility with callers that deserialize or
/// inspect the former worklist summary; the IDG represents those field,
/// tuple, yield, side-effect, exception, and capture relationships directly
/// as graph edges, so public taint queries do not consume parallel summary
/// state.
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
    /// Parameter indices that transit to a `yield` value. This is
    /// narrower than `returns_taint_of`: call-site block parameters
    /// should only receive taint when the callee actually yielded
    /// that parameter, not merely because the callee returned it.
    pub yields_taint_of: Vec<usize>,
    /// Parameter indices whose tainted descendants transit to a
    /// `yield` value.
    pub yields_descendant_taint_of: Vec<usize>,
    /// Parameter indices whose direct value is embedded into a newly
    /// returned container. `return {"value": param0}` should make the
    /// caller's LHS carry descendant taint (`lhs.*`) without making every
    /// ordinary `param0.field` read tainted.
    pub returns_container_taint_of: Vec<usize>,
    /// Exact fields on a newly returned container whose value comes
    /// from a parameter. `(0, "user", None)` means
    /// `return {"user": param0}` taints `lhs.user`, not `lhs.*`;
    /// `(0, "cmd", Some("value"))` means
    /// `return {"cmd": param0.value}` taints `lhs.cmd` only when
    /// the caller has proven `arg.value` tainted.
    pub returns_field_taint_of: Vec<ReturnFieldTaint>,
    /// Exact positional elements on a newly returned tuple/list whose
    /// value comes from a parameter. `(0, 1)` means
    /// `return (clean, param0)` taints only the second binding in
    /// `(first, second) = callee(arg0)`.
    pub returns_element_taint_of: Vec<ReturnElementTaint>,
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
    /// Parameter indices whose taint reaches a `throw` / `raise` on some
    /// path through the function body. `throws_taint_of = {0}` means
    /// tainting param 0 produces a tainted exception, so a caller doing
    /// `try { callee(tainted) } catch (e) { sink(e) }` must seed its
    /// catch binding `e` even though the caller's own try body contains
    /// no literal `Throw` event (audit R1 -- interprocedural exception
    /// flow). Empty when no parameter transits to a thrown value.
    pub throws_taint_of: Vec<usize>,
    /// Names of module-level / global variables (or captured outer
    /// locals) that a parameter-less function reads and forwards to its
    /// return value. `reads_global_taint_of = {"g"}` means
    /// `def reader(): return g` transits `g`'s taint to its result, so the
    /// inter pass can seed a tainted module-global channel through an
    /// otherwise empty summary. Empty for functions with parameters --
    /// their transit is captured by `returns_taint_of` (audit R6 -- the
    /// module/global taint channel).
    pub reads_global_taint_of: Vec<String>,
}

/// One field-of-parameter access path that the function returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnAccessPath {
    pub param: usize,
    pub path: String,
}

/// One returned-container field whose value is parameter-tainted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnFieldTaint {
    pub param: usize,
    pub field: String,
    pub source_path: Option<String>,
}

/// One returned tuple/list element whose value is parameter-tainted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnElementTaint {
    pub param: usize,
    pub index: usize,
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
    let idg = crate::idg_build::ensure_idg_service(db);
    let global = idg.global_linkage_index();
    function_summary_from_idg(global.as_ref(), idg.as_ref(), func)
}

pub(crate) fn function_summary_from_idg(
    global: &GlobalIndex,
    idg: &IdgQueryService,
    func: FuncId,
) -> FunctionSummary {
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
        return FunctionSummary::default();
    };
    let returns_taint_of = idg
        .return_taint_param_indices_for_funcs_with_max_precision(
            &[func],
            Some(bonsai_common::Precision::Narrowed),
        )
        .remove(&func)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|index| usize::try_from(index).ok())
        .filter(|index| *index < decl.params.len())
        .collect();
    FunctionSummary {
        returns_taint_of,
        ..FunctionSummary::default()
    }
}
