//! Abstract execution state (spec §17.3).

use crate::value::AbstractValue;
use ahash::AHashMap;
use bonsai_common::{BasicBlockId, FuncId, SymbolId};
use serde::{Deserialize, Serialize};

/// Per-path interpreter state carried alongside the trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecState {
    pub locals: AHashMap<SymbolId, AbstractValue>,
    pub path_constraints: Vec<Constraint>,
    pub call_stack: Vec<Frame>,
    pub current_func: FuncId,
    pub current_bb: BasicBlockId,
}

impl ExecState {
    /// Initialise a fresh state at `func`'s `entry` block.
    #[must_use]
    pub fn new(func: FuncId, entry: BasicBlockId) -> Self {
        Self {
            locals: AHashMap::new(),
            path_constraints: Vec::new(),
            call_stack: Vec::new(),
            current_func: func,
            current_bb: entry,
        }
    }
}

/// One constraint accumulated along the current path. Opaque to the engine
/// core; renderers decide how to display them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    pub text: String,
}

/// One activation record on the symbolic call stack.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    pub caller: FuncId,
    pub return_bb: BasicBlockId,
}
