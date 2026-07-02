//! Abstract execution state (spec §17.3).

use crate::value::AbstractValue;
use ahash::AHashMap;
use bonsai_common::{BasicBlockId, FuncId};
use serde::{Deserialize, Serialize};

/// Per-path interpreter state carried alongside the trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecState {
    /// Abstract values for source-level local names visible on this
    /// path. Flow events carry adapter-normalized expression text, not
    /// stable symbol ids, so the interpreter stores the same normalized
    /// names the taint engine consumes.
    pub locals: AHashMap<String, AbstractValue>,
    pub path_constraints: Vec<Constraint>,
    pub relations: Vec<ValueRelation>,
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
            relations: Vec::new(),
            call_stack: Vec::new(),
            current_func: func,
            current_bb: entry,
        }
    }

    /// Join another incoming state into this one. Returns `true` when
    /// the abstract state widened.
    pub fn merge_from(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (name, value) in &other.locals {
            match self.locals.get_mut(name) {
                Some(existing) => {
                    let joined = existing.clone().join(value.clone());
                    if *existing != joined {
                        *existing = joined;
                        changed = true;
                    }
                }
                None => {
                    self.locals.insert(name.clone(), value.clone());
                    changed = true;
                }
            }
        }
        let before_constraints = self.path_constraints.len();
        self.path_constraints
            .retain(|constraint| other.path_constraints.contains(constraint));
        changed |= self.path_constraints.len() != before_constraints;

        let before_relations = self.relations.len();
        self.relations
            .retain(|relation| other.relations.contains(relation));
        changed |= self.relations.len() != before_relations;
        changed
    }

    pub fn assume_relation(&mut self, relation: ValueRelation) {
        if !self.relations.contains(&relation) {
            self.relations.push(relation);
        }
    }
}

/// One constraint accumulated along the current path. Opaque to the engine
/// core; renderers decide how to display them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    pub text: String,
}

/// A simple value relationship accumulated along a path. The core
/// interpreter treats these as language-neutral facts; higher-level
/// analyses decide whether a relationship discharges a bounds,
/// nullness, sanitizer, or reachability question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueRelation {
    pub left: String,
    pub op: RelationOp,
    pub right: RelationTerm,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationOp {
    Eq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationTerm {
    Var(String),
    Int(i64),
    Bool(bool),
    Null,
}

/// One activation record on the symbolic call stack.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    pub caller: FuncId,
    pub return_bb: BasicBlockId,
}
