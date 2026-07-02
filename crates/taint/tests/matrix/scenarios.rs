//! Stable scenario catalog for the taint test matrix.
//!
//! Each scenario has an ID, a category, a one-line description, and a
//! polarity. The set is closed: adding a scenario requires extending
//! this list AND populating applicability for every language.

#![allow(dead_code, unreachable_pub)]

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Intra,
    Inter,
    CrossFile,
    OverTaint,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Intra => "intra",
            Category::Inter => "inter",
            Category::CrossFile => "cross_file",
            Category::OverTaint => "over_taint",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Polarity {
    /// Taint MUST reach the sink (positive flow assertion).
    Positive,
    /// Taint MUST NOT reach the sink (negative / over-taint guard).
    Negative,
}

#[derive(Copy, Clone, Debug)]
pub struct Scenario {
    pub id: &'static str,
    pub category: Category,
    pub polarity: Polarity,
    pub description: &'static str,
}

pub const SCENARIOS: &[Scenario] = &[
    // --- Intra-procedural (I_01..I_20) ---
    Scenario {
        id: "I_01",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Single assignment propagates",
    },
    Scenario {
        id: "I_02",
        category: Category::Intra,
        polarity: Polarity::Negative,
        description: "Clean reassignment overwrites taint",
    },
    Scenario {
        id: "I_03",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Augmented assignment propagates",
    },
    Scenario {
        id: "I_04",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Tuple/multiple assignment splits taint",
    },
    Scenario {
        id: "I_05",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Destructure from tainted RHS",
    },
    Scenario {
        id: "I_06",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Ternary / conditional expression",
    },
    Scenario {
        id: "I_07",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "If-branch merge propagates",
    },
    Scenario {
        id: "I_08",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Else-branch merge propagates",
    },
    Scenario {
        id: "I_09",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Loop body propagation",
    },
    Scenario {
        id: "I_10",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Loop carry across iterations",
    },
    Scenario {
        id: "I_11",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "For-each over tainted iterable",
    },
    Scenario {
        id: "I_12",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "While with tainted condition",
    },
    Scenario {
        id: "I_13",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Try -> throw -> catch propagates",
    },
    Scenario {
        id: "I_14",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Catch param propagates further",
    },
    Scenario {
        id: "I_15",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Finally after taint",
    },
    Scenario {
        id: "I_16",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Pattern match arm body",
    },
    Scenario {
        id: "I_17",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Switch/case fall-through",
    },
    Scenario {
        id: "I_18",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Closure captures tainted local",
    },
    Scenario {
        id: "I_19",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Lambda body taint",
    },
    Scenario {
        id: "I_20",
        category: Category::Intra,
        polarity: Polarity::Positive,
        description: "Lazy init via if-not assignment",
    },
    // --- Inter-procedural (R_01..R_20) ---
    Scenario {
        id: "R_01",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Direct call with tainted arg",
    },
    Scenario {
        id: "R_02",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Tainted return value to caller LHS",
    },
    Scenario {
        id: "R_03",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Method receiver taint propagates",
    },
    Scenario {
        id: "R_04",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Method tainted arg propagates",
    },
    Scenario {
        id: "R_05",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Constructor / new with taint",
    },
    Scenario {
        id: "R_06",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Static / class method propagates",
    },
    Scenario {
        id: "R_07",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Dotted module call propagates",
    },
    Scenario {
        id: "R_08",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Out-param / mutable reference convention",
    },
    Scenario {
        id: "R_09",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Higher-order: pass tainted to callback",
    },
    Scenario {
        id: "R_10",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Higher-order: callback returns tainted",
    },
    Scenario {
        id: "R_11",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Async / await propagates",
    },
    Scenario {
        id: "R_12",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Generator yield reaches consumer",
    },
    Scenario {
        id: "R_13",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Multi-return splat to LHS variables",
    },
    Scenario {
        id: "R_14",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Overload dispatch considers all candidates",
    },
    Scenario {
        id: "R_15",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Recursive function terminates with taint",
    },
    Scenario {
        id: "R_16",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Mutual recursion converges",
    },
    Scenario {
        id: "R_17",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Callable variable / function pointer",
    },
    Scenario {
        id: "R_18",
        category: Category::Inter,
        polarity: Polarity::Negative,
        description: "Default argument value stays clean",
    },
    Scenario {
        id: "R_19",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Variadic args carry taint",
    },
    Scenario {
        id: "R_20",
        category: Category::Inter,
        polarity: Polarity::Positive,
        description: "Keyword args land on named param",
    },
    // --- Cross-file (X_01..X_16) ---
    Scenario {
        id: "X_01",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Direct import + call",
    },
    Scenario {
        id: "X_02",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Aliased import",
    },
    Scenario {
        id: "X_03",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "From-import",
    },
    Scenario {
        id: "X_04",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Re-export chain A->B->C",
    },
    Scenario {
        id: "X_05",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Default export (JS/TS)",
    },
    Scenario {
        id: "X_06",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Namespace import (import * as X)",
    },
    Scenario {
        id: "X_07",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Wildcard import/load exposes bare symbol",
    },
    Scenario {
        id: "X_08",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Dynamic import (string-driven)",
    },
    Scenario {
        id: "X_09",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "CommonJS require + assign",
    },
    Scenario {
        id: "X_10",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "ES module <-> CommonJS interop",
    },
    Scenario {
        id: "X_11",
        category: Category::CrossFile,
        polarity: Polarity::Negative,
        description: "Visibility crossing - private blocks",
    },
    Scenario {
        id: "X_12",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Inheritance across files",
    },
    Scenario {
        id: "X_13",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Instance method on imported class",
    },
    Scenario {
        id: "X_14",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Static method on imported class",
    },
    Scenario {
        id: "X_15",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Module-level shadow - local wins",
    },
    Scenario {
        id: "X_16",
        category: Category::CrossFile,
        polarity: Polarity::Positive,
        description: "Multi-file fan-in to same callee",
    },
    // --- Over-taint (OT_01..OT_20) - ALL Negative ---
    Scenario {
        id: "OT_01",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Sibling field read stays clean",
    },
    Scenario {
        id: "OT_02",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Literal containing seed name stays clean",
    },
    Scenario {
        id: "OT_03",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Second-arg taint doesn't backflow to first-arg",
    },
    Scenario {
        id: "OT_04",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Tainted helper param doesn't taint sibling sink arg",
    },
    Scenario {
        id: "OT_05",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "sizeof operand isn't allocator size",
    },
    Scenario {
        id: "OT_06",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Fixed-size pointer copy length stays clean",
    },
    Scenario {
        id: "OT_07",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Clean overwrite before sink clears taint",
    },
    Scenario {
        id: "OT_08",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Lifecycle / guard path stays clean",
    },
    Scenario {
        id: "OT_09",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Field carrier stays field-scoped",
    },
    Scenario {
        id: "OT_10",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Field-derived local stays clean",
    },
    Scenario {
        id: "OT_11",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Clean return after consume stays clean",
    },
    Scenario {
        id: "OT_12",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Unknown call doesn't taint independent later sink",
    },
    Scenario {
        id: "OT_13",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Sibling key/index reads stay clean",
    },
    Scenario {
        id: "OT_14",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Argparse -> eval through hardcoded filter",
    },
    Scenario {
        id: "OT_15",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Constant int/bool args don't promote",
    },
    Scenario {
        id: "OT_16",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Receiver-only taint doesn't promote to scalar arg",
    },
    Scenario {
        id: "OT_17",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Variable named like seed but unrelated",
    },
    Scenario {
        id: "OT_18",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Type annotation containing seed name",
    },
    Scenario {
        id: "OT_19",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Function name with seed substring",
    },
    Scenario {
        id: "OT_20",
        category: Category::OverTaint,
        polarity: Polarity::Negative,
        description: "Module qualifier (Task #279) - os.getenv doesn't taint os",
    },
];

pub fn scenario(id: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|s| s.id == id)
}
