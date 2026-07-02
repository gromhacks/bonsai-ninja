//! Precision lattice used throughout the analyzer.
//!
//! The spec forbids silently inventing precision, so every fact that crosses
//! a layer boundary carries one of these values. `meet` computes the
//! conservative join of two precisions (the worse of the two wins).

use serde::{Deserialize, Serialize};

/// Internal precision lattice for analyzer facts.
///
/// Public security findings have a single accuracy contract: proven
/// static evidence only. `Exact` and `Narrowed` satisfy that contract;
/// `OverApproximate` and `Unknown` are diagnostic-only states that
/// explain why evidence was not emitted. Every cross-layer fact still
/// carries this enum so the engine can conservatively `meet` precision
/// while keeping imprecise facts out of user-facing findings.
///
/// The lattice ordering is `Exact < Narrowed < OverApproximate <
/// Unknown` — `meet` returns the worse (greater) of two precisions.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Precision {
    /// The analyzer has a proof that the fact is exact.
    Exact,
    /// The fact is precise modulo a set of named caveats (e.g. reflection
    /// narrowed by a known helper).
    Narrowed,
    /// The fact is an over-approximation and may include spurious elements.
    OverApproximate,
    /// The analyzer gave up; callers must treat the fact as opaque.
    #[default]
    Unknown,
}

impl Precision {
    /// Combine two precisions; the less precise wins. Ordering:
    /// `Exact < Narrowed < OverApproximate < Unknown`.
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        self.max(other)
    }

    /// Numeric rank in the lattice. Lower ranks are more precise.
    /// Used to derive `Ord` deterministically.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::Narrowed => 1,
            Self::OverApproximate => 2,
            Self::Unknown => 3,
        }
    }

    /// True iff this precision is `Exact`.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Exact)
    }

    /// True iff this fact is semantic enough to expose by default.
    ///
    /// `Exact` facts are proven. `Narrowed` facts are still tied to a
    /// concrete semantic constraint, such as a resolved receiver type or
    /// build target. `OverApproximate` and `Unknown` facts may contain
    /// invented alternatives and are only suitable for explicit
    /// diagnostics.
    #[must_use]
    pub const fn is_semantic(self) -> bool {
        matches!(self, Self::Exact | Self::Narrowed)
    }

    /// True iff this fact can be used as public static evidence.
    ///
    /// This intentionally aliases [`Self::is_semantic`]. The separate
    /// name makes the product contract explicit at call sites that
    /// decide whether a fact is allowed to become a finding.
    #[must_use]
    pub const fn is_proven_static_evidence(self) -> bool {
        self.is_semantic()
    }

    /// True iff this precision is only suitable for diagnostics.
    #[must_use]
    pub const fn is_diagnostic_only(self) -> bool {
        matches!(self, Self::OverApproximate | Self::Unknown)
    }
}

impl PartialOrd for Precision {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Precision {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

#[cfg(test)]
#[path = "precision_tests.rs"]
mod tests;
