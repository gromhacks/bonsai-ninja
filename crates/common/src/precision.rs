//! Precision lattice used throughout the analyzer.
//!
//! The spec forbids silently inventing precision, so every fact that crosses
//! a layer boundary carries one of these values. `meet` computes the
//! conservative join of two precisions (the worse of the two wins).

use serde::{Deserialize, Serialize};

/// How confident the analyzer is in a given fact. Every cross-layer
/// fact carries a `Precision` and gets `meet`-folded as it flows
/// through analyses. The lattice ordering is `Exact < Narrowed <
/// OverApproximate < Unknown` — `meet` returns the worse (greater)
/// of two precisions.
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
mod tests {
    use super::*;

    #[test]
    fn meet_picks_worse() {
        assert_eq!(Precision::Exact.meet(Precision::Narrowed), Precision::Narrowed);
        assert_eq!(
            Precision::Narrowed.meet(Precision::OverApproximate),
            Precision::OverApproximate
        );
        assert_eq!(Precision::Unknown.meet(Precision::Exact), Precision::Unknown);
    }
}
