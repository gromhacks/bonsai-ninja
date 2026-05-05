//! Abstract value lattice (spec §17.2).

use bonsai_common::TypeId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub enum AbstractValue {
    #[default]
    Unknown,
    ConstInt(i64),
    ConstBool(bool),
    ConstString(String),
    Null,
    Object(TypeId),
    Set(Vec<AbstractValue>),
    /// Any value of the given type.
    Top(TypeId),
}

impl AbstractValue {
    /// Is this value a compile-time constant.
    #[must_use]
    pub fn is_const(&self) -> bool {
        matches!(
            self,
            Self::ConstInt(_) | Self::ConstBool(_) | Self::ConstString(_) | Self::Null
        )
    }

    /// Merge two abstract values, widening as needed. Sets larger than
    /// eight elements collapse to `Unknown` to keep the lattice bounded
    /// (otherwise loops over distinct constants would inflate it
    /// without bound).
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        const SET_WIDEN_THRESHOLD: usize = 8;
        if self == other {
            return self;
        }
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Set(mut left), Self::Set(right)) => {
                for value in right {
                    if !left.contains(&value) {
                        left.push(value);
                    }
                }
                if left.len() > SET_WIDEN_THRESHOLD {
                    Self::Unknown
                } else {
                    Self::Set(left)
                }
            }
            (Self::Set(mut set), other) | (other, Self::Set(mut set)) => {
                if !set.contains(&other) {
                    set.push(other);
                }
                if set.len() > SET_WIDEN_THRESHOLD {
                    Self::Unknown
                } else {
                    Self::Set(set)
                }
            }
            (left, right) => Self::Set(vec![left, right]),
        }
    }
}
