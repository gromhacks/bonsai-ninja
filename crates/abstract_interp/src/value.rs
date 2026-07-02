//! Abstract value lattice (spec §17.2).

use bonsai_common::TypeId;
use serde::{Deserialize, Serialize};

/// Closed integer interval. `None` means unbounded on that side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntRange {
    pub min: Option<i64>,
    pub max: Option<i64>,
}

impl IntRange {
    #[must_use]
    pub const fn new(min: Option<i64>, max: Option<i64>) -> Self {
        Self { min, max }
    }

    #[must_use]
    pub const fn singleton(value: i64) -> Self {
        Self {
            min: Some(value),
            max: Some(value),
        }
    }

    #[must_use]
    pub const fn unbounded() -> Self {
        Self { min: None, max: None }
    }

    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        Self {
            min: join_lower_bound(self.min, other.min),
            max: join_upper_bound(self.max, other.max),
        }
    }

    #[must_use]
    pub fn contains(&self, value: i64) -> bool {
        self.min.is_none_or(|min| min <= value) && self.max.is_none_or(|max| value <= max)
    }

    #[must_use]
    pub fn is_singleton(&self) -> Option<i64> {
        match (self.min, self.max) {
            (Some(min), Some(max)) if min == max => Some(min),
            _ => None,
        }
    }
}

fn join_lower_bound(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        _ => None,
    }
}

fn join_upper_bound(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        _ => None,
    }
}

/// Boolean domain. `true|false` means an unknown boolean, not top for
/// arbitrary non-boolean values.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoolDomain {
    pub can_be_true: bool,
    pub can_be_false: bool,
}

impl BoolDomain {
    #[must_use]
    pub const fn singleton(value: bool) -> Self {
        Self {
            can_be_true: value,
            can_be_false: !value,
        }
    }

    #[must_use]
    pub const fn any() -> Self {
        Self {
            can_be_true: true,
            can_be_false: true,
        }
    }

    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        Self {
            can_be_true: self.can_be_true || other.can_be_true,
            can_be_false: self.can_be_false || other.can_be_false,
        }
    }

    #[must_use]
    pub const fn is_definitely_true(self) -> bool {
        self.can_be_true && !self.can_be_false
    }

    #[must_use]
    pub const fn is_definitely_false(self) -> bool {
        self.can_be_false && !self.can_be_true
    }
}

/// Nullness facet derived from an [`AbstractValue`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nullness {
    Unknown,
    Null,
    NonNull,
    MaybeNull,
}

impl Nullness {
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Null, Self::Null) => Self::Null,
            (Self::NonNull, Self::NonNull) => Self::NonNull,
            _ => Self::MaybeNull,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub enum AbstractValue {
    #[default]
    Unknown,
    ConstInt(i64),
    IntRange(IntRange),
    ConstBool(bool),
    Bool(BoolDomain),
    ConstString(String),
    /// Any string whose byte length falls in this interval.
    StringWithLength(IntRange),
    Null,
    Nullable(Box<AbstractValue>),
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

    #[must_use]
    pub fn int_range(&self) -> Option<IntRange> {
        match self {
            Self::ConstInt(value) => Some(IntRange::singleton(*value)),
            Self::IntRange(range) => Some(range.clone()),
            Self::Set(values) => {
                let mut acc: Option<IntRange> = None;
                for value in values {
                    let range = value.int_range()?;
                    acc = Some(acc.map_or_else(|| range.clone(), |existing| existing.join(&range)));
                }
                acc
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn bool_domain(&self) -> Option<BoolDomain> {
        match self {
            Self::ConstBool(value) => Some(BoolDomain::singleton(*value)),
            Self::Bool(domain) => Some(*domain),
            Self::Set(values) => {
                let mut acc: Option<BoolDomain> = None;
                for value in values {
                    let domain = value.bool_domain()?;
                    acc = Some(acc.map_or(domain, |existing| existing.join(domain)));
                }
                acc
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn nullness(&self) -> Nullness {
        match self {
            Self::Unknown => Nullness::Unknown,
            Self::Null => Nullness::Null,
            Self::Nullable(_) => Nullness::MaybeNull,
            Self::Set(values) => values
                .iter()
                .map(Self::nullness)
                .reduce(Nullness::join)
                .unwrap_or(Nullness::Unknown),
            Self::ConstInt(_)
            | Self::IntRange(_)
            | Self::ConstBool(_)
            | Self::Bool(_)
            | Self::ConstString(_)
            | Self::StringWithLength(_)
            | Self::Object(_)
            | Self::Top(_) => Nullness::NonNull,
        }
    }

    #[must_use]
    pub fn string_length_range(&self) -> Option<IntRange> {
        match self {
            Self::ConstString(value) => Some(IntRange::singleton(i64::try_from(value.len()).ok()?)),
            Self::StringWithLength(range) => Some(range.clone()),
            Self::Set(values) => {
                let mut acc: Option<IntRange> = None;
                for value in values {
                    let range = value.string_length_range()?;
                    acc = Some(acc.map_or_else(|| range.clone(), |existing| existing.join(&range)));
                }
                acc
            }
            Self::Nullable(value) => value.string_length_range(),
            _ => None,
        }
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
            (Self::ConstInt(left), Self::ConstInt(right)) => {
                Self::IntRange(IntRange::singleton(left).join(&IntRange::singleton(right)))
            }
            (Self::ConstInt(value), Self::IntRange(range))
            | (Self::IntRange(range), Self::ConstInt(value)) => {
                Self::IntRange(range.join(&IntRange::singleton(value)))
            }
            (Self::IntRange(left), Self::IntRange(right)) => Self::IntRange(left.join(&right)),
            (Self::ConstBool(left), Self::ConstBool(right)) => {
                Self::Bool(BoolDomain::singleton(left).join(BoolDomain::singleton(right)))
            }
            (Self::ConstBool(value), Self::Bool(domain)) | (Self::Bool(domain), Self::ConstBool(value)) => {
                Self::Bool(domain.join(BoolDomain::singleton(value)))
            }
            (Self::Bool(left), Self::Bool(right)) => Self::Bool(left.join(right)),
            (Self::ConstString(left), Self::StringWithLength(right))
            | (Self::StringWithLength(right), Self::ConstString(left)) => {
                let left_len = IntRange::singleton(i64::try_from(left.len()).unwrap_or(i64::MAX));
                Self::StringWithLength(left_len.join(&right))
            }
            (Self::StringWithLength(left), Self::StringWithLength(right)) => {
                Self::StringWithLength(left.join(&right))
            }
            (Self::Null, value) | (value, Self::Null) => value.with_null(),
            (Self::Nullable(left), Self::Nullable(right)) => Self::Nullable(Box::new(left.join(*right))),
            (Self::Nullable(left), value) | (value, Self::Nullable(left)) => {
                Self::Nullable(Box::new(left.join(value)))
            }
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

    fn with_null(self) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::Null | Self::Nullable(_) => self,
            value => Self::Nullable(Box::new(value)),
        }
    }
}
