//! Compact symbolic access-path transforms.
//!
//! Field flow across calls, returns, constructors, receiver mutation, and
//! aggregate copies is an algebra over `(base, suffix)` pairs. Keeping that
//! algebra symbolic avoids materialising one graph node/edge for every
//! `transform × concrete suffix` combination. All names in this table come
//! from adapter-produced AST places; hot relations use numeric ids only.

use ahash::AHashMap;
use bonsai_callgraph::EdgeKind as CallEdgeKind;
use bonsai_common::{FuncId, Precision, Span};
use serde::{Deserialize, Serialize};

use crate::workspace::SegmentId;
use crate::{place::Place, segment::IdgSegment};

/// Canonical adapter-normalized storage components for one IDG read/write.
///
/// Older transfer payloads may store a dotted compiler place in `name`, while
/// newer payloads use `Place::path`. Both forms come from adapter AST facts;
/// this is the single normalization boundary used by symbolic consumers.
pub(crate) fn structured_storage_parts(
    segment: &IdgSegment,
    place: &Place,
) -> Option<(Vec<String>, Option<Span>, bool)> {
    let (name, path, write_span, is_read) = match place {
        Place::Read { name, path } => (*name, path, None, true),
        Place::Write { name, path, span } => (*name, path, Some(*span), false),
        _ => return None,
    };
    let mut parts = Vec::with_capacity(path.len() + 1);
    parts.extend(
        segment
            .strings
            .get(name)?
            .split('.')
            .filter(|part| !part.is_empty())
            .map(ToString::to_string),
    );
    for part in path {
        parts.push(segment.strings.get(*part)?.to_string());
    }
    Some((parts, write_span, is_read))
}

/// Sentinel used when a transform has no string operand.
pub const NO_SYMBOLIC_STRING: u32 = u32::MAX;

/// One interned field-bearing storage base.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolicFieldBase {
    /// Segment holding the base.
    pub segment: SegmentId,
    /// Function holding the base.
    pub func: FuncId,
    /// Numeric id in the graph's string dictionary.
    pub storage: u32,
}

/// Algebraic field-flow operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SymbolicFieldTransformKind {
    /// Caller argument base to callee parameter base.
    Argument = 0,
    /// Callee returned base to caller assignment base.
    Return = 1,
    /// One exact callee field consumed as a scalar return.
    ScalarReturn = 2,
    /// Constructor receiver state to the constructed caller value.
    ConstructorReturn = 3,
    /// Callee receiver state written back to the caller receiver.
    ReceiverMutation = 4,
    /// Function-local aggregate/descendant copy.
    Copy = 5,
}

/// One suffix-preserving (or exact-suffix-consuming) compiler transform.
///
/// `source` and `target` index [`SymbolicFieldGraph::bases`]. For a
/// scalar-return transform, `target` names the AST-derived caller storage that
/// receives the consumed field value.
/// `exact_field` is set only for a scalar return that consumes one exact
/// suffix; all other transforms preserve any AST-proven suffix unchanged.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolicFieldTransform {
    /// Source base id.
    pub source: u32,
    /// Target base id.
    pub target: u32,
    /// Required exact suffix string id, or [`NO_SYMBOLIC_STRING`].
    pub exact_field: u32,
    /// Resolved call/copy site.
    pub call_span: Span,
    /// Target write site.
    pub write_span: Span,
    /// Resolver/evidence precision.
    pub precision: Precision,
    /// Resolved call kind.
    pub call_kind: CallEdgeKind,
    /// Transform operation.
    pub kind: SymbolicFieldTransformKind,
    /// AST argument slot for an explicit argument transform, or `u32::MAX`
    /// for receiver/synthetic/non-argument transforms.
    pub arg_idx: u32,
    /// Resolved callee formal slot for an explicit argument transform, or
    /// `u32::MAX` when the relation does not target a formal parameter.
    pub param_idx: u32,
    /// Whether structural control flow permits a lexically later source.
    pub allow_out_of_order_source: bool,
}

/// Numeric dictionaries plus the symbolic transform relation.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicFieldGraph {
    strings: Vec<String>,
    bases: Vec<SymbolicFieldBase>,
    transforms: Vec<SymbolicFieldTransform>,
    #[serde(skip)]
    string_ids: AHashMap<String, u32>,
    #[serde(skip)]
    base_ids: AHashMap<SymbolicFieldBase, u32>,
    #[serde(skip)]
    outgoing_by_source: Vec<Vec<u32>>,
}

impl SymbolicFieldGraph {
    /// Construct an empty relation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern one adapter-normalized AST place/string.
    pub fn intern_string(&mut self, value: &str) -> u32 {
        if let Some(id) = self.string_ids.get(value).copied() {
            return id;
        }
        let id = u32::try_from(self.strings.len()).expect("symbolic field string count exceeds u32");
        self.strings.push(value.to_string());
        self.string_ids.insert(value.to_string(), id);
        id
    }

    /// Intern one `(segment, function, base)` compiler place.
    pub fn intern_base(&mut self, segment: SegmentId, func: FuncId, storage: &str) -> u32 {
        let storage = self.intern_string(storage);
        let base = SymbolicFieldBase {
            segment,
            func,
            storage,
        };
        if let Some(id) = self.base_ids.get(&base).copied() {
            return id;
        }
        let id = u32::try_from(self.bases.len()).expect("symbolic field base count exceeds u32");
        self.bases.push(base);
        self.base_ids.insert(base, id);
        id
    }

    /// Add one transform.
    pub fn push_transform(&mut self, transform: SymbolicFieldTransform) {
        let source = transform.source as usize;
        if self.outgoing_by_source.len() <= source {
            self.outgoing_by_source.resize_with(source + 1, Vec::new);
        }
        self.outgoing_by_source[source]
            .push(u32::try_from(self.transforms.len()).expect("symbolic field transform count exceeds u32"));
        self.transforms.push(transform);
    }

    /// Interned strings in id order.
    #[must_use]
    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    /// Interned bases in id order.
    #[must_use]
    pub fn bases(&self) -> &[SymbolicFieldBase] {
        &self.bases
    }

    /// Symbolic transforms in stable insertion order.
    #[must_use]
    pub fn transforms(&self) -> &[SymbolicFieldTransform] {
        &self.transforms
    }

    /// Resolve one numeric string id.
    #[must_use]
    pub fn string(&self, id: u32) -> Option<&str> {
        self.strings.get(id as usize).map(String::as_str)
    }

    /// Look up an already-interned string without mutating the relation.
    #[must_use]
    pub fn string_id(&self, value: &str) -> Option<u32> {
        self.string_ids.get(value).copied()
    }

    /// Look up an already-interned base without mutating the relation.
    #[must_use]
    pub fn base_id(&self, segment: SegmentId, func: FuncId, storage: &str) -> Option<u32> {
        let storage = self.string_id(storage)?;
        self.base_ids
            .get(&SymbolicFieldBase {
                segment,
                func,
                storage,
            })
            .copied()
    }

    /// Transform indices whose source is `base`.
    #[must_use]
    pub fn outgoing_transform_indices(&self, base: u32) -> &[u32] {
        self.outgoing_by_source
            .get(base as usize)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Restore hash-consing indexes after deserialization.
    pub fn rebuild_indexes(&mut self) {
        self.string_ids.clear();
        self.base_ids.clear();
        for (index, value) in self.strings.iter().enumerate() {
            self.string_ids.insert(
                value.clone(),
                u32::try_from(index).expect("symbolic field string count exceeds u32"),
            );
        }
        for (index, base) in self.bases.iter().copied().enumerate() {
            self.base_ids.insert(
                base,
                u32::try_from(index).expect("symbolic field base count exceeds u32"),
            );
        }
        self.outgoing_by_source = vec![Vec::new(); self.bases.len()];
        for (index, transform) in self.transforms.iter().enumerate() {
            if let Some(outgoing) = self.outgoing_by_source.get_mut(transform.source as usize) {
                outgoing.push(u32::try_from(index).expect("symbolic field transform count exceeds u32"));
            }
        }
    }

    pub(crate) fn release_indexes(&mut self) {
        self.string_ids = AHashMap::new();
        self.base_ids = AHashMap::new();
        self.outgoing_by_source = Vec::new();
    }

    pub(crate) fn from_parts(
        strings: Vec<String>,
        bases: Vec<SymbolicFieldBase>,
        transforms: Vec<SymbolicFieldTransform>,
    ) -> Self {
        let mut graph = Self {
            strings,
            bases,
            transforms,
            string_ids: AHashMap::default(),
            base_ids: AHashMap::default(),
            outgoing_by_source: Vec::new(),
        };
        graph.rebuild_indexes();
        graph
    }

    pub(crate) fn extend_transforms(&mut self, transforms: impl IntoIterator<Item = SymbolicFieldTransform>) {
        for transform in transforms {
            self.push_transform(transform);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionaries_are_numeric_deduplicated_and_rebuild_after_serde() {
        let mut graph = SymbolicFieldGraph::new();
        let first = graph.intern_base(SegmentId(3), FuncId::new(9), "payload");
        let duplicate = graph.intern_base(SegmentId(3), FuncId::new(9), "payload");
        let other = graph.intern_base(SegmentId(3), FuncId::new(9), "result");
        assert_eq!(first, duplicate);
        assert_ne!(first, other);
        assert_eq!(
            graph.string(graph.bases()[first as usize].storage),
            Some("payload")
        );

        let bytes = bonsai_common::wire::encode(&graph).expect("serialize symbolic graph");
        let mut restored: SymbolicFieldGraph =
            bonsai_common::wire::decode(&bytes).expect("deserialize symbolic graph");
        restored.rebuild_indexes();
        assert_eq!(
            restored.intern_base(SegmentId(3), FuncId::new(9), "payload"),
            first
        );
    }
}
