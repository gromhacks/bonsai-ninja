//! Exact external reverse index for scalar-return access-path transforms.

use crate::external_relation::{
    ExternalRecord, ExternalSorter, PersistedExternalRelation, SortedExternalRelation,
};
use crate::workspace::QueryAcceleratorBlobReader;
use bonsai_common::{FileId, Precision, Span};
use std::fs::File;
use std::sync::Arc;

const RECORD_BYTES: usize = 33;
const RUN_ROWS: usize = 100_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReverseScalarRecord {
    target: u32,
    write_span: Span,
    source: u32,
    exact_field: u32,
    precision: u8,
}

impl ExternalRecord for ReverseScalarRecord {
    const BYTES: usize = RECORD_BYTES;

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.target.to_le_bytes());
        output.extend_from_slice(&self.write_span.file.raw().to_le_bytes());
        output.extend_from_slice(&self.write_span.start.to_le_bytes());
        output.extend_from_slice(&self.write_span.end.to_le_bytes());
        output.extend_from_slice(&self.source.to_le_bytes());
        output.extend_from_slice(&self.exact_field.to_le_bytes());
        output.push(self.precision);
    }

    fn decode(record: &[u8]) -> Self {
        let word = |start| u32::from_le_bytes(record[start..start + 4].try_into().expect("word bytes"));
        let wide = |start| u64::from_le_bytes(record[start..start + 8].try_into().expect("wide bytes"));
        Self {
            target: word(0),
            write_span: Span::new(FileId::new(word(4)), wide(8), wide(16)),
            source: word(24),
            exact_field: word(28),
            precision: record[32],
        }
    }
}

/// One inverse scalar-return row consumed by target relevance.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReverseScalarTransform {
    pub(crate) source: u32,
    pub(crate) exact_field: u32,
    pub(crate) precision: Precision,
}

pub(crate) struct ReverseScalarTransformSpool(ExternalSorter<ReverseScalarRecord>);

impl ReverseScalarTransformSpool {
    pub(crate) fn new() -> Self {
        Self(ExternalSorter::new(RUN_ROWS))
    }

    pub(crate) fn push(
        &mut self,
        target: u32,
        write_span: Span,
        source: u32,
        exact_field: u32,
        precision: Precision,
    ) {
        self.0.push(ReverseScalarRecord {
            target,
            write_span,
            source,
            exact_field,
            precision: precision.rank(),
        });
    }

    pub(crate) fn finish(self) -> ReverseScalarTransformIndex {
        ReverseScalarTransformIndex(self.0.finish())
    }
}

pub(crate) struct ReverseScalarTransformIndex(SortedExternalRelation<ReverseScalarRecord>);

impl ReverseScalarTransformIndex {
    pub(crate) fn empty() -> Self {
        Self(SortedExternalRelation::empty())
    }

    pub(crate) fn persisted_metadata(&self) -> PersistedExternalRelation {
        self.0.persisted_metadata()
    }

    pub(crate) fn snapshot_file(&self) -> std::io::Result<Arc<File>> {
        self.0.snapshot_file()
    }

    pub(crate) fn from_persisted(
        metadata: PersistedExternalRelation,
        storage: QueryAcceleratorBlobReader,
    ) -> Result<Self, &'static str> {
        SortedExternalRelation::from_persisted(metadata, storage).map(Self)
    }

    pub(crate) fn visit_incoming(
        &self,
        target: u32,
        write_span: Span,
        mut visit: impl FnMut(ReverseScalarTransform),
    ) {
        let start = self.0.lower_bound(ReverseScalarRecord {
            target,
            write_span,
            source: 0,
            exact_field: 0,
            precision: 0,
        });
        self.0.visit_while(start, |row| {
            if row.target != target || row.write_span != write_span {
                return false;
            }
            visit(ReverseScalarTransform {
                source: row.source,
                exact_field: row.exact_field,
                precision: decode_precision(row.precision),
            });
            true
        });
    }
}

fn decode_precision(value: u8) -> Precision {
    match value {
        0 => Precision::Exact,
        1 => Precision::Narrowed,
        2 => Precision::OverApproximate,
        3 => Precision::Unknown,
        _ => panic!("invalid compact reverse scalar precision"),
    }
}

#[cfg(test)]
mod tests {
    use super::{ReverseScalarTransformSpool, RUN_ROWS};
    use bonsai_common::{FileId, Precision, Span};

    #[test]
    fn external_scalar_index_preserves_one_key_across_runs() {
        let target_span = Span::new(FileId::new(7), 10, 20);
        let other_span = Span::new(FileId::new(7), 30, 40);
        let mut spool = ReverseScalarTransformSpool::new();
        for source in (0..u32::try_from(RUN_ROWS + 10).expect("test row count")).rev() {
            spool.push(3, target_span, source, source % 5, Precision::Exact);
            spool.push(3, target_span, source, source % 5, Precision::Exact);
            spool.push(3, other_span, source, 0, Precision::Narrowed);
        }
        let index = spool.finish();
        let mut rows = Vec::new();
        index.visit_incoming(3, target_span, |row| rows.push(row));
        assert_eq!(rows.len(), RUN_ROWS + 10);
        assert!(rows.windows(2).all(|pair| pair[0].source < pair[1].source));
        assert!(rows.iter().all(|row| row.precision == Precision::Exact));
    }
}
