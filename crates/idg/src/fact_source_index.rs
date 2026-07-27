//! Exact external reverse index for symbolic fact producers.
//!
//! Rows are keyed by `(base, field, producer node)`. Exact field and whole-base
//! target relevance therefore share one canonical relation.

use crate::external_relation::{ExternalRecord, ExternalSorter, SortedExternalRelation};

const RECORD_BYTES: usize = 12;
const RUN_ROWS: usize = 131_072;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FactSourceRecord {
    key: u64,
    node: u32,
}

impl ExternalRecord for FactSourceRecord {
    const BYTES: usize = RECORD_BYTES;

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.key.to_le_bytes());
        output.extend_from_slice(&self.node.to_le_bytes());
    }

    fn decode(record: &[u8]) -> Self {
        Self {
            key: u64::from_le_bytes(record[..8].try_into().expect("fact-source key bytes")),
            node: u32::from_le_bytes(record[8..12].try_into().expect("fact-source node bytes")),
        }
    }
}

pub(crate) struct FactSourceSpool(ExternalSorter<FactSourceRecord>);

impl FactSourceSpool {
    pub(crate) fn new() -> Self {
        Self(ExternalSorter::new(RUN_ROWS))
    }

    pub(crate) fn push(&mut self, key: u64, node: u32) {
        self.0.push(FactSourceRecord { key, node });
    }

    pub(crate) fn finish(self) -> FactSourceIndex {
        FactSourceIndex(self.0.finish())
    }
}

pub(crate) struct FactSourceIndex(SortedExternalRelation<FactSourceRecord>);

impl FactSourceIndex {
    pub(crate) fn empty() -> Self {
        Self(SortedExternalRelation::empty())
    }

    pub(crate) fn visit_key(&self, key: u64, mut visit: impl FnMut(u32)) {
        let start = self.0.lower_bound(FactSourceRecord { key, node: 0 });
        let end = if key == u64::MAX {
            self.0.len()
        } else {
            self.0.lower_bound(FactSourceRecord {
                key: key + 1,
                node: 0,
            })
        };
        self.0.visit_range(start, end, |row| visit(row.node));
    }

    pub(crate) fn visit_base(&self, base: u32, mut visit: impl FnMut(u32)) {
        let start = self.0.lower_bound(FactSourceRecord {
            key: u64::from(base) << 32,
            node: 0,
        });
        let end = if base == u32::MAX {
            self.0.len()
        } else {
            self.0.lower_bound(FactSourceRecord {
                key: u64::from(base + 1) << 32,
                node: 0,
            })
        };
        self.0.visit_range(start, end, |row| visit(row.node));
    }
}

#[cfg(test)]
mod tests {
    use super::FactSourceSpool;

    #[test]
    fn external_index_preserves_exact_and_base_ranges_across_runs() {
        let mut spool = FactSourceSpool::new();
        for index in (0..140_000_u32).rev() {
            let base = index % 3;
            let field = index % 11;
            let key = (u64::from(base) << 32) | u64::from(field);
            spool.push(key, index);
            spool.push(key, index);
        }
        let index = spool.finish();

        let key = (1_u64 << 32) | 4;
        let mut exact = Vec::new();
        index.visit_key(key, |node| exact.push(node));
        assert!(exact.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(exact.iter().all(|node| node % 3 == 1 && node % 11 == 4));

        let mut base = Vec::new();
        index.visit_base(2, |node| base.push(node));
        base.sort_unstable();
        base.dedup();
        assert_eq!(base.len(), (0..140_000_u32).filter(|node| node % 3 == 2).count());
    }
}
