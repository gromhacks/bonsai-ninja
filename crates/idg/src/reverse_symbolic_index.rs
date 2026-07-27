//! Exact paged reverse index for non-scalar symbolic transforms.

use crate::external_relation::{ExternalRecord, ExternalSorter, SortedExternalRelation};
use ahash::AHashMap;
use bonsai_common::Precision;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

const RECORD_BYTES: usize = 9;
const RUN_ROWS: usize = 131_072;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReverseSymbolicRecord {
    target: u32,
    source: u32,
    precision: u8,
}

impl ExternalRecord for ReverseSymbolicRecord {
    const BYTES: usize = RECORD_BYTES;

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.target.to_le_bytes());
        output.extend_from_slice(&self.source.to_le_bytes());
        output.push(self.precision);
    }

    fn decode(record: &[u8]) -> Self {
        Self {
            target: u32::from_le_bytes(record[..4].try_into().expect("reverse target bytes")),
            source: u32::from_le_bytes(record[4..8].try_into().expect("reverse source bytes")),
            precision: record[8],
        }
    }
}

/// One inverse access-path transform consumed by target relevance.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReverseSymbolicTransform {
    pub(crate) source: u32,
    pub(crate) precision: Precision,
}

pub(crate) struct ReverseSymbolicTransformSpool(ExternalSorter<ReverseSymbolicRecord>);

impl ReverseSymbolicTransformSpool {
    pub(crate) fn new() -> Self {
        Self(ExternalSorter::new(RUN_ROWS))
    }

    pub(crate) fn push(&mut self, target: u32, source: u32, precision: Precision) {
        self.0.push(ReverseSymbolicRecord {
            target,
            source,
            precision: precision.rank(),
        });
    }

    pub(crate) fn finish(self) -> ReverseSymbolicTransformIndex {
        let workers = bonsai_common::compiler_worker_count(rayon::current_num_threads());
        let capacity = workers.saturating_mul(2).max(2);
        let cache_bytes = bonsai_common::effective_memory_limit_bytes().map_or(2 * 1024 * 1024, |limit| {
            (limit / 1_024).clamp(64 * 1024, 8 * 1024 * 1024)
        });
        ReverseSymbolicTransformIndex {
            relation: self.0.finish(),
            cache: Mutex::new(ReversePageCache::new(
                capacity,
                usize::try_from(cache_bytes).unwrap_or(usize::MAX),
            )),
        }
    }
}

pub(crate) struct ReverseSymbolicTransformIndex {
    relation: SortedExternalRelation<ReverseSymbolicRecord>,
    cache: Mutex<ReversePageCache>,
}

impl ReverseSymbolicTransformIndex {
    pub(crate) fn empty() -> Self {
        Self {
            relation: SortedExternalRelation::empty(),
            cache: Mutex::new(ReversePageCache::new(2, 64 * 1024)),
        }
    }

    pub(crate) fn visit_incoming(&self, target: u32, mut visit: impl FnMut(ReverseSymbolicTransform)) {
        if let Some(rows) = self.cache.lock().pages.get(&target).cloned() {
            for &row in rows.iter() {
                visit(row);
            }
            return;
        }
        let start = self.relation.lower_bound(ReverseSymbolicRecord {
            target,
            source: 0,
            precision: 0,
        });
        let max_entry_rows = self.cache.lock().max_entry_rows;
        let mut cache_candidate = Some(Vec::with_capacity(max_entry_rows.min(1_024)));
        self.relation.visit_while(start, |row| {
            if row.target != target {
                return false;
            }
            let row = ReverseSymbolicTransform {
                source: row.source,
                precision: decode_precision(row.precision),
            };
            visit(row);
            if let Some(candidate) = &mut cache_candidate {
                if candidate.len() < max_entry_rows {
                    candidate.push(row);
                } else {
                    cache_candidate = None;
                }
            }
            true
        });
        if let Some(mut rows) = cache_candidate {
            rows.shrink_to_fit();
            self.cache.lock().insert(target, Arc::new(rows));
        }
    }
}

struct ReversePageCache {
    pages: AHashMap<u32, Arc<Vec<ReverseSymbolicTransform>>>,
    order: VecDeque<u32>,
    capacity: usize,
    max_entry_rows: usize,
}

impl ReversePageCache {
    fn new(capacity: usize, byte_budget: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            pages: AHashMap::default(),
            order: VecDeque::new(),
            capacity,
            max_entry_rows: byte_budget
                .checked_div(capacity)
                .unwrap_or(0)
                .checked_div(std::mem::size_of::<ReverseSymbolicTransform>())
                .unwrap_or(0)
                .max(1),
        }
    }

    fn insert(&mut self, target: u32, rows: Arc<Vec<ReverseSymbolicTransform>>) {
        if self.pages.insert(target, rows).is_some() {
            return;
        }
        self.order.push_back(target);
        while self.pages.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.pages.remove(&evicted);
            }
        }
    }
}

fn decode_precision(value: u8) -> Precision {
    match value {
        0 => Precision::Exact,
        1 => Precision::Narrowed,
        2 => Precision::OverApproximate,
        3 => Precision::Unknown,
        _ => panic!("invalid compact reverse symbolic precision"),
    }
}

#[cfg(test)]
mod tests {
    use super::{ReverseSymbolicTransformSpool, RUN_ROWS};
    use bonsai_common::Precision;

    #[test]
    fn external_reverse_index_preserves_target_bucket_across_runs() {
        let mut spool = ReverseSymbolicTransformSpool::new();
        for source in (0..u32::try_from(RUN_ROWS + 10).expect("test row count")).rev() {
            spool.push(4, source, Precision::Exact);
            spool.push(4, source, Precision::Exact);
            spool.push(5, source, Precision::Narrowed);
        }
        let index = spool.finish();
        let mut rows = Vec::new();
        index.visit_incoming(4, |row| rows.push(row));
        assert_eq!(rows.len(), RUN_ROWS + 10);
        assert!(rows.windows(2).all(|pair| pair[0].source < pair[1].source));
        assert!(rows.iter().all(|row| row.precision == Precision::Exact));
        let mut replay = Vec::new();
        index.visit_incoming(4, |row| replay.push(row));
        assert_eq!(rows, replay);
    }
}
