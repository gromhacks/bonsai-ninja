//! Reusable exact external sort for fixed-width compiler relations.
//!
//! Relation rows are sorted and deduplicated in bounded runs, merged into one
//! immutable temporary file, and queried through sparse checkpoints plus
//! positioned reads. Memory budgets change run/page locality only; every row
//! remains part of the relation.

use crate::positioned_io::read_exact_at;
use crate::workspace::QueryAcceleratorBlobReader;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::sync::Arc;

const READ_ROWS: usize = 2_048;
const INDEX_STRIDE: u64 = 256;
const MIB: u64 = 1024 * 1024;
const DEFAULT_MERGE_BUFFER_BYTES: u64 = 4 * MIB;
const MINIMUM_MERGE_BUFFER_BYTES: u64 = MIB;
const MAXIMUM_MERGE_BUFFER_BYTES: u64 = 16 * MIB;

/// Divide one detected-memory merge buffer across every sorted run.
///
/// A k-way merge must retain one head row per run, but it must not retain one
/// maximum-sized read page per run. The returned page size keeps ordinary
/// merge payloads within one acceleration budget regardless of run count.
pub(crate) fn merge_page_rows(run_count: usize, record_bytes: usize, maximum_rows: usize) -> usize {
    let buffer_bytes = bonsai_common::effective_memory_limit_bytes()
        .map_or(DEFAULT_MERGE_BUFFER_BYTES, |limit| {
            (limit / 512).clamp(MINIMUM_MERGE_BUFFER_BYTES, MAXIMUM_MERGE_BUFFER_BYTES)
        });
    let per_run_bytes = usize::try_from(buffer_bytes).unwrap_or(usize::MAX) / run_count.max(1);
    (per_run_bytes / record_bytes.max(1)).clamp(1, maximum_rows.max(1))
}

pub(crate) trait ExternalRecord: Copy + Ord {
    const BYTES: usize;

    fn encode(self, output: &mut Vec<u8>);

    fn decode(record: &[u8]) -> Self;
}

#[derive(Copy, Clone)]
struct RunEntry {
    offset: u64,
    count: u32,
}

pub(crate) struct ExternalSorter<R> {
    file: File,
    write_offset: u64,
    runs: Vec<RunEntry>,
    rows: Vec<R>,
    max_rows: usize,
}

impl<R: ExternalRecord> ExternalSorter<R> {
    pub(crate) fn new(max_rows: usize) -> Self {
        let max_rows = max_rows.max(1);
        Self {
            file: tempfile::tempfile().expect("create exact compiler relation run spool"),
            write_offset: 0,
            runs: Vec::new(),
            rows: Vec::with_capacity(max_rows),
            max_rows,
        }
    }

    pub(crate) fn push(&mut self, row: R) {
        self.rows.push(row);
        if self.rows.len() == self.max_rows {
            self.flush();
        }
    }

    pub(crate) fn finish(mut self) -> SortedExternalRelation<R> {
        self.flush();
        let mut output = BufWriter::new(tempfile::tempfile().expect("create sorted exact compiler relation"));
        let mut checkpoints = Vec::new();
        let mut count = 0_u64;
        let mut previous = None;
        let mut payload = Vec::with_capacity(R::BYTES);
        for row in RunMerger::<R>::new(&self.file, &self.runs) {
            if previous == Some(row) {
                continue;
            }
            if count.is_multiple_of(INDEX_STRIDE) {
                checkpoints.push(row);
            }
            payload.clear();
            row.encode(&mut payload);
            debug_assert_eq!(payload.len(), R::BYTES);
            output
                .write_all(&payload)
                .expect("write sorted exact compiler relation");
            previous = Some(row);
            count = count
                .checked_add(1)
                .expect("exact compiler relation count exceeds u64");
        }
        output.flush().expect("flush sorted exact compiler relation");
        let mut file = output
            .into_inner()
            .expect("finish sorted exact compiler relation");
        file.seek(SeekFrom::Start(0))
            .expect("rewind sorted exact compiler relation");
        SortedExternalRelation {
            storage: ExternalRelationStorage::File(file),
            len: count,
            checkpoints: checkpoints.into_boxed_slice(),
        }
    }

    fn flush(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        self.rows.sort_unstable();
        self.rows.dedup();
        let mut payload = Vec::with_capacity(self.rows.len().saturating_mul(R::BYTES));
        for &row in &self.rows {
            row.encode(&mut payload);
        }
        debug_assert_eq!(payload.len(), self.rows.len() * R::BYTES);
        self.file
            .seek(SeekFrom::Start(self.write_offset))
            .expect("seek exact compiler relation run spool");
        self.file
            .write_all(&payload)
            .expect("write exact compiler relation run spool");
        self.runs.push(RunEntry {
            offset: self.write_offset,
            count: u32::try_from(self.rows.len()).expect("exact compiler relation run exceeds u32"),
        });
        self.write_offset = self
            .write_offset
            .checked_add(u64::try_from(payload.len()).expect("exact compiler relation payload exceeds u64"))
            .expect("exact compiler relation spool exceeds u64");
        self.rows.clear();
    }
}

pub(crate) struct SortedExternalRelation<R> {
    storage: ExternalRelationStorage,
    len: u64,
    checkpoints: Box<[R]>,
}

enum ExternalRelationStorage {
    File(File),
    Persisted(QueryAcceleratorBlobReader),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedExternalRelation {
    len: u64,
    checkpoints: Box<[u8]>,
}

impl<R: ExternalRecord> SortedExternalRelation<R> {
    pub(crate) fn empty() -> Self {
        ExternalSorter::new(1).finish()
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn persisted_metadata(&self) -> PersistedExternalRelation {
        let mut checkpoints = Vec::with_capacity(self.checkpoints.len().saturating_mul(R::BYTES));
        for checkpoint in self.checkpoints.iter().copied() {
            checkpoint.encode(&mut checkpoints);
        }
        PersistedExternalRelation {
            len: self.len,
            checkpoints: checkpoints.into_boxed_slice(),
        }
    }

    pub(crate) fn snapshot_file(&self) -> std::io::Result<Arc<File>> {
        let mut file = tempfile::tempfile()?;
        let mut offset = 0_u64;
        let total = self.len.saturating_mul(R::BYTES as u64);
        let mut buffer = vec![0_u8; 1024 * 1024];
        while offset < total {
            let take =
                usize::try_from((total - offset).min(buffer.len() as u64)).expect("relation page fits usize");
            self.read_exact_at(offset, &mut buffer[..take])?;
            file.write_all(&buffer[..take])?;
            offset = offset.saturating_add(take as u64);
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(Arc::new(file))
    }

    pub(crate) fn from_persisted(
        metadata: PersistedExternalRelation,
        storage: QueryAcceleratorBlobReader,
    ) -> Result<Self, &'static str> {
        let expected_checkpoints = metadata.len.div_ceil(INDEX_STRIDE) as usize;
        if metadata.checkpoints.len() != expected_checkpoints.saturating_mul(R::BYTES)
            || storage.len() != metadata.len.saturating_mul(R::BYTES as u64)
        {
            return Err("external relation layout");
        }
        let checkpoints: Vec<R> = metadata
            .checkpoints
            .chunks_exact(R::BYTES)
            .map(R::decode)
            .collect();
        if checkpoints.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("external relation checkpoint ordering");
        }
        Ok(Self {
            storage: ExternalRelationStorage::Persisted(storage),
            len: metadata.len,
            checkpoints: checkpoints.into_boxed_slice(),
        })
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> std::io::Result<()> {
        match &self.storage {
            ExternalRelationStorage::File(file) => read_exact_at(file, offset, output),
            ExternalRelationStorage::Persisted(blob) => blob
                .read_exact_at(offset, output)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        }
    }

    pub(crate) fn lower_bound(&self, row: R) -> u64 {
        if self.len == 0 {
            return 0;
        }
        // Rows may share a lookup prefix across several blocks. Starting
        // before the first equal checkpoint preserves every matching row.
        let checkpoint = self
            .checkpoints
            .partition_point(|candidate| *candidate < row)
            .saturating_sub(1) as u64;
        let block_start = checkpoint.saturating_mul(INDEX_STRIDE).min(self.len);
        let block_end = block_start.saturating_add(INDEX_STRIDE).min(self.len);
        let rows = usize::try_from(block_end - block_start).expect("relation block exceeds usize");
        let byte_count = rows.saturating_mul(R::BYTES);
        let mut block = vec![0_u8; byte_count];
        if byte_count > 0 {
            self.read_exact_at(block_start.saturating_mul(R::BYTES as u64), &mut block)
                .expect("read sorted exact compiler relation block");
        }
        let mut low = 0usize;
        let mut high = rows;
        while low < high {
            let middle = low + (high - low) / 2;
            if R::decode(&block[middle * R::BYTES..(middle + 1) * R::BYTES]) < row {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        block_start.saturating_add(u64::try_from(low).expect("relation block index exceeds u64"))
    }

    pub(crate) fn visit_range(&self, mut start: u64, end: u64, mut visit: impl FnMut(R)) {
        let mut payload = vec![0_u8; READ_ROWS * R::BYTES];
        while start < end {
            let rows =
                usize::try_from((end - start).min(READ_ROWS as u64)).expect("relation page exceeds usize");
            let bytes = rows.saturating_mul(R::BYTES);
            self.read_exact_at(start.saturating_mul(R::BYTES as u64), &mut payload[..bytes])
                .expect("read sorted exact compiler relation range");
            for record in payload[..bytes].chunks_exact(R::BYTES) {
                visit(R::decode(record));
            }
            start += rows as u64;
        }
    }

    pub(crate) fn visit_while(&self, mut start: u64, mut visit: impl FnMut(R) -> bool) {
        let mut payload = vec![0_u8; READ_ROWS * R::BYTES];
        while start < self.len {
            let rows = usize::try_from((self.len - start).min(READ_ROWS as u64))
                .expect("relation page exceeds usize");
            let bytes = rows.saturating_mul(R::BYTES);
            self.read_exact_at(start.saturating_mul(R::BYTES as u64), &mut payload[..bytes])
                .expect("read sorted exact compiler relation range");
            for record in payload[..bytes].chunks_exact(R::BYTES) {
                if !visit(R::decode(record)) {
                    return;
                }
            }
            start += rows as u64;
        }
    }
}

struct RunReader<'a, R> {
    file: &'a File,
    offset: u64,
    remaining: u32,
    payload: Vec<u8>,
    position: usize,
    page_rows: usize,
    marker: std::marker::PhantomData<R>,
}

impl<R: ExternalRecord> RunReader<'_, R> {
    fn next(&mut self) -> Option<R> {
        if self.remaining == 0 {
            return None;
        }
        if self.position == self.payload.len() {
            let rows = usize::try_from(self.remaining)
                .expect("exact compiler relation run fits usize")
                .min(self.page_rows);
            self.payload.resize(rows.saturating_mul(R::BYTES), 0);
            read_exact_at(self.file, self.offset, &mut self.payload)
                .expect("read exact compiler relation run");
            self.offset += self.payload.len() as u64;
            self.position = 0;
        }
        let end = self.position + R::BYTES;
        let row = R::decode(&self.payload[self.position..end]);
        self.position = end;
        self.remaining -= 1;
        Some(row)
    }
}

struct RunMerger<'a, R> {
    readers: Vec<RunReader<'a, R>>,
    pending: BinaryHeap<Reverse<(R, usize)>>,
}

impl<'a, R: ExternalRecord> RunMerger<'a, R> {
    fn new(file: &'a File, runs: &[RunEntry]) -> Self {
        let page_rows = merge_page_rows(runs.len(), R::BYTES, READ_ROWS);
        let mut readers = runs
            .iter()
            .map(|run| RunReader {
                file,
                offset: run.offset,
                remaining: run.count,
                payload: Vec::new(),
                position: 0,
                page_rows,
                marker: std::marker::PhantomData,
            })
            .collect::<Vec<_>>();
        let mut pending = BinaryHeap::new();
        for (index, reader) in readers.iter_mut().enumerate() {
            if let Some(row) = reader.next() {
                pending.push(Reverse((row, index)));
            }
        }
        Self { readers, pending }
    }
}

impl<R: ExternalRecord> Iterator for RunMerger<'_, R> {
    type Item = R;

    fn next(&mut self) -> Option<Self::Item> {
        let Reverse((row, reader)) = self.pending.pop()?;
        if let Some(next) = self.readers[reader].next() {
            self.pending.push(Reverse((next, reader)));
        }
        Some(row)
    }
}

#[cfg(test)]
mod tests {
    use super::{merge_page_rows, ExternalRecord, ExternalSorter, MAXIMUM_MERGE_BUFFER_BYTES};

    #[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct Word(u32);

    impl ExternalRecord for Word {
        const BYTES: usize = std::mem::size_of::<u32>();

        fn encode(self, output: &mut Vec<u8>) {
            output.extend_from_slice(&self.0.to_le_bytes());
        }

        fn decode(record: &[u8]) -> Self {
            Self(u32::from_le_bytes(
                record.try_into().expect("word record must be fixed width"),
            ))
        }
    }

    #[test]
    fn merge_uses_one_positioned_file_across_many_runs() {
        let mut sorter = ExternalSorter::new(1);
        for value in (0..2_048).rev() {
            sorter.push(Word(value));
        }
        let relation = sorter.finish();
        let mut values = Vec::new();
        relation.visit_range(0, relation.len(), |word| values.push(word.0));

        assert_eq!(values, (0..2_048).collect::<Vec<_>>());
        assert_eq!(relation.lower_bound(Word(1_337)), 1_337);
    }

    #[test]
    fn merge_pages_share_one_bounded_payload_budget() {
        let runs = 2_048;
        let rows = merge_page_rows(runs, Word::BYTES, 2_048);
        assert!(rows >= 1);
        assert!(
            runs * rows * Word::BYTES
                <= usize::try_from(MAXIMUM_MERGE_BUFFER_BYTES).expect("merge budget fits usize")
        );
    }
}
