//! Exact external-memory set for large compiler fixed points.
//!
//! The semantic relation is never capped. A bounded resident hash table is
//! flushed into immutable sorted runs, equal-sized runs are merged like an
//! LSM tree, and one bounded Bloom filter avoids probing the runs for keys
//! that have never entered the relation. Bloom positives are always checked
//! against the sorted runs, so false positives affect speed but never compiler
//! results.

use crate::positioned_io::read_exact_at;
use ahash::{AHashMap, AHashSet};
use parking_lot::RwLock;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU8, Ordering};

const KEY_BYTES: u64 = std::mem::size_of::<u128>() as u64;
const RUN_INDEX_ENTRIES: usize = 256;
const RUN_INDEX_STRIDE: u64 = RUN_INDEX_ENTRIES as u64;
const RUN_BLOCK_BYTES: usize = RUN_INDEX_ENTRIES * std::mem::size_of::<u128>();
const MAX_BLOOM_HASH_COUNT: u64 = 7;
const RECENT_POSITIVE_ASSOCIATIVITY: usize = 4;
const RECENT_POSITIVE_OCCUPIED: u8 = 1;
const RECENT_POSITIVE_REFERENCED: u8 = 2;
const RECENT_POSITIVE_SET_BYTES: usize = RECENT_POSITIVE_ASSOCIATIVITY
    * (std::mem::size_of::<u128>() + std::mem::size_of::<AtomicU8>())
    + std::mem::size_of::<u8>();

struct BloomFilter {
    words: Box<[u64]>,
    bit_len: u64,
    hash_count: u64,
}

impl BloomFilter {
    fn new(bytes: usize, expected_items: u64) -> Self {
        let word_count = bytes
            .max(std::mem::size_of::<u64>())
            .div_ceil(std::mem::size_of::<u64>());
        let bit_len = (word_count as u64).saturating_mul(u64::BITS as u64);
        // `ln(2) ~= 0.7`: the optimal Bloom hash count is
        // `(bits / entries) * ln(2)`. Integer arithmetic keeps construction
        // deterministic across platforms.
        let bits_per_item = bit_len / expected_items.max(1);
        let hash_count = bits_per_item
            .saturating_mul(7)
            .div_ceil(10)
            .clamp(1, MAX_BLOOM_HASH_COUNT);
        Self {
            words: vec![0; word_count].into_boxed_slice(),
            bit_len,
            hash_count,
        }
    }

    fn insert(&mut self, key: u128) {
        let (first, step) = bloom_hashes(key);
        for round in 0..self.hash_count {
            let bit = first.wrapping_add(round.wrapping_mul(step)) % self.bit_len;
            self.words[(bit / u64::BITS as u64) as usize] |= 1_u64 << (bit % u64::BITS as u64);
        }
    }

    fn may_contain(&self, key: u128) -> bool {
        let (first, step) = bloom_hashes(key);
        (0..self.hash_count).all(|round| {
            let bit = first.wrapping_add(round.wrapping_mul(step)) % self.bit_len;
            self.words[(bit / u64::BITS as u64) as usize] & (1_u64 << (bit % u64::BITS as u64)) != 0
        })
    }

    fn byte_len(&self) -> usize {
        self.words.len().saturating_mul(std::mem::size_of::<u64>())
    }
}

fn bloom_hashes(key: u128) -> (u64, u64) {
    let low = key as u64;
    let high = (key >> u64::BITS) as u64;
    let first = mix64(low ^ high.rotate_left(17));
    let step = mix64(high ^ low.rotate_left(31) ^ 0x9e37_79b9_7f4a_7c15) | 1;
    (first, step)
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

struct SortedRun {
    file: File,
    len: u64,
    checkpoints: Box<[u128]>,
}

impl SortedRun {
    fn from_sorted(keys: &[u128]) -> io::Result<Self> {
        let file = tempfile::tempfile()?;
        let mut writer = RunWriter::new(file);
        for &key in keys {
            writer.push(key)?;
        }
        writer.finish()
    }

    fn contains(&self, key: u128) -> io::Result<bool> {
        self.locate(key).map(|(_, found)| found)
    }

    fn append_prefix_batch(
        &mut self,
        prefix: u32,
        after: Option<u128>,
        limit: usize,
        keys: &mut Vec<u128>,
    ) -> io::Result<()> {
        let lower = u128::from(prefix) << 96;
        let upper = if prefix == u32::MAX {
            u128::MAX
        } else {
            (u128::from(prefix + 1) << 96).saturating_sub(1)
        };
        if after.is_some_and(|key| key >= upper) {
            return Ok(());
        }
        let first = after.map_or(lower, |key| key.saturating_add(1).max(lower));
        let start = self.lower_bound(first)?;
        self.file.seek(SeekFrom::Start(start.saturating_mul(KEY_BYTES)))?;
        let mut reader = BufReader::new(&mut self.file);
        let mut appended = 0usize;
        for _ in start..self.len {
            let key = read_key(&mut reader)?;
            if key > upper {
                break;
            }
            keys.push(key);
            appended += 1;
            if appended >= limit {
                break;
            }
        }
        Ok(())
    }

    fn lower_bound(&self, key: u128) -> io::Result<u64> {
        self.locate(key).map(|(index, _)| index)
    }

    fn locate(&self, key: u128) -> io::Result<(u64, bool)> {
        let checkpoint = self
            .checkpoints
            .partition_point(|candidate| *candidate <= key)
            .saturating_sub(1) as u64;
        let block_start = checkpoint.saturating_mul(RUN_INDEX_STRIDE).min(self.len);
        let block_end = block_start.saturating_add(RUN_INDEX_STRIDE).min(self.len);
        let entry_count = usize::try_from(block_end - block_start).expect("run block exceeds usize");
        let byte_count = entry_count.saturating_mul(std::mem::size_of::<u128>());
        let mut block = [0_u8; RUN_BLOCK_BYTES];
        if byte_count > 0 {
            read_exact_at(
                &self.file,
                block_start.saturating_mul(KEY_BYTES),
                &mut block[..byte_count],
            )?;
        }

        let mut low = 0usize;
        let mut high = entry_count;
        while low < high {
            let middle = low + (high - low) / 2;
            if block_key(&block, middle) < key {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let found = low < entry_count && block_key(&block, low) == key;
        Ok((
            block_start.saturating_add(u64::try_from(low).expect("run index exceeds u64")),
            found,
        ))
    }
}

fn block_key(block: &[u8; RUN_BLOCK_BYTES], index: usize) -> u128 {
    let start = index.saturating_mul(std::mem::size_of::<u128>());
    let end = start.saturating_add(std::mem::size_of::<u128>());
    let bytes = block[start..end]
        .try_into()
        .expect("run block key must occupy 16 bytes");
    u128::from_le_bytes(bytes)
}

struct RunWriter {
    writer: BufWriter<File>,
    len: u64,
    checkpoints: Vec<u128>,
    previous: Option<u128>,
}

impl RunWriter {
    fn new(file: File) -> Self {
        Self {
            writer: BufWriter::new(file),
            len: 0,
            checkpoints: Vec::new(),
            previous: None,
        }
    }

    fn push(&mut self, key: u128) -> io::Result<()> {
        if self.previous == Some(key) {
            return Ok(());
        }
        debug_assert!(self.previous.is_none_or(|previous| previous < key));
        if self.len.is_multiple_of(RUN_INDEX_STRIDE) {
            self.checkpoints.push(key);
        }
        self.writer.write_all(&key.to_le_bytes())?;
        self.previous = Some(key);
        self.len += 1;
        Ok(())
    }

    fn finish(mut self) -> io::Result<SortedRun> {
        self.writer.flush()?;
        let mut file = self.writer.into_inner().map_err(|error| error.into_error())?;
        file.seek(SeekFrom::Start(0))?;
        Ok(SortedRun {
            file,
            len: self.len,
            checkpoints: self.checkpoints.into_boxed_slice(),
        })
    }
}

fn read_key(reader: &mut impl Read) -> io::Result<u128> {
    let mut bytes = [0_u8; std::mem::size_of::<u128>()];
    reader.read_exact(&mut bytes)?;
    Ok(u128::from_le_bytes(bytes))
}

fn merge_runs(left: SortedRun, right: SortedRun) -> io::Result<SortedRun> {
    let mut left = BufReader::new(left.file);
    let mut right = BufReader::new(right.file);
    left.seek(SeekFrom::Start(0))?;
    right.seek(SeekFrom::Start(0))?;
    let mut left_remaining = left.get_ref().metadata()?.len() / KEY_BYTES;
    let mut right_remaining = right.get_ref().metadata()?.len() / KEY_BYTES;
    let mut left_key = (left_remaining > 0).then(|| read_key(&mut left)).transpose()?;
    let mut right_key = (right_remaining > 0).then(|| read_key(&mut right)).transpose()?;
    let mut writer = RunWriter::new(tempfile::tempfile()?);

    while left_key.is_some() || right_key.is_some() {
        let take_left = match (left_key, right_key) {
            (Some(left), Some(right)) => left <= right,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let key = if take_left {
            let key = left_key.expect("left merge key");
            left_remaining -= 1;
            left_key = (left_remaining > 0).then(|| read_key(&mut left)).transpose()?;
            key
        } else {
            let key = right_key.expect("right merge key");
            right_remaining -= 1;
            right_key = (right_remaining > 0).then(|| read_key(&mut right)).transpose()?;
            key
        };
        writer.push(key)?;
    }
    writer.finish()
}

/// Exact set with a bounded resident delta and logarithmically many sorted
/// temporary runs.
pub(crate) struct SpillSet {
    resident: AHashSet<u128>,
    /// Bounded acceleration cache for keys already proven present.
    ///
    /// Large fixed points repeatedly rediscover the same recently propagated
    /// states after their primary resident delta has flushed. Remembering
    /// those positives avoids a positioned read into a sorted run. Eviction
    /// only causes another exact lookup and therefore cannot change set
    /// membership or fixed-point semantics.
    /// Allocated only after the resident relation first spills. Before that,
    /// `resident` is the complete relation, so a second membership structure
    /// would only add allocator work to small compiler closures.
    recent_positives: RwLock<Option<RecentPositiveCache>>,
    recent_positive_budget_bytes: usize,
    resident_by_prefix: Option<AHashMap<u32, Vec<u128>>>,
    max_resident_entries: usize,
    levels: Vec<Option<SortedRun>>,
    /// One bounded negative-membership filter for the complete relation.
    ///
    /// A filter miss proves that no sorted run contains the key. A possible
    /// hit always falls through to the exact run index, so saturation or
    /// false positives affect only speed. Keeping one filter avoids hashing
    /// every insertion once per LSM level and avoids rebuilding filters when
    /// immutable runs merge.
    membership_filter: Option<BloomFilter>,
    membership_filter_budget_bytes: usize,
    len: u64,
}

struct RecentPositiveCache {
    keys: Box<[u128]>,
    metadata: Box<[AtomicU8]>,
    hands: Box<[u8]>,
    set_count: usize,
    len: usize,
}

impl RecentPositiveCache {
    /// Build a compact exact-positive cache from an explicit acceleration
    /// budget. The budget controls only how many proven hits remain hot:
    /// eviction always falls back to the exact external relation.
    fn new(memory_budget_bytes: usize) -> Self {
        let set_count = (memory_budget_bytes / RECENT_POSITIVE_SET_BYTES).max(1);
        let capacity = set_count.saturating_mul(RECENT_POSITIVE_ASSOCIATIVITY);
        Self {
            keys: vec![0; capacity].into_boxed_slice(),
            metadata: (0..capacity)
                .map(|_| AtomicU8::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            hands: vec![0; set_count].into_boxed_slice(),
            set_count,
            len: 0,
        }
    }

    fn contains(&self, key: u128) -> bool {
        let start = self.set_start(key);
        for index in start..start + RECENT_POSITIVE_ASSOCIATIVITY {
            let metadata = self.metadata[index].load(Ordering::Relaxed);
            // Sets fill from the first free way and eviction never creates a
            // hole, so the first empty way proves the remaining ways empty.
            if metadata & RECENT_POSITIVE_OCCUPIED == 0 {
                return false;
            }
            if self.keys[index] == key {
                // A membership reader holds the cache's shared lock, so the
                // key cannot be replaced while its CLOCK reference is
                // refreshed. The bit is only an eviction hint.
                self.metadata[index].fetch_or(RECENT_POSITIVE_REFERENCED, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    fn remember(&mut self, key: u128) {
        if self.contains(key) {
            return;
        }
        self.remember_absent(key);
    }

    /// Insert a key that the caller has already proven absent from this
    /// cache while holding exclusive access.
    fn remember_absent(&mut self, key: u128) {
        let set = self.set_index(key);
        let start = set.saturating_mul(RECENT_POSITIVE_ASSOCIATIVITY);
        if let Some(index) = (start..start + RECENT_POSITIVE_ASSOCIATIVITY)
            .find(|&index| self.metadata[index].load(Ordering::Relaxed) & RECENT_POSITIVE_OCCUPIED == 0)
        {
            self.keys[index] = key;
            self.metadata[index].store(
                RECENT_POSITIVE_OCCUPIED | RECENT_POSITIVE_REFERENCED,
                Ordering::Relaxed,
            );
            self.len += 1;
            return;
        }

        let mut hand = usize::from(self.hands[set]) % RECENT_POSITIVE_ASSOCIATIVITY;
        loop {
            let index = start + hand;
            let metadata = self.metadata[index].swap(RECENT_POSITIVE_OCCUPIED, Ordering::Relaxed);
            hand = (hand + 1) % RECENT_POSITIVE_ASSOCIATIVITY;
            if metadata & RECENT_POSITIVE_REFERENCED != 0 {
                continue;
            }
            self.keys[index] = key;
            self.metadata[index].store(
                RECENT_POSITIVE_OCCUPIED | RECENT_POSITIVE_REFERENCED,
                Ordering::Relaxed,
            );
            self.hands[set] = hand as u8;
            return;
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn set_index(&self, key: u128) -> usize {
        let low = key as u64;
        let high = (key >> u64::BITS) as u64;
        (mix64(low ^ high.rotate_left(29)) as usize) % self.set_count
    }

    fn set_start(&self, key: u128) -> usize {
        self.set_index(key).saturating_mul(RECENT_POSITIVE_ASSOCIATIVITY)
    }
}

impl SpillSet {
    pub(crate) fn new(
        max_resident_entries: usize,
        bloom_bytes: usize,
        recent_positive_bytes: usize,
        track_prefixes: bool,
    ) -> Self {
        let max_resident_entries = max_resident_entries.max(1);
        Self {
            // Small compiler closures are overwhelmingly common. Let the
            // resident delta grow with actual facts instead of reserving the
            // maximum spill page for every closure up front.
            resident: AHashSet::new(),
            recent_positives: RwLock::new(None),
            recent_positive_budget_bytes: recent_positive_bytes,
            resident_by_prefix: track_prefixes.then(AHashMap::default),
            max_resident_entries,
            levels: Vec::new(),
            membership_filter: None,
            membership_filter_budget_bytes: bloom_bytes,
            len: 0,
        }
    }

    pub(crate) fn insert(&mut self, key: u128) -> bool {
        if self.resident.contains(&key)
            || self
                .recent_positives
                .get_mut()
                .as_ref()
                .is_some_and(|cache| cache.contains(key))
        {
            return false;
        }
        if self.contains_in_runs(key) {
            self.recent_positives
                .get_mut()
                .as_mut()
                .expect("spilled relation has a positive cache")
                .remember_absent(key);
            return false;
        }

        self.resident.insert(key);
        if let Some(cache) = self.recent_positives.get_mut() {
            cache.remember_absent(key);
        }
        if let Some(by_prefix) = &mut self.resident_by_prefix {
            by_prefix.entry((key >> 96) as u32).or_default().push(key);
        }
        self.len = self.len.saturating_add(1);
        if self.resident.len() >= self.max_resident_entries {
            self.flush();
        }
        true
    }

    /// Test exact membership across the resident delta and every sorted run.
    ///
    /// Run reads are positioned, so a completed set can be queried safely by
    /// concurrent compiler workers without a shared file cursor or a resident
    /// mirror of spilled keys.
    pub(crate) fn contains(&self, key: u128) -> bool {
        // Keep the shared guard in its own scope. A proven run hit is promoted
        // below under the exclusive guard; relying on temporary-lifetime
        // shortening here can otherwise make that promotion self-deadlock.
        let recently_positive = {
            let cache = self.recent_positives.read();
            cache.as_ref().is_some_and(|cache| cache.contains(key))
        };
        if self.resident.contains(&key) || recently_positive {
            return true;
        }
        if !self.contains_in_runs(key) {
            return false;
        }
        self.recent_positives
            .write()
            .as_mut()
            .expect("spilled relation has a positive cache")
            .remember(key);
        true
    }

    fn contains_in_runs(&self, key: u128) -> bool {
        if self.levels.is_empty() {
            return false;
        }
        if self
            .membership_filter
            .as_ref()
            .is_some_and(|filter| !filter.may_contain(key))
        {
            return false;
        }
        self.levels
            .iter()
            .flatten()
            .any(|run| run.contains(key).expect("read exact compiler fixed-point run"))
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn resident_len(&self) -> usize {
        self.resident.len()
    }

    pub(crate) fn recent_positive_len(&self) -> usize {
        self.recent_positives
            .read()
            .as_ref()
            .map_or(0, RecentPositiveCache::len)
    }

    pub(crate) fn run_count(&self) -> usize {
        self.levels.iter().flatten().count()
    }

    pub(crate) fn disk_bytes(&self) -> u64 {
        self.levels
            .iter()
            .flatten()
            .map(|run| run.len.saturating_mul(KEY_BYTES))
            .sum()
    }

    pub(crate) fn bloom_filter_bytes(&self) -> usize {
        self.membership_filter.as_ref().map_or(0, BloomFilter::byte_len)
    }

    /// Return the next exact, sorted page for `prefix`.
    ///
    /// `limit` is a memory scheduling bound, not a semantic bound: callers
    /// continue with the last returned key until this returns an empty page.
    pub(crate) fn keys_with_prefix_batch(
        &mut self,
        prefix: u32,
        after: Option<u128>,
        limit: usize,
    ) -> Vec<u128> {
        let limit = limit.max(1);
        let mut keys = self
            .resident_by_prefix
            .as_ref()
            .and_then(|by_prefix| by_prefix.get(&prefix))
            .cloned()
            .unwrap_or_default();
        if let Some(after) = after {
            keys.retain(|key| *key > after);
        }
        keys.sort_unstable();
        keys.truncate(limit);
        for run in self.levels.iter_mut().flatten() {
            run.append_prefix_batch(prefix, after, limit, &mut keys)
                .expect("read exact compiler summary run");
        }
        keys.sort_unstable();
        keys.dedup();
        keys.truncate(limit);
        keys
    }

    fn flush(&mut self) {
        let mut keys: Vec<u128> = self.resident.drain().collect();
        keys.sort_unstable();
        let positive_cache = self
            .recent_positives
            .get_mut()
            .get_or_insert_with(|| RecentPositiveCache::new(self.recent_positive_budget_bytes));
        for &key in &keys {
            positive_cache.remember(key);
        }
        if self.membership_filter.is_none()
            && self.membership_filter_budget_bytes >= std::mem::size_of::<u64>()
        {
            self.membership_filter = Some(BloomFilter::new(
                self.membership_filter_budget_bytes,
                self.membership_filter_budget_bytes as u64,
            ));
        }
        if let Some(filter) = &mut self.membership_filter {
            for &key in &keys {
                filter.insert(key);
            }
        }
        if let Some(by_prefix) = &mut self.resident_by_prefix {
            by_prefix.clear();
        }
        let mut run = SortedRun::from_sorted(&keys).expect("write exact compiler fixed-point run");
        let mut level = 0usize;
        loop {
            if level == self.levels.len() {
                self.levels.push(Some(run));
                break;
            }
            if let Some(existing) = self.levels[level].take() {
                run = merge_runs(existing, run).expect("merge exact compiler fixed-point runs");
                level += 1;
            } else {
                self.levels[level] = Some(run);
                break;
            }
        }
    }
}

/// Bounded LIFO work frontier.
///
/// Fixed-point order is not semantic. When the resident stack fills, its
/// complete contents are written to one temporary chunk and reloaded when
/// newer work is exhausted. This retains stack locality while preventing a
/// sudden fan-out from becoming an unbounded `Vec`.
pub(crate) struct SpillStack {
    resident: Vec<u128>,
    max_resident_entries: usize,
    /// The vast majority of compiler frontiers fit in `resident`. Creating a
    /// temporary file per closure made setup cost proportional to function
    /// count even when no external-memory work occurred.
    file: Option<File>,
    chunks: Vec<SpillStackChunk>,
    len: u64,
}

#[derive(Copy, Clone)]
struct SpillStackChunk {
    offset: u64,
    len: u64,
}

impl SpillStack {
    pub(crate) fn new(max_resident_entries: usize) -> Self {
        let max_resident_entries = max_resident_entries.max(1);
        Self {
            resident: Vec::new(),
            max_resident_entries,
            file: None,
            chunks: Vec::new(),
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, key: u128) {
        self.resident.push(key);
        self.len = self.len.saturating_add(1);
        if self.resident.len() >= self.max_resident_entries {
            self.flush();
        }
    }

    pub(crate) fn pop(&mut self) -> Option<u128> {
        if self.resident.is_empty() {
            self.reload();
        }
        let key = self.resident.pop()?;
        self.len = self.len.saturating_sub(1);
        Some(key)
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn flush(&mut self) {
        let file = self
            .file
            .get_or_insert_with(|| tempfile::tempfile().expect("create exact compiler frontier store"));
        let offset = file
            .seek(SeekFrom::End(0))
            .expect("seek exact compiler frontier store");
        {
            let mut writer = BufWriter::new(&mut *file);
            for &key in &self.resident {
                writer
                    .write_all(&key.to_le_bytes())
                    .expect("write exact compiler frontier store");
            }
            writer.flush().expect("flush exact compiler frontier store");
        }
        self.chunks.push(SpillStackChunk {
            offset,
            len: self.resident.len() as u64,
        });
        self.resident.clear();
    }

    fn reload(&mut self) {
        let Some(chunk) = self.chunks.pop() else {
            return;
        };
        let file = self
            .file
            .as_mut()
            .expect("spilled compiler frontier has a backing file");
        file.seek(SeekFrom::Start(chunk.offset))
            .expect("seek exact compiler frontier chunk");
        self.resident.clear();
        {
            let mut reader = BufReader::new(&mut *file);
            for _ in 0..chunk.len {
                self.resident
                    .push(read_key(&mut reader).expect("read exact compiler frontier chunk"));
            }
        }
        // Chunks are consumed newest-first, so the popped chunk is always the
        // tail of the file. Truncation bounds disk use to the live frontier
        // and retains older chunk offsets unchanged.
        file.set_len(chunk.offset)
            .expect("truncate consumed exact compiler frontier chunk");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RecentPositiveCache, SortedRun, SpillSet, SpillStack, RECENT_POSITIVE_ASSOCIATIVITY,
        RECENT_POSITIVE_SET_BYTES, RUN_INDEX_ENTRIES,
    };

    #[test]
    fn spill_set_deduplicates_across_resident_and_merged_runs() {
        let mut set = SpillSet::new(2, 128, 128, false);
        for key in [9, 1, 7, 3, 5, 1, 9, 11, 13, 15, 7] {
            set.insert(key);
        }
        assert_eq!(set.len(), 8);
        for key in [1, 3, 5, 7, 9, 11, 13, 15] {
            assert!(set.contains(key));
            assert!(!set.insert(key));
        }
        assert!(!set.contains(2));
        assert_eq!(set.len(), 8);
    }

    #[test]
    fn sorted_run_checkpoint_boundaries_preserve_exact_membership() {
        let keys = (0..RUN_INDEX_ENTRIES * 3 + 17)
            .map(|key| key as u128 * 2)
            .collect::<Vec<_>>();
        let run = SortedRun::from_sorted(&keys).expect("sorted run");

        for &index in &[
            0,
            1,
            RUN_INDEX_ENTRIES - 1,
            RUN_INDEX_ENTRIES,
            RUN_INDEX_ENTRIES + 1,
            RUN_INDEX_ENTRIES * 2,
            keys.len() - 1,
        ] {
            let key = keys[index];
            assert!(run.contains(key).expect("exact run lookup"), "missing key {key}");
            assert!(
                !run.contains(key + 1).expect("exact run lookup"),
                "non-member beside {key} was reported present"
            );
        }
    }

    #[test]
    fn recent_positive_cache_is_bounded_and_eviction_falls_back_to_exact_runs() {
        let mut set = SpillSet::new(2, 128, RECENT_POSITIVE_SET_BYTES, false);
        assert!(
            set.recent_positives.get_mut().is_none(),
            "resident-only relations must not allocate spill acceleration"
        );
        assert!(set.insert(0));
        assert!(set.insert(1));
        let capacity = set
            .recent_positives
            .get_mut()
            .as_ref()
            .expect("first spill allocates positive cache")
            .keys
            .len();
        assert_eq!(capacity, RECENT_POSITIVE_ASSOCIATIVITY);
        for key in 2..capacity as u128 {
            assert!(set.insert(key));
        }
        assert_eq!(set.recent_positive_len(), capacity);
        assert!(set.insert(capacity as u128));
        assert!(set
            .recent_positives
            .get_mut()
            .as_ref()
            .is_some_and(|cache| cache.contains(capacity as u128)));
        assert!(!set
            .recent_positives
            .get_mut()
            .as_ref()
            .is_some_and(|cache| cache.contains(0)));
        assert!(
            set.contains(0),
            "read-only membership must fall back to the exact run"
        );
        assert!(
            set.recent_positives
                .get_mut()
                .as_ref()
                .is_some_and(|cache| cache.contains(0)),
            "a proven read-only hit should populate the bounded hot cache"
        );

        assert!(
            !set.insert(capacity as u128),
            "hot positive must deduplicate from memory"
        );
        assert!(
            !set.insert(0),
            "evicted positive must deduplicate from the exact run"
        );
        assert_eq!(set.len(), capacity as u64 + 1);
        assert!(
            set.recent_positive_len()
                <= set
                    .recent_positives
                    .get_mut()
                    .as_ref()
                    .expect("spilled set positive cache")
                    .keys
                    .len()
        );
    }

    #[test]
    fn recent_positive_reads_refresh_clock_references() {
        let mut cache = RecentPositiveCache::new(RECENT_POSITIVE_SET_BYTES);
        assert_eq!(cache.keys.len(), 4);
        for key in 0..4 {
            cache.remember(key);
        }

        // The first replacement clears the initial reference bits and evicts
        // slot zero. A read of key one must refresh its bit so the next
        // replacement advances to key two instead.
        cache.remember(4);
        assert!(cache.contains(1));
        cache.remember(5);

        assert!(cache.contains(1), "a recently read key must survive eviction");
        assert!(!cache.contains(2), "CLOCK must evict the next cold key");
    }

    #[test]
    fn recent_positive_cache_uses_its_byte_budget_without_duplicate_keys() {
        let budget = RECENT_POSITIVE_SET_BYTES.saturating_mul(10) + 17;
        let cache = RecentPositiveCache::new(budget);
        let allocation_bytes = cache
            .keys
            .len()
            .saturating_mul(std::mem::size_of::<u128>())
            .saturating_add(
                cache
                    .metadata
                    .len()
                    .saturating_mul(std::mem::size_of::<std::sync::atomic::AtomicU8>()),
            )
            .saturating_add(cache.hands.len().saturating_mul(std::mem::size_of::<u8>()));

        assert_eq!(cache.set_count, 10);
        assert_eq!(cache.keys.len(), 40);
        assert!(allocation_bytes <= budget);
    }

    #[test]
    fn spilled_set_supports_concurrent_positioned_membership_reads() {
        let mut set = SpillSet::new(2, 128, 128, false);
        for key in 0..128 {
            assert!(set.insert(key));
        }
        let set = std::sync::Arc::new(set);
        let readers = (0..4)
            .map(|_| {
                let set = std::sync::Arc::clone(&set);
                std::thread::spawn(move || {
                    for key in 0..128 {
                        assert!(set.contains(key));
                    }
                    assert!(!set.contains(512));
                })
            })
            .collect::<Vec<_>>();
        for reader in readers {
            reader.join().expect("membership reader");
        }
    }

    #[test]
    fn spill_set_membership_filter_stays_bounded_without_changing_membership() {
        let mut set = SpillSet::new(1024, 1024, 1024, false);
        for key in 0..1024 {
            assert!(set.insert(key));
        }
        assert!(
            set.bloom_filter_bytes() <= 1024,
            "acceleration indexes must respect their resident-memory budget"
        );
        for key in 0..1024 {
            assert!(!set.insert(key), "spilled key {key} must remain exact");
        }
        for key in 1024..2048 {
            assert!(set.insert(key), "new key {key} must not be a false hit");
        }
    }

    #[test]
    fn membership_filter_tracks_only_spilled_keys() {
        let mut set = SpillSet::new(4, 128, 128, false);
        assert!(
            set.recent_positives.get_mut().is_none(),
            "resident-only sets must not allocate a positive cache"
        );
        for key in 0..3 {
            assert!(set.insert(key));
        }
        assert!(
            set.membership_filter.is_none(),
            "resident membership is already exact and must not allocate a spill filter"
        );
        assert!(
            set.recent_positives.get_mut().is_none(),
            "resident membership is already exact and must not allocate a positive cache"
        );
        assert!(set.insert(3), "the fourth key flushes the resident delta");
        assert!(
            set.recent_positives.get_mut().is_some(),
            "the first spill should instantiate its bounded positive cache"
        );
        let filter = set.membership_filter.as_ref().expect("membership filter");
        assert!(
            (0..4).all(|key| filter.may_contain(key)),
            "every spilled key must enter the negative-membership filter"
        );
    }

    #[test]
    fn spill_set_replays_exact_prefix_members_after_flushes() {
        let mut set = SpillSet::new(2, 128, 128, true);
        let key = |prefix: u32, value: u128| (u128::from(prefix) << 96) | value;
        for item in [key(2, 8), key(1, 7), key(2, 3), key(1, 4), key(2, 5)] {
            assert!(set.insert(item));
        }
        let first = set.keys_with_prefix_batch(2, None, 2);
        assert_eq!(first, vec![key(2, 3), key(2, 5)]);
        let second = set.keys_with_prefix_batch(2, first.last().copied(), 2);
        assert_eq!(second, vec![key(2, 8)]);
        assert!(set
            .keys_with_prefix_batch(2, second.last().copied(), 2)
            .is_empty());
        assert!(set.keys_with_prefix_batch(9, None, 2).is_empty());
    }

    #[test]
    fn spill_set_prefix_cursor_terminates_after_maximum_key() {
        let mut set = SpillSet::new(1, 128, 128, true);
        assert!(set.insert(u128::MAX));
        assert_eq!(set.keys_with_prefix_batch(u32::MAX, None, 1), vec![u128::MAX]);
        assert!(set
            .keys_with_prefix_batch(u32::MAX, Some(u128::MAX), 1)
            .is_empty());
    }

    #[test]
    fn spill_stack_preserves_lifo_work_across_bounded_chunks() {
        let mut stack = SpillStack::new(2);
        assert!(
            stack.file.is_none(),
            "resident-only frontiers must not create temporary files"
        );
        stack.push(0);
        assert!(
            stack.file.is_none(),
            "frontier files must remain lazy below the spill threshold"
        );
        for key in 1..7 {
            stack.push(key);
        }
        assert_eq!(stack.chunks.len(), 3);
        assert_eq!(stack.len(), 7);
        let popped: Vec<_> = std::iter::from_fn(|| stack.pop()).collect();
        assert_eq!(popped, vec![6, 5, 4, 3, 2, 1, 0]);
        assert!(stack.is_empty());
        assert!(stack.chunks.is_empty());
        assert_eq!(
            stack
                .file
                .as_ref()
                .expect("spilled frontier backing file")
                .metadata()
                .expect("frontier store metadata")
                .len(),
            0,
            "consumed LIFO chunks should release temporary disk space"
        );
    }
}
