//! In-memory LRU cache for decoded fact values.
//!
//! Sits in front of [`crate::FactStoreReader`] so the hot working set
//! of a security scan stays in process memory while the long tail
//! pages through the OS file cache. Hot lookups are a single
//! `HashMap::get` + `Arc::clone`; cold lookups read from disk and
//! decode via the caller-supplied closure.
//!
//! ## Bounded size, not bounded correctness
//!
//! The cache cap is a memory-management knob, not an accuracy knob.
//! Eviction never makes a query return the wrong answer — evicted
//! entries are simply re-read from disk on the next access. Callers
//! can pick the cap based on the host's RAM budget.
//!
//! ## Concurrency
//!
//! Internal state is wrapped in `parking_lot::Mutex`. The mutex is
//! held only for the index update + LRU bookkeeping; the cold-path
//! decode runs outside the lock so concurrent readers don't serialise
//! on a slow decode. Two readers racing on the same key may both
//! decode (the loser's value is dropped on insert), which is fine
//! because decoders are pure functions of the on-disk bytes.

use crate::error::FactStoreResult;
use crate::reader::{FactStoreReader, LookupHit};
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Result of a cache lookup. Hits return the cached `Arc<V>`; misses
/// return `None` (the caller should decode + insert) or errors from
/// the underlying reader.
#[derive(Debug)]
pub enum CacheGet<V> {
    /// Cached value found in the LRU.
    Hit(Arc<V>),
    /// Key exists on disk; payload bytes loaded but not yet decoded.
    /// The caller decodes via [`FactCache::insert_decoded`].
    Miss(LookupHit),
    /// No entry on disk for this key.
    Absent,
}

/// LRU cache of decoded values fronting a [`FactStoreReader`].
///
/// Generic over the decoded value type so the same wrapper serves
/// `ValueFlowGraph`, `EntryTaintGraph`, `KindedTokens`, and any
/// other per-`FuncId` analysis fact.
pub struct FactCache<V> {
    reader: FactStoreReader,
    cache: Mutex<LruCache<u64, Arc<V>>>,
}

impl<V> FactCache<V> {
    /// Wrap `reader` with an LRU cache of `capacity` entries.
    /// `capacity` must be non-zero.
    #[must_use]
    pub fn new(reader: FactStoreReader, capacity: NonZeroUsize) -> Self {
        Self {
            reader,
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Borrow the underlying reader. Useful for advanced callers that
    /// want to iterate every entry (`reader.iter()`) or read the
    /// string pool (`reader.string_pool()`).
    #[must_use]
    pub fn reader(&self) -> &FactStoreReader {
        &self.reader
    }

    /// Probe the cache for `key`. On a miss, reads the payload bytes
    /// from disk so the caller can decode them, but does NOT insert
    /// into the LRU yet (the caller does that via
    /// [`Self::insert_decoded`] once decoding succeeds).
    ///
    /// Splitting probe and insert lets callers attribute decode time
    /// to the cold-path budget without holding the cache lock.
    pub fn get(&self, key: u64) -> FactStoreResult<CacheGet<V>> {
        if let Some(hit) = self.cache.lock().get(&key).cloned() {
            return Ok(CacheGet::Hit(hit));
        }
        match self.reader.get(key)? {
            Some(payload) => Ok(CacheGet::Miss(payload)),
            None => Ok(CacheGet::Absent),
        }
    }

    /// Convenience wrapper: probe; on miss, decode via `decode` and
    /// insert. Returns the resulting `Arc<V>`.
    ///
    /// Two threads racing on the same `key` may both decode; the
    /// LRU's `put` keeps the second writer's value. Both threads then
    /// hold an `Arc<V>` that compares value-equal (decoders are pure)
    /// even though `Arc::ptr_eq` may not.
    pub fn get_or_decode<F>(&self, key: u64, decode: F) -> FactStoreResult<Option<Arc<V>>>
    where
        F: FnOnce(&[u8]) -> Arc<V>,
    {
        match self.get(key)? {
            CacheGet::Hit(value) => Ok(Some(value)),
            CacheGet::Miss(hit) => {
                let value = decode(&hit.payload);
                self.cache.lock().put(key, value.clone());
                Ok(Some(value))
            }
            CacheGet::Absent => Ok(None),
        }
    }

    /// Insert a freshly-decoded value for `key`. Used by callers that
    /// got a [`CacheGet::Miss`] from [`Self::get`], decoded the bytes
    /// outside the lock, and now want to publish the result.
    pub fn insert_decoded(&self, key: u64, value: Arc<V>) {
        self.cache.lock().put(key, value);
    }

    /// Number of entries currently resident in the LRU.
    #[must_use]
    pub fn resident(&self) -> usize {
        self.cache.lock().len()
    }

    /// Drop every cached value. The next access will re-decode from
    /// disk. Used after a workspace edit when the on-disk store was
    /// regenerated.
    pub fn clear(&self) {
        self.cache.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::FactStoreWriter;
    use std::path::Path;

    fn write_test_store(path: &Path, entries: &[(u64, u64, &[u8])]) {
        let w = FactStoreWriter::create(path, 0, 0).expect("create");
        for &(key, body_hash, payload) in entries {
            w.add(key, body_hash, payload).expect("add");
        }
        w.finish().expect("finish");
    }

    /// Decoder that just sums the payload bytes — keeps tests
    /// concrete without dragging in bincode.
    fn sum_decoder(bytes: &[u8]) -> Arc<u32> {
        Arc::new(bytes.iter().map(|b| u32::from(*b)).sum())
    }

    #[test]
    fn first_get_misses_then_hits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(&path, &[(1, 0, &[1, 2, 3])]);
        let reader = FactStoreReader::open(&path, 0, 0).expect("open");
        let cache: FactCache<u32> = FactCache::new(reader, NonZeroUsize::new(8).unwrap());
        let v1 = cache.get_or_decode(1, sum_decoder).expect("ok").expect("hit");
        assert_eq!(*v1, 6);
        // Second time should return the cached Arc directly.
        let v2 = match cache.get(1).expect("ok") {
            CacheGet::Hit(v) => v,
            other => panic!("expected hit, got {other:?}"),
        };
        assert!(Arc::ptr_eq(&v1, &v2));
    }

    #[test]
    fn lookup_for_unknown_key_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(&path, &[(1, 0, &[1])]);
        let reader = FactStoreReader::open(&path, 0, 0).expect("open");
        let cache: FactCache<u32> = FactCache::new(reader, NonZeroUsize::new(8).unwrap());
        match cache.get(999).expect("ok") {
            CacheGet::Absent => {}
            other => panic!("expected Absent, got {other:?}"),
        }
        assert!(cache.get_or_decode(999, sum_decoder).expect("ok").is_none());
    }

    #[test]
    fn evicted_entries_re_decode_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(&path, &[(1, 0, &[1]), (2, 0, &[2]), (3, 0, &[3]), (4, 0, &[4])]);
        let reader = FactStoreReader::open(&path, 0, 0).expect("open");
        let cache: FactCache<u32> = FactCache::new(reader, NonZeroUsize::new(2).unwrap());
        let _a = cache.get_or_decode(1, sum_decoder).expect("ok");
        let _b = cache.get_or_decode(2, sum_decoder).expect("ok");
        // Inserting the third entry should evict the LRU (key 1).
        let _c = cache.get_or_decode(3, sum_decoder).expect("ok");
        assert_eq!(cache.resident(), 2);
        // Re-fetching 1 must produce a new Arc with the right value.
        let v1 = cache.get_or_decode(1, sum_decoder).expect("ok").expect("hit");
        assert_eq!(*v1, 1);
    }

    #[test]
    fn clear_drops_resident_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        write_test_store(&path, &[(1, 0, &[1])]);
        let reader = FactStoreReader::open(&path, 0, 0).expect("open");
        let cache: FactCache<u32> = FactCache::new(reader, NonZeroUsize::new(8).unwrap());
        let _ = cache.get_or_decode(1, sum_decoder).expect("ok");
        assert_eq!(cache.resident(), 1);
        cache.clear();
        assert_eq!(cache.resident(), 0);
    }

    #[test]
    fn parallel_get_or_decode_is_safe_and_consistent() {
        use std::sync::Arc as StdArc;
        use std::thread;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.bin");
        let entries: Vec<(u64, u64, &[u8])> = (0..32u64).map(|i| (i, i, b"x" as &[u8])).collect();
        write_test_store(&path, &entries);
        let reader = FactStoreReader::open(&path, 0, 0).expect("open");
        let cache: StdArc<FactCache<u32>> =
            StdArc::new(FactCache::new(reader, NonZeroUsize::new(16).unwrap()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = StdArc::clone(&cache);
            handles.push(thread::spawn(move || {
                for k in 0..32u64 {
                    let v = cache.get_or_decode(k, sum_decoder).expect("ok").expect("hit");
                    assert_eq!(*v, u32::from(b'x'));
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
    }
}
