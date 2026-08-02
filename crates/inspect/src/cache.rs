//! Bounded FIFO cache used by every memo field on [`crate::ChainCache`].
//!
//! The shape is "an [`ahash::AHashMap`] with a backing
//! [`std::collections::VecDeque`] of insertion order, evicting the
//! oldest entry when an insert would exceed capacity."  Insertion order
//! is preserved on update-in-place so an entry doesn't get evicted
//! just because a writer touched it again.
//!
//! Bounding retained memo entries limits `inspect` / `export` memory:
//! Redis's worst-case `--from main --to system` query held ~250 MB in
//! the `reachable` map alone before eviction was introduced. Eviction
//! changes reuse only; a miss recomputes the same exact facts and never
//! narrows semantic work or returned results.

pub struct BoundedCache<K, V> {
    map: ahash::AHashMap<K, V>,
    order: std::collections::VecDeque<K>,
    cap: usize,
}

impl<K: std::hash::Hash + Eq + Clone, V> BoundedCache<K, V> {
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        // Initial allocation is bounded so a tiny cache doesn't pay
        // for a 65 K-slot hashmap up front, but is still big enough
        // that hot caches don't reallocate from 64 → ... → 65 K as
        // they fill on first use. 1024 is roughly two cache lines
        // worth of entries on the largest CACHE_CAP and amortises
        // the growth cost flat.
        let initial = cap.clamp(64, 1024);
        Self {
            map: ahash::AHashMap::with_capacity(initial),
            order: std::collections::VecDeque::with_capacity(initial),
            cap,
        }
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.map.get(key)
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.map.contains_key(key)
    }

    pub fn insert(&mut self, key: K, value: V) {
        if self.cap == 0 {
            return;
        }
        if self.map.contains_key(&key) {
            // Update-in-place: replace the value but keep the
            // existing slot in `order`. This is FIFO eviction, NOT
            // LRU — a touch on a long-resident entry does not move
            // it to the back of the queue.
            self.map.insert(key, value);
            return;
        }
        if self.map.len() >= self.cap {
            // Evict the oldest entry. `pop_front` is O(1).
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap
    }
}

// ---------------------------------------------------------------------------
// Per-cache size caps
//
// Each capacity is generous enough that a typical run never evicts; it
// bounds retained memo state, not analysis work or result cardinality.
// The current caps are intentionally higher than the original Redis-
// scale baseline because flow filtering now composes several token
// caches and benefits from keeping hot FuncId/FileId facts resident.
// ---------------------------------------------------------------------------
pub const REACHABLE_CACHE_CAP: usize = 65536;
pub const CHAINS_CACHE_CAP: usize = 16384;
pub const DOWNSTREAM_CACHE_CAP: usize = 16384;
pub const CALLEES_CACHE_CAP: usize = 32768;
pub const ENCLOSING_CACHE_CAP: usize = 65536;
