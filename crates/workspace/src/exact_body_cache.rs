//! Memory-aware hot cache for exact Tree-sitter-lowered file bodies.
//!
//! Workspace-wide compiler phases deliberately stream bodies so resident
//! memory does not grow with project size. Query and attribution phases often
//! revisit the same few files, though; recompiling those bodies for every
//! declaration lookup turns exact analysis into repeated frontend work. This
//! cache retains only a memory-scheduled hot set. Eviction changes
//! recomputation, never compiler facts or analysis scope.

use ahash::AHashMap;
use bonsai_common::FileId;
use bonsai_lang_api::DeclIndex;
use lru::LruCache;
use parking_lot::Mutex;
use std::sync::{Arc, OnceLock};

type ExactBodyKey = (FileId, u64);
type ExactBodyCell = Arc<OnceLock<Option<Arc<DeclIndex>>>>;

pub(crate) struct ExactBodyCache {
    budget_bytes: u64,
    state: Mutex<ExactBodyCacheState>,
}

struct ExactBodyEntry {
    cell: ExactBodyCell,
    estimated_bytes: u64,
}

struct ExactBodyFlight {
    cell: ExactBodyCell,
    retention_generation: u64,
}

struct ExactBodyCacheState {
    entries: LruCache<ExactBodyKey, ExactBodyEntry>,
    in_flight: AHashMap<ExactBodyKey, ExactBodyFlight>,
    estimated_bytes: u64,
    retention_generation: u64,
}

impl Default for ExactBodyCacheState {
    fn default() -> Self {
        Self {
            entries: LruCache::unbounded(),
            in_flight: AHashMap::new(),
            estimated_bytes: 0,
            retention_generation: 0,
        }
    }
}

impl Default for ExactBodyCache {
    fn default() -> Self {
        const DEFAULT_BUDGET_BYTES: u64 = 128 * 1024 * 1024;
        const MAX_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
        let budget_bytes = bonsai_common::effective_memory_limit_bytes()
            .map(|limit| (limit / 32).clamp(1, MAX_BUDGET_BYTES))
            .unwrap_or(DEFAULT_BUDGET_BYTES);
        Self::with_budget(budget_bytes)
    }
}

impl ExactBodyCache {
    fn with_budget(budget_bytes: u64) -> Self {
        Self {
            budget_bytes: budget_bytes.max(1),
            state: Mutex::new(ExactBodyCacheState::default()),
        }
    }

    pub(crate) fn get_or_insert_with(
        &self,
        key: ExactBodyKey,
        estimated_bytes: u64,
        build: impl FnOnce() -> Option<Arc<DeclIndex>>,
    ) -> Option<Arc<DeclIndex>> {
        let (cell, flight_generation) = {
            let mut state = self.state.lock();
            if let Some(entry) = state.entries.get(&key) {
                (Arc::clone(&entry.cell), None)
            } else if let Some(flight) = state.in_flight.get(&key) {
                (Arc::clone(&flight.cell), Some(flight.retention_generation))
            } else {
                let cell = Arc::new(OnceLock::new());
                let retention_generation = state.retention_generation;
                state.in_flight.insert(
                    key,
                    ExactBodyFlight {
                        cell: Arc::clone(&cell),
                        retention_generation,
                    },
                );
                (cell, Some(retention_generation))
            }
        };
        let result = cell.get_or_init(build).clone();

        let mut state = self.state.lock();
        let owns_in_flight_slot = state
            .in_flight
            .get(&key)
            .is_some_and(|candidate| Arc::ptr_eq(&candidate.cell, &cell));
        if owns_in_flight_slot {
            state.in_flight.remove(&key);
            // A missing body can reflect a transient parse/compiler-object
            // failure. Share that result with current waiters, but do not turn
            // it into a persistent negative cache for an unchanged file.
            // Likewise, a phase-boundary `clear` lets current waiters finish
            // on this cell but invalidates its retention generation.
            if result.is_some()
                && estimated_bytes <= self.budget_bytes
                && flight_generation == Some(state.retention_generation)
            {
                state.estimated_bytes = state.estimated_bytes.saturating_add(estimated_bytes);
                if let Some((_replaced_key, replaced)) = state.entries.push(
                    key,
                    ExactBodyEntry {
                        cell,
                        estimated_bytes,
                    },
                ) {
                    state.estimated_bytes = state.estimated_bytes.saturating_sub(replaced.estimated_bytes);
                }
                while state.estimated_bytes > self.budget_bytes {
                    let Some((_evicted_key, evicted)) = state.entries.pop_lru() else {
                        break;
                    };
                    state.estimated_bytes = state.estimated_bytes.saturating_sub(evicted.estimated_bytes);
                }
            }
        }
        result
    }

    pub(crate) fn clear(&self) {
        let mut state = self.state.lock();
        state.entries.clear();
        state.estimated_bytes = 0;
        state.retention_generation = state
            .retention_generation
            .checked_add(1)
            .expect("exact-body cache retention generation exhausted");
    }
}

pub(crate) fn estimated_exact_body_bytes(source_bytes: usize) -> u64 {
    const PER_FILE_BYTES: u64 = 256 * 1024;
    const SOURCE_AMPLIFICATION: u64 = 16;
    PER_FILE_BYTES.saturating_add(
        u64::try_from(source_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(SOURCE_AMPLIFICATION),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Barrier,
        },
        thread,
        time::Duration,
    };

    #[test]
    fn same_snapshot_is_built_once_and_lru_eviction_only_recomputes() {
        let cache = ExactBodyCache::with_budget(1);
        let builds = AtomicUsize::new(0);
        let first = cache
            .get_or_insert_with((FileId::new(0), 1), 1, || {
                builds.fetch_add(1, Ordering::Relaxed);
                Some(Arc::new(DeclIndex::default()))
            })
            .expect("first body");
        let reused = cache
            .get_or_insert_with((FileId::new(0), 1), 1, || {
                builds.fetch_add(1, Ordering::Relaxed);
                Some(Arc::new(DeclIndex::default()))
            })
            .expect("reused body");
        assert!(Arc::ptr_eq(&first, &reused));
        assert_eq!(builds.load(Ordering::Relaxed), 1);

        let _ = cache.get_or_insert_with((FileId::new(1), 1), 1, || Some(Arc::new(DeclIndex::default())));
        let rebuilt = cache
            .get_or_insert_with((FileId::new(0), 1), 1, || {
                builds.fetch_add(1, Ordering::Relaxed);
                Some(Arc::new(DeclIndex::default()))
            })
            .expect("rebuilt body");
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn body_larger_than_budget_is_returned_but_not_retained() {
        let cache = ExactBodyCache::with_budget(1);
        let builds = AtomicUsize::new(0);
        for _ in 0..2 {
            let body = cache
                .get_or_insert_with((FileId::new(0), 1), 2, || {
                    builds.fetch_add(1, Ordering::Relaxed);
                    Some(Arc::new(DeclIndex::default()))
                })
                .expect("exact body is still produced");
            drop(body);
        }
        assert_eq!(
            builds.load(Ordering::Relaxed),
            2,
            "an oversize body must be recomputed rather than retained beyond the cache budget"
        );
    }

    #[test]
    fn missing_body_is_shared_in_flight_but_retried_later() {
        let cache = ExactBodyCache::with_budget(1);
        let builds = AtomicUsize::new(0);
        assert!(cache
            .get_or_insert_with((FileId::new(0), 1), 1, || {
                builds.fetch_add(1, Ordering::Relaxed);
                None
            })
            .is_none());
        assert!(cache
            .get_or_insert_with((FileId::new(0), 1), 1, || {
                builds.fetch_add(1, Ordering::Relaxed);
                Some(Arc::new(DeclIndex::default()))
            })
            .is_some());
        assert_eq!(
            builds.load(Ordering::Relaxed),
            2,
            "a transient missing body must not poison the exact-body cache"
        );
    }

    #[test]
    fn clearing_the_hot_set_only_forces_exact_recomputation() {
        let cache = ExactBodyCache::with_budget(1);
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::Relaxed);
            Some(Arc::new(DeclIndex::default()))
        };
        let first = cache
            .get_or_insert_with((FileId::new(0), 1), 1, build)
            .expect("first body");
        cache.clear();
        let rebuilt = cache
            .get_or_insert_with((FileId::new(0), 1), 1, build)
            .expect("rebuilt body");

        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn concurrent_oversize_requests_share_in_flight_lowering() {
        const THREADS: usize = 8;
        let cache = Arc::new(ExactBodyCache::with_budget(1));
        let builds = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(THREADS));
        let handles = (0..THREADS)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let builds = Arc::clone(&builds);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    cache
                        .get_or_insert_with((FileId::new(0), 1), 2, || {
                            builds.fetch_add(1, Ordering::Relaxed);
                            thread::sleep(Duration::from_millis(50));
                            Some(Arc::new(DeclIndex::default()))
                        })
                        .expect("exact body")
                })
            })
            .collect::<Vec<_>>();

        let bodies = handles
            .into_iter()
            .map(|handle| handle.join().expect("request thread"))
            .collect::<Vec<_>>();
        assert!(
            bodies.iter().skip(1).all(|body| Arc::ptr_eq(&bodies[0], body)),
            "overlapping requests must observe one exact body"
        );
        assert_eq!(builds.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn clearing_retained_bodies_preserves_an_active_single_flight() {
        use std::sync::mpsc;

        let cache = Arc::new(ExactBodyCache::with_budget(1));
        let builds = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let builder_cache = Arc::clone(&cache);
        let builder_builds = Arc::clone(&builds);
        let builder = thread::spawn(move || {
            builder_cache
                .get_or_insert_with((FileId::new(0), 1), 1, || {
                    builder_builds.fetch_add(1, Ordering::Relaxed);
                    started_tx.send(()).expect("announce lowering");
                    release_rx.recv().expect("release lowering");
                    Some(Arc::new(DeclIndex::default()))
                })
                .expect("built body")
        });

        started_rx.recv().expect("lowering started");
        cache.clear();
        let active_cell = {
            let state = cache.state.lock();
            Arc::clone(
                &state
                    .in_flight
                    .get(&(FileId::new(0), 1))
                    .expect("active exact-body flight")
                    .cell,
            )
        };

        let waiter_cache = Arc::clone(&cache);
        let waiter_builds = Arc::clone(&builds);
        let waiter = thread::spawn(move || {
            waiter_cache
                .get_or_insert_with((FileId::new(0), 1), 1, || {
                    waiter_builds.fetch_add(1, Ordering::Relaxed);
                    Some(Arc::new(DeclIndex::default()))
                })
                .expect("shared body")
        });

        let wait_started = std::time::Instant::now();
        while Arc::strong_count(&active_cell) < 4 {
            assert!(
                wait_started.elapsed() < Duration::from_secs(5),
                "waiter did not join the active exact-body flight"
            );
            thread::yield_now();
        }
        release_tx.send(()).expect("finish lowering");
        let built = builder.join().expect("builder thread");
        let shared = waiter.join().expect("waiter thread");
        assert!(
            Arc::ptr_eq(&built, &shared),
            "cache release must not replace an exact lowering already in flight"
        );
        assert_eq!(builds.load(Ordering::Relaxed), 1);

        let rebuilt = cache
            .get_or_insert_with((FileId::new(0), 1), 1, || {
                builds.fetch_add(1, Ordering::Relaxed);
                Some(Arc::new(DeclIndex::default()))
            })
            .expect("body rebuilt after cache release");
        assert!(
            !Arc::ptr_eq(&built, &rebuilt),
            "an in-flight body completed after cache release must not repopulate the hot set"
        );
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }
}
