//! Shared per-thread [`SpanMap`] cache.
//!
//! Several render and matching paths need repeated byte-offset to
//! line/column lookups for the same file snapshot. For immutable VFS
//! snapshots, keying by `(FileId, VFS version, snapshot
//! pointer, length)` keeps lookups stable across edits while avoiding an
//! `O(file_size)` content hash per emitted row or finding. The cache stores a
//! clone of the snapshot's `Arc<str>` with the map, so the pointer cannot be
//! freed and reused by a later workspace while the entry remains cached.

use crate::{FileId, SpanMap};
use std::{cell::RefCell, collections::HashMap, sync::Arc};

const MAX_THREAD_LOCAL_SPAN_MAPS: usize = 4096;

struct ArcSpanMapEntry {
    _text: Arc<str>,
    map: Arc<SpanMap>,
}

thread_local! {
    static ARC_SPAN_MAP_CACHE: RefCell<HashMap<(FileId, u64, usize, usize), ArcSpanMapEntry>> =
        RefCell::new(HashMap::new());
    static HASH_SPAN_MAP_CACHE: RefCell<HashMap<(FileId, u64, u64), Arc<SpanMap>>> =
        RefCell::new(HashMap::new());
}

/// Return a thread-local cached [`SpanMap`] for one immutable VFS snapshot.
/// First-call cost is `O(n)` over the file; subsequent calls within the
/// same thread are `O(1)`. The cache evicts at
/// `MAX_THREAD_LOCAL_SPAN_MAPS` entries (clear-and-rebuild).
#[must_use]
pub fn cached_span_map_arc(file: FileId, version: u64, text: &Arc<str>) -> Arc<SpanMap> {
    let key = (file, version, text.as_ref().as_ptr() as usize, text.len());
    ARC_SPAN_MAP_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(entry) = cache.get(&key) {
            return Arc::clone(&entry.map);
        }
        if cache.len() >= MAX_THREAD_LOCAL_SPAN_MAPS {
            cache.clear();
        }
        let map = Arc::new(SpanMap::new(text));
        cache.insert(
            key,
            ArcSpanMapEntry {
                _text: Arc::clone(text),
                map: Arc::clone(&map),
            },
        );
        map
    })
}

/// Return a thread-local cached [`SpanMap`] for borrowed text when no owning
/// snapshot handle is available. This path hashes content on each lookup to
/// stay correct across short-lived workspaces that reuse small [`FileId`]s.
#[must_use]
pub fn cached_span_map(file: FileId, version: u64, text: &str) -> Arc<SpanMap> {
    let key = (file, version, content_hash(text.as_bytes()));
    HASH_SPAN_MAP_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(map) = cache.get(&key).cloned() {
            return map;
        }
        if cache.len() >= MAX_THREAD_LOCAL_SPAN_MAPS {
            cache.clear();
        }
        let map = Arc::new(SpanMap::new(text));
        cache.insert(key, Arc::clone(&map));
        map
    })
}

fn content_hash(bytes: &[u8]) -> u64 {
    bonsai_hash::fnv1a_bytes64(bytes)
}

#[cfg(test)]
#[path = "span_cache_tests.rs"]
mod tests;
