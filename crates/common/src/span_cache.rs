//! Shared per-thread [`SpanMap`] cache.
//!
//! Several render and matching paths need repeated byte-offset to
//! line/column lookups for the same file snapshot. Keying by
//! `(FileId, VFS version, content hash)` keeps lookups stable across
//! edits and across short-lived workspaces that reuse small `FileId`
//! values, while avoiding an `O(file_size)` line scan per emitted row
//! or finding.

use crate::{FileId, SpanMap};
use std::{cell::RefCell, collections::HashMap, sync::Arc};

const MAX_THREAD_LOCAL_SPAN_MAPS: usize = 4096;

thread_local! {
    static SPAN_MAP_CACHE: RefCell<HashMap<(FileId, u64, u64), Arc<SpanMap>>> =
        RefCell::new(HashMap::new());
}

/// Return a thread-local cached [`SpanMap`] for `(file, version, content)`.
/// First-call cost is `O(n)` over the file; subsequent calls within the
/// same thread are `O(1)`. The cache evicts at
/// `MAX_THREAD_LOCAL_SPAN_MAPS` entries (clear-and-rebuild).
#[must_use]
pub fn cached_span_map(file: FileId, version: u64, text: &str) -> Arc<SpanMap> {
    let key = (file, version, content_hash(text.as_bytes()));
    SPAN_MAP_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(map) = cache.get(&key).cloned() {
            return map;
        }
        if cache.len() >= MAX_THREAD_LOCAL_SPAN_MAPS {
            cache.clear();
        }
        let map = Arc::new(SpanMap::new(text));
        cache.insert(key, map.clone());
        map
    })
}

fn content_hash(bytes: &[u8]) -> u64 {
    bonsai_hash::fnv1a_bytes64(bytes)
}

#[cfg(test)]
#[path = "span_cache_tests.rs"]
mod tests;
