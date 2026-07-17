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
/// concrete without coupling the storage layer to a payload codec.
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
    let cache: StdArc<FactCache<u32>> = StdArc::new(FactCache::new(reader, NonZeroUsize::new(16).unwrap()));
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
