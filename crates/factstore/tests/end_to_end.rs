//! Integration tests covering the full write → reopen → query path.
//!
//! Unit tests in each module exercise individual primitives. These
//! tests stitch the public API together as a downstream consumer
//! would.

use bonsai_factstore::{
    CacheGet, FactCache, FactStoreError, FactStoreReader, FactStoreWriter, StringPoolView,
};
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Toy "graph" payload that uses interned string ids. Mirrors the
/// real-world shape: per-function facts referencing names from the
/// workspace-wide pool. Ids are stable for one fact-store file.
#[derive(Debug, PartialEq, Eq)]
struct TinyGraph {
    name_id: u32,
    edges: Vec<(u32, u32)>, // (src_name_id, dst_name_id)
}

impl TinyGraph {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.edges.len() * 8);
        buf.extend_from_slice(&self.name_id.to_le_bytes());
        buf.extend_from_slice(&u32::try_from(self.edges.len()).unwrap().to_le_bytes());
        for (a, b) in &self.edges {
            buf.extend_from_slice(&a.to_le_bytes());
            buf.extend_from_slice(&b.to_le_bytes());
        }
        buf
    }

    fn decode(bytes: &[u8]) -> Self {
        let name_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let edge_count = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let mut edges = Vec::with_capacity(edge_count);
        for i in 0..edge_count {
            let off = 8 + i * 8;
            let a = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
            let b = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
            edges.push((a, b));
        }
        Self { name_id, edges }
    }
}

#[test]
fn write_reopen_query_with_interned_strings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.bin");

    let mut writer = FactStoreWriter::create(&path, /* table */ 1, /* pipeline */ 0xCAFE).expect("create");
    let validate = writer.intern("validate_input");
    let helper = writer.intern("helper");
    let sink = writer.intern("sink");
    let entry = writer.intern("entry");

    let g_entry = TinyGraph {
        name_id: entry,
        edges: vec![(entry, validate), (validate, helper), (helper, sink)],
    };
    let g_helper = TinyGraph {
        name_id: helper,
        edges: vec![(helper, sink)],
    };

    writer.add(/* func 1 */ 1, /* body_hash */ 0xAA, &g_entry.encode()).expect("add");
    writer.add(/* func 2 */ 2, /* body_hash */ 0xBB, &g_helper.encode()).expect("add");
    writer.finish().expect("finish");

    // Reopen — verify section-bounds + sort invariants survived.
    let reader = FactStoreReader::open(&path, 1, 0xCAFE).expect("open");
    assert_eq!(reader.len(), 2);

    // String pool should round-trip every interned name.
    let pool: StringPoolView<'_> = reader.string_pool().expect("pool");
    assert_eq!(pool.get(entry), Some("entry"));
    assert_eq!(pool.get(validate), Some("validate_input"));
    assert_eq!(pool.get(helper), Some("helper"));
    assert_eq!(pool.get(sink), Some("sink"));

    // Per-key lookup decodes the right graph.
    let hit_entry = reader.get(1).expect("ok").expect("found");
    assert_eq!(hit_entry.body_hash, 0xAA);
    let decoded_entry = TinyGraph::decode(&hit_entry.payload);
    assert_eq!(decoded_entry, g_entry);

    let hit_helper = reader.get(2).expect("ok").expect("found");
    assert_eq!(hit_helper.body_hash, 0xBB);
    let decoded_helper = TinyGraph::decode(&hit_helper.payload);
    assert_eq!(decoded_helper, g_helper);
}

#[test]
fn cache_layer_handles_repeated_lookups_efficiently() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.bin");

    let mut writer = FactStoreWriter::create(&path, 0, 0).expect("create");
    for i in 0..100u64 {
        let g = TinyGraph {
            name_id: 0,
            edges: vec![(i as u32, (i + 1) as u32)],
        };
        writer.add(i, i, &g.encode()).expect("add");
    }
    writer.finish().expect("finish");

    let reader = FactStoreReader::open(&path, 0, 0).expect("open");
    let cache: FactCache<TinyGraph> =
        FactCache::new(reader, NonZeroUsize::new(16).unwrap());

    // First lookup of each key: miss → decode → insert. Capture the
    // resulting Arcs so we can verify a second lookup hits the cache.
    let mut first: Vec<Arc<TinyGraph>> = Vec::new();
    for k in 0..16u64 {
        let v = cache
            .get_or_decode(k, |bytes| Arc::new(TinyGraph::decode(bytes)))
            .expect("ok")
            .expect("hit");
        first.push(v);
    }
    // The cache cap is 16; all 16 should still be resident.
    assert_eq!(cache.resident(), 16);

    // Second pass: every probe should hit and return the same Arc.
    for (k, original) in (0..16u64).zip(first.iter()) {
        match cache.get(k).expect("ok") {
            CacheGet::Hit(v) => assert!(Arc::ptr_eq(&v, original)),
            other => panic!("expected hit at {k}, got {other:?}"),
        }
    }

    // Pulling in a 17th entry should evict one. The 17th lookup is a
    // miss → decode → insert; LRU drops key 0.
    let _ = cache
        .get_or_decode(16, |bytes| Arc::new(TinyGraph::decode(bytes)))
        .expect("ok")
        .expect("hit");
    assert_eq!(cache.resident(), 16);
    match cache.get(0).expect("ok") {
        CacheGet::Miss(_) => {}
        other => panic!("expected miss after eviction, got {other:?}"),
    }
}

#[test]
fn pipeline_hash_mismatch_is_a_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.bin");

    let mut w = FactStoreWriter::create(&path, /* table */ 1, /* pipeline */ 0xAAAA).expect("create");
    w.add(1, 0, b"payload").expect("add");
    w.finish().expect("finish");

    let err = FactStoreReader::open(&path, 1, 0xBBBB).expect_err("must mismatch");
    match err {
        FactStoreError::PipelineMismatch { file, expected } => {
            assert_eq!(file, 0xAAAA);
            assert_eq!(expected, 0xBBBB);
        }
        other => panic!("expected PipelineMismatch, got {other:?}"),
    }
}

#[test]
fn iter_streams_every_entry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.bin");

    let mut w = FactStoreWriter::create(&path, 0, 0).expect("create");
    for i in 0..50u64 {
        w.add(i, i * 11, &i.to_le_bytes()).expect("add");
    }
    w.finish().expect("finish");

    let reader = FactStoreReader::open(&path, 0, 0).expect("open");
    let mut keys: Vec<u64> = Vec::new();
    for item in reader.iter() {
        let (k, hit) = item.expect("ok");
        assert_eq!(hit.body_hash, k * 11);
        keys.push(k);
    }
    assert_eq!(keys, (0..50u64).collect::<Vec<_>>());
}

#[test]
fn version_mismatch_yields_typed_error_on_open_relaxed() {
    use bonsai_factstore::{FORMAT_VERSION, HEADER_SIZE, MAGIC};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vmis.bin");

    // Write a header with magic + a bogus version. We don't fill in
    // valid section offsets; `open_relaxed` must reject on version
    // before it gets to bounds checks.
    let mut bytes = vec![0u8; HEADER_SIZE];
    bytes[0..8].copy_from_slice(&MAGIC);
    bytes[8..12].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
    std::fs::write(&path, &bytes).unwrap();
    let err = FactStoreReader::open_relaxed(&path).expect_err("must reject");
    match err {
        FactStoreError::VersionMismatch { file, expected } => {
            assert_eq!(file, FORMAT_VERSION + 1);
            assert_eq!(expected, FORMAT_VERSION);
        }
        other => panic!("expected VersionMismatch, got {other:?}"),
    }
}
