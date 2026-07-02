use super::*;
use crate::format::INDEX_ENTRY_SIZE;
use crate::writer::FactStoreWriter;
use std::io::{Seek, SeekFrom, Write};

fn write_test_store(path: &Path, table: u32, hash: u64, entries: &[(u64, u64, &[u8])]) {
    let w = FactStoreWriter::create(path, table, hash).expect("create");
    for &(key, body_hash, payload) in entries {
        w.add(key, body_hash, payload).expect("add");
    }
    w.finish().expect("finish");
}

#[test]
fn open_roundtrips_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    write_test_store(&path, 1, 0xCAFE, &[]);
    let r = FactStoreReader::open(&path, 1, 0xCAFE).expect("open");
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[test]
fn get_returns_payload_for_known_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    write_test_store(
        &path,
        2,
        0xDEAD,
        &[(10, 100, b"ten"), (20, 200, b"twenty"), (30, 300, b"thirty")],
    );
    let r = FactStoreReader::open(&path, 2, 0xDEAD).expect("open");
    let twenty = r.get(20).expect("ok").expect("hit");
    assert_eq!(twenty.payload, b"twenty");
    assert_eq!(twenty.body_hash, 200);
    let ten = r.get(10).expect("ok").expect("hit");
    assert_eq!(ten.payload, b"ten");
    let thirty = r.get(30).expect("ok").expect("hit");
    assert_eq!(thirty.payload, b"thirty");
}

#[test]
fn get_returns_none_for_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    write_test_store(&path, 0, 0, &[(1, 0, b"a"), (3, 0, b"c"), (5, 0, b"e")]);
    let r = FactStoreReader::open(&path, 0, 0).expect("open");
    assert!(r.get(0).expect("ok").is_none());
    assert!(r.get(2).expect("ok").is_none());
    assert!(r.get(4).expect("ok").is_none());
    assert!(r.get(6).expect("ok").is_none());
    assert_eq!(r.get(3).expect("ok").expect("hit").payload, b"c");
}

#[test]
fn open_rejects_wrong_table_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    write_test_store(&path, 1, 0xCAFE, &[]);
    let err = FactStoreReader::open(&path, 99, 0xCAFE).expect_err("must reject");
    match err {
        FactStoreError::WrongTable { file, expected } => {
            assert_eq!(file, 1);
            assert_eq!(expected, 99);
        }
        other => panic!("expected WrongTable, got {other:?}"),
    }
}

#[test]
fn open_rejects_wrong_pipeline_hash() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    write_test_store(&path, 1, 0xCAFE, &[]);
    let err = FactStoreReader::open(&path, 1, 0xBEEF).expect_err("must reject");
    match err {
        FactStoreError::PipelineMismatch { file, expected } => {
            assert_eq!(file, 0xCAFE);
            assert_eq!(expected, 0xBEEF);
        }
        other => panic!("expected PipelineMismatch, got {other:?}"),
    }
}

#[test]
fn open_rejects_bad_magic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    std::fs::write(&path, vec![0u8; HEADER_SIZE]).expect("write zeros");
    let err = FactStoreReader::open(&path, 0, 0).expect_err("must reject");
    assert!(matches!(err, FactStoreError::BadMagic));
}

#[test]
fn open_rejects_truncated_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    std::fs::write(&path, vec![0u8; HEADER_SIZE - 1]).expect("write");
    let err = FactStoreReader::open(&path, 0, 0).expect_err("must reject");
    assert!(matches!(err, FactStoreError::Truncated { .. }));
}

#[test]
fn iter_visits_entries_in_key_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    write_test_store(&path, 0, 0, &[(30, 0, b"c"), (10, 0, b"a"), (20, 0, b"b")]);
    let r = FactStoreReader::open(&path, 0, 0).expect("open");
    let collected: Vec<(u64, Vec<u8>)> = r
        .iter()
        .map(|item| {
            let (k, hit) = item.expect("ok");
            (k, hit.payload)
        })
        .collect();
    assert_eq!(
        collected,
        vec![(10, b"a".to_vec()), (20, b"b".to_vec()), (30, b"c".to_vec()),]
    );
}

#[test]
fn open_rejects_duplicate_index_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    write_test_store(&path, 0, 0, &[(1, 0, b"one"), (2, 0, b"two")]);

    let r = FactStoreReader::open(&path, 0, 0).expect("open before mutation");
    let second_index_key = r.header().index_offset + INDEX_ENTRY_SIZE as u64;
    drop(r);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open for mutation");
    file.seek(SeekFrom::Start(second_index_key))
        .expect("seek index key");
    file.write_all(&1u64.to_le_bytes())
        .expect("overwrite duplicate key");
    file.sync_all().expect("sync mutation");

    let err = FactStoreReader::open(&path, 0, 0).expect_err("duplicate key must reject");
    assert!(matches!(err, FactStoreError::DuplicateKey(1)));
}

#[test]
fn string_pool_view_is_accessible_through_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    let w = FactStoreWriter::create(&path, 0, 0).expect("create");
    let a = w.intern("hello");
    let b = w.intern("world");
    w.add(1, 0, &[]).expect("add");
    w.finish().expect("finish");
    let r = FactStoreReader::open(&path, 0, 0).expect("open");
    let pool = r.string_pool().expect("pool");
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.get(a), Some("hello"));
    assert_eq!(pool.get(b), Some("world"));
}

#[test]
fn binary_search_locates_first_and_last() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    let entries: Vec<(u64, u64, &[u8])> = (0..1000u64).map(|i| (i * 2, i, b"x" as &[u8])).collect();
    write_test_store(&path, 0, 0, &entries);
    let r = FactStoreReader::open(&path, 0, 0).expect("open");
    assert_eq!(r.get(0).expect("ok").unwrap().body_hash, 0);
    assert_eq!(r.get(1998).expect("ok").unwrap().body_hash, 999);
    assert!(r.get(1).expect("ok").is_none());
    assert!(r.get(1999).expect("ok").is_none());
    assert!(r.get(2000).expect("ok").is_none());
}

#[test]
fn parallel_reads_are_safe() {
    // Verify Send + Sync — many threads can hit `get` against
    // the same reader. The positioned-read API does not share a
    // file cursor, so this should be deadlock- and race-free.
    use std::sync::Arc;
    use std::thread;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.bin");
    let entries: Vec<(u64, u64, &[u8])> = (0..256u64).map(|i| (i, i, b"payload" as &[u8])).collect();
    write_test_store(&path, 0, 0, &entries);
    let r = Arc::new(FactStoreReader::open(&path, 0, 0).expect("open"));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let r = Arc::clone(&r);
        handles.push(thread::spawn(move || {
            for k in 0..256u64 {
                let hit = r.get(k).expect("ok").expect("hit");
                assert_eq!(hit.body_hash, k);
                assert_eq!(hit.payload, b"payload");
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
}
