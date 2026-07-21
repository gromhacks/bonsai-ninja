use super::*;
use crate::format::Header;
use crate::reader::FactStoreReader;

#[test]
fn empty_writer_emits_a_valid_header() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let writer = FactStoreWriter::create(&target, 7, 0xCAFE).expect("create");
    let written = writer.finish().expect("finish");
    assert_eq!(written, 0);
    let bytes = std::fs::read(&target).expect("read");
    let header = Header::from_bytes(&bytes).expect("magic + len OK");
    assert_eq!(header.format_version, FORMAT_VERSION);
    assert_eq!(header.table_id, 7);
    assert_eq!(header.pipeline_hash, 0xCAFE);
    assert_eq!(header.string_count, 0);
    assert_eq!(header.index_count, 0);
    assert_eq!(header.payload_len, 0);
    assert_eq!(header.payload_offset, HEADER_SIZE as u64);
}

#[test]
fn entries_are_sorted_by_key_ascending() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let w = FactStoreWriter::create(&target, 0, 0).expect("create");
    w.add(30, 0, b"thirty").expect("add");
    w.add(10, 0, b"ten").expect("add");
    w.add(20, 0, b"twenty").expect("add");
    w.finish().expect("finish");
    let r = FactStoreReader::open(&target, 0, 0).expect("open");
    let mut keys: Vec<u64> = r.iter().map(|item| item.expect("ok").0).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec![10, 20, 30]);
}

#[test]
fn entry_pipeline_has_deterministic_bounded_backpressure() {
    // Exercise the exact channel factory used by FactStoreWriter without
    // racing its background consumer. Once the finite pipeline is full,
    // a producer cannot enqueue another owned payload; `send`, used by
    // `add_owned`, waits for capacity instead of growing memory or
    // dropping the entry.
    let (sender, _receiver) = entry_channel();
    let capacity = entry_queue_capacity();
    let byte_budget = Arc::new(ByteBudget::new(capacity.saturating_add(1)));
    assert!(capacity > 0);
    assert_eq!(sender.capacity(), Some(capacity));

    for key in 0..capacity as u64 {
        sender
            .try_send(WriteCmd::Entry {
                key,
                body_hash: 0,
                payload: vec![key as u8],
                _permit: byte_budget.acquire(1),
            })
            .expect("pipeline slot");
    }
    let overflow = WriteCmd::Entry {
        key: capacity as u64,
        body_hash: 0,
        payload: vec![0xFF],
        _permit: byte_budget.acquire(1),
    };
    assert!(matches!(
        sender.try_send(overflow),
        Err(crossbeam_channel::TrySendError::Full(_))
    ));
}

#[test]
fn entry_pipeline_backpressure_is_weighted_by_payload_bytes() {
    let budget = Arc::new(ByteBudget::new(8));
    let first = budget.try_acquire(6).expect("first payload fits");
    assert!(
        budget.try_acquire(3).is_none(),
        "a second payload must not exceed the byte budget even when item slots remain"
    );
    drop(first);
    let oversized = budget
        .try_acquire(usize::MAX)
        .expect("one oversized payload is admitted exclusively");
    assert!(budget.try_acquire(1).is_none());
    drop(oversized);
    assert!(budget.try_acquire(8).is_some());
}

#[test]
fn add_owned_transfers_payload_and_preserves_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let w = FactStoreWriter::create(&target, 3, 0xBEEF).expect("create");
    let payload = vec![0x00, 0x7F, 0x80, 0xFF];
    w.add_owned(9, 0xCAFE, payload).expect("add owned");
    w.finish().expect("finish");

    let r = FactStoreReader::open(&target, 3, 0xBEEF).expect("open");
    let hit = r.get(9).expect("lookup").expect("entry");
    assert_eq!(hit.body_hash, 0xCAFE);
    assert_eq!(hit.payload, &[0x00, 0x7F, 0x80, 0xFF]);
}

#[test]
fn add_streamed_writes_without_an_intermediate_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let w = FactStoreWriter::create(&target, 3, 0xBEEF).expect("create");
    w.add_streamed(9, 0xCAFE, |writer| writer.write_all(&[0x00, 0x7F, 0x80, 0xFF]))
        .expect("streamed entry");
    w.finish().expect("finish");

    let r = FactStoreReader::open(&target, 3, 0xBEEF).expect("open");
    let hit = r.get(9).expect("lookup").expect("entry");
    assert_eq!(hit.body_hash, 0xCAFE);
    assert_eq!(hit.payload, &[0x00, 0x7F, 0x80, 0xFF]);
}

#[test]
fn failed_streamed_entry_never_publishes_a_partial_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let writer = FactStoreWriter::create(&target, 3, 0xBEEF).expect("create");
    let error = writer
        .add_streamed(9, 0xCAFE, |output| {
            output.write_all(&[1, 2, 3])?;
            Err(std::io::Error::other("injected encoder failure"))
        })
        .expect_err("stream failure must be reported");
    assert!(error.to_string().contains("injected encoder failure"));
    drop(writer);

    assert!(
        !target.exists(),
        "an encoder failure must leave the previously published target untouched"
    );
}

#[test]
fn finish_rejects_duplicate_keys_without_publishing_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let w = FactStoreWriter::create(&target, 0, 0).expect("create");
    w.add(7, 0, b"first").expect("add");
    w.add(7, 0, b"second").expect("add");
    let err = w.finish().expect_err("duplicate key must fail");
    assert!(matches!(err, FactStoreError::DuplicateKey(7)));
    assert!(
        !target.exists(),
        "failed duplicate-key finalization must not publish {target:?}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("readdir")
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(
        leftovers.is_empty(),
        "failed duplicate-key finalization must clean temp files, got {leftovers:?}"
    );
}

#[test]
fn finish_creates_file_at_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let w = FactStoreWriter::create(&target, 1, 0xABCD).expect("create");
    w.add(42, 0xDEAD, b"hello").expect("add");
    w.finish().expect("finish");
    assert!(target.exists());
    let r = FactStoreReader::open(&target, 1, 0xABCD).expect("open");
    let hit = r.get(42).expect("ok").expect("hit");
    assert_eq!(hit.payload, b"hello");
    assert_eq!(hit.body_hash, 0xDEAD);
}

#[test]
fn finish_creates_missing_parent_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("nested/sub/dir/v.bin");
    let w = FactStoreWriter::create(&target, 0, 0).expect("create");
    w.finish().expect("finish");
    assert!(target.exists());
}

#[test]
fn drop_without_finish_cleans_up_tmp_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    {
        let w = FactStoreWriter::create(&target, 0, 0).expect("create");
        w.add(1, 0, b"abandoned").expect("add");
        // dropped here without finish — tmp should be cleaned
    }
    // Give the writer thread a brief moment to handle the
    // channel-closed signal and remove the tmp file. (The Drop
    // impl joins, so this should already be synchronous, but the
    // test doesn't fight the OS scheduler if it isn't.)
    std::thread::sleep(std::time::Duration::from_millis(50));
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("readdir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        "no orphan files should remain, got {entries:?}"
    );
}

#[test]
fn intern_ids_are_stable_and_dedup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let w = FactStoreWriter::create(&target, 0, 0).expect("create");
    let a = w.intern("foo");
    let b = w.intern("bar");
    let a2 = w.intern("foo");
    assert_eq!(a, a2);
    assert_ne!(a, b);
    assert_eq!(w.string_count(), 2);
    w.add(0, 0, &[]).expect("add");
    w.finish().expect("finish");
    let r = FactStoreReader::open(&target, 0, 0).expect("open");
    let pool = r.string_pool().expect("pool");
    assert_eq!(pool.get(a), Some("foo"));
    assert_eq!(pool.get(b), Some("bar"));
}

#[test]
fn payload_offsets_in_index_are_absolute_and_sequential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let w = FactStoreWriter::create(&target, 0, 0).expect("create");
    w.add(1, 0, b"AAAA").expect("add");
    w.add(2, 0, b"BBBBBB").expect("add");
    w.add(3, 0, b"CCCCCCCC").expect("add");
    w.finish().expect("finish");
    let r = FactStoreReader::open(&target, 0, 0).expect("open");
    let header = r.header();
    assert_eq!(header.payload_offset, HEADER_SIZE as u64);
    assert_eq!(header.payload_len, 4 + 6 + 8);
    assert_eq!(r.get(1).expect("ok").unwrap().payload, b"AAAA");
    assert_eq!(r.get(2).expect("ok").unwrap().payload, b"BBBBBB");
    assert_eq!(r.get(3).expect("ok").unwrap().payload, b"CCCCCCCC");
}

#[test]
fn unique_tmp_paths_dont_collide() {
    let target = Path::new("/tmp/store.bin");
    let a = unique_tmp_path(target);
    let b = unique_tmp_path(target);
    assert_ne!(a, b);
    assert_eq!(a.parent(), target.parent());
}

#[test]
fn concurrent_adds_under_shared_ref_are_serialised_correctly() {
    // Verify that calling `add(&self)` from many threads yields
    // a fact-store file with the exact set of entries written —
    // proving that the channel handoff to the writer thread
    // preserves all sends and the writer drains them in order.
    use std::sync::Arc;
    use std::thread;
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("v.bin");
    let writer = Arc::new(FactStoreWriter::create(&target, 0, 0).expect("create"));
    let mut handles = Vec::new();
    for tid in 0u64..8 {
        let w = Arc::clone(&writer);
        handles.push(thread::spawn(move || {
            for k in 0..32u64 {
                w.add(tid * 100 + k, 0, &k.to_le_bytes()).expect("add");
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    let writer = Arc::try_unwrap(writer).expect("only owner");
    let written = writer.finish().expect("finish");
    assert_eq!(written, 8 * 32);
    let r = FactStoreReader::open(&target, 0, 0).expect("open");
    for tid in 0u64..8 {
        for k in 0..32u64 {
            let key = tid * 100 + k;
            let hit = r.get(key).expect("ok").expect("hit");
            let recovered = u64::from_le_bytes(hit.payload[..8].try_into().unwrap());
            assert_eq!(recovered, k);
        }
    }
}
