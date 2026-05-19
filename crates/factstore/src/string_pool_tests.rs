use super::*;

#[test]
fn empty_builder_emits_one_sentinel() {
    let pool = StringPoolBuilder::new();
    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());
    assert_eq!(pool.bytes_len(), 0);
    // Empty pool: zero strings, one sentinel = 4 bytes.
    let offsets = pool.offsets_bytes();
    assert_eq!(offsets.len(), 4);
    assert_eq!(u32::from_le_bytes(offsets.try_into().unwrap()), 0);
}

#[test]
fn intern_dedupes_repeated_strings() {
    let mut pool = StringPoolBuilder::new();
    let a1 = pool.intern("hello");
    let a2 = pool.intern("hello");
    let b = pool.intern("world");
    assert_eq!(a1, a2, "second intern must return the same id");
    assert_ne!(a1, b);
    assert_eq!(pool.len(), 2);
    assert_eq!(pool.bytes_len(), "hello".len() + "world".len());
}

#[test]
fn builder_get_roundtrips_inserted_strings() {
    let mut pool = StringPoolBuilder::new();
    let a = pool.intern("alpha");
    let b = pool.intern("beta");
    let c = pool.intern("");
    assert_eq!(pool.get(a), Some("alpha"));
    assert_eq!(pool.get(b), Some("beta"));
    assert_eq!(pool.get(c), Some(""));
    assert_eq!(pool.get(99), None);
}

#[test]
fn view_roundtrips_through_bytes() {
    let mut pool = StringPoolBuilder::new();
    let a = pool.intern("alpha");
    let b = pool.intern("beta");
    let c = pool.intern("");
    let bytes = pool.bytes().to_vec();
    let offsets = pool.offsets_bytes();
    let view = StringPoolView::new(&bytes, &offsets, 3).expect("valid pool");
    assert_eq!(view.len(), 3);
    assert_eq!(view.get(a), Some("alpha"));
    assert_eq!(view.get(b), Some("beta"));
    assert_eq!(view.get(c), Some(""));
    assert_eq!(view.get(3), None);
}

#[test]
fn view_rejects_offsets_section_length_mismatch() {
    let bytes = b"abc".to_vec();
    // Three strings need 4 offsets = 16 bytes; supply 12.
    let offsets = vec![0u8; 12];
    let err = StringPoolView::new(&bytes, &offsets, 3).expect_err("must reject");
    match err {
        FactStoreError::BadStringPool(_) => {}
        other => panic!("expected BadStringPool, got {other:?}"),
    }
}

#[test]
fn view_rejects_offset_past_bytes_end() {
    // count = 1, offsets section = [0, 99] (sentinel beyond bytes).
    let bytes = b"abc".to_vec();
    let mut offsets = Vec::new();
    offsets.extend_from_slice(&0u32.to_le_bytes());
    offsets.extend_from_slice(&99u32.to_le_bytes());
    let err = StringPoolView::new(&bytes, &offsets, 1).expect_err("must reject");
    match err {
        FactStoreError::BadStringPool(_) => {}
        other => panic!("expected BadStringPool, got {other:?}"),
    }
}

#[test]
fn view_rejects_decreasing_offsets() {
    let bytes = b"abc".to_vec();
    let mut offsets = Vec::new();
    offsets.extend_from_slice(&2u32.to_le_bytes());
    offsets.extend_from_slice(&1u32.to_le_bytes());
    offsets.extend_from_slice(&3u32.to_le_bytes());
    let err = StringPoolView::new(&bytes, &offsets, 2).expect_err("must reject");
    match err {
        FactStoreError::BadStringPool(_) => {}
        other => panic!("expected BadStringPool, got {other:?}"),
    }
}

#[test]
fn view_rejects_sentinel_mismatch() {
    let bytes = b"abc".to_vec();
    // count = 1, sentinel = 2 (should be 3 = bytes.len()).
    let mut offsets = Vec::new();
    offsets.extend_from_slice(&0u32.to_le_bytes());
    offsets.extend_from_slice(&2u32.to_le_bytes());
    let err = StringPoolView::new(&bytes, &offsets, 1).expect_err("must reject");
    match err {
        FactStoreError::BadStringPool(_) => {}
        other => panic!("expected BadStringPool, got {other:?}"),
    }
}

#[test]
fn intern_handles_empty_and_unicode() {
    let mut pool = StringPoolBuilder::new();
    let empty = pool.intern("");
    let snowman = pool.intern("☃");
    let combined = pool.intern("a☃b");
    assert_eq!(pool.get(empty), Some(""));
    assert_eq!(pool.get(snowman), Some("☃"));
    assert_eq!(pool.get(combined), Some("a☃b"));
    let bytes = pool.bytes().to_vec();
    let offsets = pool.offsets_bytes();
    let view = StringPoolView::new(&bytes, &offsets, 3).expect("valid");
    assert_eq!(view.get(empty), Some(""));
    assert_eq!(view.get(snowman), Some("☃"));
    assert_eq!(view.get(combined), Some("a☃b"));
}

#[test]
fn get_or_err_distinguishes_out_of_range() {
    let mut pool = StringPoolBuilder::new();
    let _ = pool.intern("only");
    let bytes = pool.bytes().to_vec();
    let offsets = pool.offsets_bytes();
    let view = StringPoolView::new(&bytes, &offsets, 1).expect("valid");
    match view.get_or_err(99) {
        Err(FactStoreError::BadStringId { id, count }) => {
            assert_eq!(id, 99);
            assert_eq!(count, 1);
        }
        other => panic!("expected BadStringId, got {other:?}"),
    }
}
