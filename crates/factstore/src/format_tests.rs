use super::*;

#[test]
fn header_roundtrips_byte_form() {
    let h = Header {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        table_id: 7,
        pipeline_hash: 0xDEAD_BEEF_CAFE_BABE,
        string_pool_offset: HEADER_SIZE as u64,
        string_pool_bytes_len: 1024,
        string_count: 42,
        index_offset: 4096,
        index_count: 100,
        payload_offset: 8192,
        payload_len: 65_536,
        reserved: [0; 8],
    };
    let bytes = h.to_bytes();
    assert_eq!(bytes.len(), HEADER_SIZE);
    let decoded = Header::from_bytes(&bytes).expect("magic + len OK");
    assert_eq!(decoded, h);
}

#[test]
fn header_rejects_wrong_magic() {
    let mut bytes = [0u8; HEADER_SIZE];
    bytes[0..8].copy_from_slice(b"NOTABNSI");
    assert!(Header::from_bytes(&bytes).is_none());
}

#[test]
fn header_rejects_short_input() {
    let bytes = [0u8; HEADER_SIZE - 1];
    assert!(Header::from_bytes(&bytes).is_none());
}

#[test]
fn index_entry_roundtrips_byte_form() {
    let entry = IndexEntry {
        key: 0x0123_4567_89AB_CDEF,
        body_hash: 0xFEDC_BA98_7654_3210,
        payload_offset: 1_000_000,
        payload_len: 4096,
        reserved: 0,
    };
    let bytes = entry.to_bytes();
    assert_eq!(bytes.len(), INDEX_ENTRY_SIZE);
    let decoded = IndexEntry::from_bytes(&bytes).expect("len OK");
    assert_eq!(decoded, entry);
}

#[test]
fn index_entry_rejects_short_input() {
    let bytes = [0u8; INDEX_ENTRY_SIZE - 1];
    assert!(IndexEntry::from_bytes(&bytes).is_none());
}

#[test]
fn header_size_is_exactly_96() {
    // The header holds `mmap` reinterpretation invariants — if the
    // size drifts, downstream offset math breaks silently. Pin it.
    assert_eq!(HEADER_SIZE, 96);
}

#[test]
fn index_entry_size_is_exactly_32() {
    // Same rationale as the header: binary-search math and mmap
    // bounds checking depend on this constant.
    assert_eq!(INDEX_ENTRY_SIZE, 32);
}
