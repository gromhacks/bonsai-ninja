use super::*;

#[test]
fn empty_entry_roundtrips() {
    let entry = FlowIdEntry::default();
    let bytes = encode(&entry);
    let decoded = decode(&bytes).expect("decode");
    assert!(decoded.id.is_empty());
}

#[test]
fn entry_with_id_roundtrips() {
    let entry = FlowIdEntry {
        id: "F:abc123".to_string(),
    };
    let bytes = encode(&entry);
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded.id, entry.id);
}

#[test]
fn corrupt_bytes_surface_typed_error() {
    let bytes = vec![0xFFu8; 16];
    match decode(&bytes) {
        Err(DecodeError::Wire(_)) => {}
        other => panic!("expected Bincode error, got {other:?}"),
    }
}
