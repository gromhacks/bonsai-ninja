use super::*;

#[test]
fn empty_entry_roundtrips() {
    let entry = FlowIdEntry::default();
    let bytes = encode(&entry);
    let decoded = decode(&bytes).expect("decode");
    assert!(decoded.labels.is_empty());
    assert!(!decoded.truncated);
}

#[test]
fn entry_with_labels_roundtrips() {
    let entry = FlowIdEntry {
        labels: vec!["F:abc123".to_string(), "F:def456".to_string()],
        truncated: true,
    };
    let bytes = encode(&entry);
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded.labels, entry.labels);
    assert!(decoded.truncated);
}

#[test]
fn corrupt_bytes_surface_typed_error() {
    let bytes = vec![0xFFu8; 16];
    match decode(&bytes) {
        Err(DecodeError::Wire(_)) => {}
        other => panic!("expected Bincode error, got {other:?}"),
    }
}
