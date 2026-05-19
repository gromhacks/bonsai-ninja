use super::*;

#[test]
fn empty_entry_roundtrips() {
    let entry = TaintGraphEntry::default();
    let bytes = encode(&entry);
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded.func_raw, 0);
    assert!(decoded.seeds.is_empty());
}

#[test]
fn entry_roundtrips_with_seeds() {
    let entry = TaintGraphEntry {
        func_raw: 42,
        seeds: vec!["request".to_string(), "user".to_string()],
        graph: EntryTaintGraph::default(),
    };
    let bytes = encode(&entry);
    let decoded = decode(&bytes).expect("decode");
    assert_eq!(decoded.func_raw, 42);
    assert_eq!(decoded.seeds, vec!["request".to_string(), "user".to_string()]);
}

#[test]
fn decode_verified_accepts_matching_key() {
    let entry = TaintGraphEntry {
        func_raw: 42,
        seeds: vec!["a".to_string(), "b".to_string()],
        graph: EntryTaintGraph::default(),
    };
    let bytes = encode(&entry);
    let seeds: Vec<String> = vec!["a".to_string(), "b".to_string()];
    let decoded = decode_verified(&bytes, FuncId::new(42), &seeds).expect("verified decode");
    assert_eq!(decoded.func_raw, 42);
}

#[test]
fn decode_verified_rejects_mismatched_func() {
    let entry = TaintGraphEntry {
        func_raw: 42,
        seeds: vec!["a".to_string()],
        graph: EntryTaintGraph::default(),
    };
    let bytes = encode(&entry);
    let seeds = vec!["a".to_string()];
    match decode_verified(&bytes, FuncId::new(99), &seeds) {
        Err(DecodeError::KeyMismatch { .. }) => {}
        other => panic!("expected KeyMismatch, got {other:?}"),
    }
}

#[test]
fn decode_verified_rejects_mismatched_seeds() {
    let entry = TaintGraphEntry {
        func_raw: 42,
        seeds: vec!["a".to_string()],
        graph: EntryTaintGraph::default(),
    };
    let bytes = encode(&entry);
    let seeds = vec!["different".to_string()];
    match decode_verified(&bytes, FuncId::new(42), &seeds) {
        Err(DecodeError::KeyMismatch { .. }) => {}
        other => panic!("expected KeyMismatch, got {other:?}"),
    }
}

#[test]
fn factstore_key_is_deterministic() {
    let a = factstore_key(FuncId::new(7), &["alpha".to_string(), "beta".to_string()]);
    let b = factstore_key(FuncId::new(7), &["alpha".to_string(), "beta".to_string()]);
    assert_eq!(a, b);
}

#[test]
fn factstore_key_distinguishes_different_inputs() {
    let a = factstore_key(FuncId::new(7), &["alpha".to_string()]);
    let b = factstore_key(FuncId::new(7), &["beta".to_string()]);
    let c = factstore_key(FuncId::new(8), &["alpha".to_string()]);
    let d = factstore_key(FuncId::new(7), &["alpha".to_string(), "beta".to_string()]);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
    assert_ne!(b, c);
}

#[test]
fn factstore_key_distinguishes_seed_partition() {
    // FNV-1a with null separators must distinguish list shapes.
    let a = factstore_key(FuncId::new(0), &["ab".to_string(), "c".to_string()]);
    let b = factstore_key(FuncId::new(0), &["a".to_string(), "bc".to_string()]);
    assert_ne!(a, b);
}
