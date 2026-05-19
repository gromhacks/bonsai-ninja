use super::*;
use bonsai_common::FuncId;
use bonsai_taint::KindedTokens;

#[test]
fn empty_entry_roundtrips() {
    let entry = DataFlowEntry::default();
    let bytes = encode(&entry);
    let decoded = decode(&bytes).expect("decode");
    assert!(decoded.facts.by_kind.is_empty());
    assert!(decoded.dependency_files.is_empty());
}

#[test]
fn dependencies_are_sorted_for_determinism() {
    let entry = DataFlowEntry::from_owned(
        KindedTokens::default(),
        EntryTaintGraph::default(),
        [FileId::new(7), FileId::new(2), FileId::new(7), FileId::new(5)],
    );
    assert_eq!(entry.dependency_files, vec![2, 5, 7]);
}

#[test]
fn entry_with_facts_and_dependencies_roundtrips() {
    let mut facts = KindedTokens::default();
    facts
        .by_kind
        .entry(bonsai_taint::FactKind::Decl)
        .or_default()
        .insert("foo".to_string());
    let entry = DataFlowEntry::from_owned(
        facts,
        EntryTaintGraph::default(),
        [FileId::new(1), FileId::new(3)],
    );
    let bytes = encode(&entry);
    let decoded = decode(&bytes).expect("decode");
    let recovered_facts = decoded
        .facts
        .by_kind
        .get(&bonsai_taint::FactKind::Decl)
        .expect("decl bucket present");
    assert!(recovered_facts.contains("foo"));
    assert_eq!(decoded.dependency_set().len(), 2);
    // Smoke-check that FuncId path still works for callers
    // building a new entry around recovered values.
    let _check: FuncId = FuncId::new(0);
}

#[test]
fn corrupt_bytes_surface_typed_error() {
    let bytes = vec![0xFFu8; 16];
    match decode(&bytes) {
        Err(DecodeError::Bincode(_)) => {}
        other => panic!("expected Bincode error, got {other:?}"),
    }
}
