use super::*;

#[test]
fn place_dict_intern_dedupes() {
    let mut d = PlaceDict::new();
    let a = d.intern(Place::Return);
    let b = d.intern(Place::Return);
    assert_eq!(a, b, "interning the same place must return the same id");
    assert_eq!(d.len(), 1);
}

#[test]
fn place_dict_distinct_places_get_distinct_ids() {
    let mut d = PlaceDict::new();
    let a = d.intern(Place::Return);
    let b = d.intern(Place::Param { idx: 0 });
    let c = d.intern(Place::read(7));
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
    assert_eq!(d.len(), 3);
}

#[test]
fn place_dict_get_roundtrips_inserts() {
    let mut d = PlaceDict::new();
    let id = d.intern(Place::Param { idx: 3 });
    match d.get(id) {
        Some(Place::Param { idx: 3 }) => {}
        other => panic!("expected Param{{idx:3}}, got {other:?}"),
    }
}

#[test]
fn place_dict_lookup_finds_existing_only() {
    let mut d = PlaceDict::new();
    let id = d.intern(Place::Param { idx: 3 });
    assert_eq!(d.lookup(&Place::Param { idx: 3 }), Some(id));
    assert_eq!(d.lookup(&Place::Return), None);
}

#[test]
fn place_dict_get_none_past_end() {
    let mut d = PlaceDict::new();
    d.intern(Place::Return);
    assert!(d.get(PlaceId(0)).is_some());
    assert!(d.get(PlaceId(1)).is_none());
    assert!(d.get(PlaceId::SENTINEL).is_none());
}

#[test]
fn place_dict_rebuild_lookup_after_serde_roundtrip() {
    let mut d = PlaceDict::new();
    d.intern(Place::Return);
    let id_param = d.intern(Place::Param { idx: 5 });
    let bytes = bincode::serialize(&d).expect("serialize");
    let mut restored: PlaceDict = bincode::deserialize(&bytes).expect("deserialize");
    // After deserialise, by_place is empty (skip). lookup returns None.
    assert_eq!(restored.lookup(&Place::Return), None);
    restored.rebuild_lookup();
    assert_eq!(restored.lookup(&Place::Return), Some(PlaceId(0)));
    assert_eq!(restored.lookup(&Place::Param { idx: 5 }), Some(id_param));
}

#[test]
fn node_dict_intern_dedupes() {
    let mut d = NodeDict::new();
    let a = d.intern(FuncId::new(1), PlaceId(2));
    let b = d.intern(FuncId::new(1), PlaceId(2));
    assert_eq!(a, b);
    assert_eq!(d.len(), 1);
}

#[test]
fn node_dict_distinct_components_distinct_ids() {
    let mut d = NodeDict::new();
    let a = d.intern(FuncId::new(1), PlaceId(2));
    let b = d.intern(FuncId::new(1), PlaceId(3));
    let c = d.intern(FuncId::new(2), PlaceId(2));
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
    assert_eq!(d.len(), 3);
}

#[test]
fn node_dict_get_roundtrips() {
    let mut d = NodeDict::new();
    let id = d.intern(FuncId::new(7), PlaceId(11));
    match d.get(id) {
        Some(node) => {
            assert_eq!(node.func, FuncId::new(7));
            assert_eq!(node.place, PlaceId(11));
        }
        None => panic!("just-interned node must be retrievable"),
    }
}

#[test]
fn node_dict_lookup_uses_both_components() {
    let mut d = NodeDict::new();
    d.intern(FuncId::new(7), PlaceId(11));
    assert!(d.lookup(FuncId::new(7), PlaceId(11)).is_some());
    assert!(d.lookup(FuncId::new(7), PlaceId(12)).is_none());
    assert!(d.lookup(FuncId::new(8), PlaceId(11)).is_none());
}

#[test]
fn node_dict_rebuild_lookup_after_serde_roundtrip() {
    let mut d = NodeDict::new();
    let a = d.intern(FuncId::new(7), PlaceId(11));
    let b = d.intern(FuncId::new(8), PlaceId(11));
    let bytes = bincode::serialize(&d).expect("serialize");
    let mut restored: NodeDict = bincode::deserialize(&bytes).expect("deserialize");
    assert_eq!(restored.lookup(FuncId::new(7), PlaceId(11)), None);
    restored.rebuild_lookup();
    assert_eq!(restored.lookup(FuncId::new(7), PlaceId(11)), Some(a));
    assert_eq!(restored.lookup(FuncId::new(8), PlaceId(11)), Some(b));
}

#[test]
fn dicts_are_empty_initially() {
    assert!(PlaceDict::new().is_empty());
    assert!(NodeDict::new().is_empty());
}

#[test]
fn place_dict_with_capacity_starts_empty() {
    let d = PlaceDict::with_capacity(64);
    assert_eq!(d.len(), 0);
    assert!(d.is_empty());
}

#[test]
fn node_dict_with_capacity_starts_empty() {
    let d = NodeDict::with_capacity(64);
    assert_eq!(d.len(), 0);
    assert!(d.is_empty());
}
