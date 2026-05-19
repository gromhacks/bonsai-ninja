use super::*;
use bonsai_common::FileId;

fn span(start: u64, end: u64) -> Span {
    Span::new(FileId::new(0), start, end)
}

#[test]
fn read_constructor_is_empty_field_path() {
    let p = Place::read(7);
    match p {
        Place::Read { name, path } => {
            assert_eq!(name, 7);
            assert!(path.is_empty());
        }
        _ => panic!("expected Read"),
    }
}

#[test]
fn read_field_constructor_has_one_segment() {
    let p = Place::read_field(2, 11);
    match p {
        Place::Read { name, path } => {
            assert_eq!(name, 2);
            assert_eq!(path.len(), 1);
            assert_eq!(path[0], 11);
        }
        _ => panic!("expected Read"),
    }
}

#[test]
fn discriminant_tags_are_stable() {
    // Pinning these — on-disk format depends on them not shifting.
    assert_eq!(Place::Param { idx: 0 }.tag(), 0);
    assert_eq!(Place::Return.tag(), 1);
    assert_eq!(Place::read(0).tag(), 2);
    assert_eq!(Place::write(0, span(0, 1)).tag(), 3);
    assert_eq!(
        Place::CallArg {
            site: CallSiteId(span(0, 1)),
            idx: 0
        }
        .tag(),
        4
    );
    assert_eq!(
        Place::CallRet {
            site: CallSiteId(span(0, 1)),
        }
        .tag(),
        5
    );
    assert_eq!(Place::Throw { ty: TypeId(0) }.tag(), 6);
    assert_eq!(Place::Catch { ty: TypeId(0) }.tag(), 7);
    assert_eq!(Place::Yield.tag(), 8);
    assert_eq!(Place::Await.tag(), 9);
}

#[test]
fn equality_distinguishes_field_paths() {
    let a = Place::read(1);
    let b = Place::read_field(1, 5);
    let c = Place::read_field(1, 5);
    assert_ne!(a, b);
    assert_eq!(b, c);
}

#[test]
fn equality_distinguishes_read_vs_write() {
    let a = Place::read(1);
    let b = Place::write(1, span(0, 1));
    assert_ne!(a, b);
}

#[test]
fn equality_distinguishes_writes_by_span() {
    let a = Place::write(1, span(0, 5));
    let b = Place::write(1, span(0, 6));
    assert_ne!(a, b, "different write span must produce distinct Place");
}

#[test]
fn equality_distinguishes_call_sites_by_span() {
    let a = Place::CallArg {
        site: CallSiteId(span(0, 5)),
        idx: 0,
    };
    let b = Place::CallArg {
        site: CallSiteId(span(0, 6)),
        idx: 0,
    };
    let c = Place::CallArg {
        site: CallSiteId(span(0, 5)),
        idx: 1,
    };
    assert_ne!(a, b, "different span must not be equal");
    assert_ne!(a, c, "different arg index must not be equal");
}

#[test]
fn is_named_storage_only_matches_read_write() {
    assert!(Place::read(0).is_named_storage());
    assert!(Place::write(0, span(0, 1)).is_named_storage());
    assert!(!Place::Return.is_named_storage());
    assert!(!Place::CallArg {
        site: CallSiteId(span(0, 1)),
        idx: 0,
    }
    .is_named_storage());
    assert!(!Place::Throw { ty: TypeId(0) }.is_named_storage());
}

#[test]
fn is_call_site_only_matches_call_arg_and_call_ret() {
    let s = CallSiteId(span(0, 1));
    assert!(Place::CallArg { site: s, idx: 0 }.is_call_site());
    assert!(Place::CallRet { site: s }.is_call_site());
    assert!(!Place::Param { idx: 0 }.is_call_site());
    assert!(!Place::Read {
        name: 0,
        path: SmallVec::new(),
    }
    .is_call_site());
}

#[test]
fn call_site_returns_span_only_for_call_places() {
    let s = span(10, 20);
    let cs = CallSiteId(s);
    assert_eq!(Place::CallArg { site: cs, idx: 0 }.call_site(), Some(s));
    assert_eq!(Place::CallRet { site: cs }.call_site(), Some(s));
    assert_eq!(Place::Param { idx: 0 }.call_site(), None);
    assert_eq!(Place::read(0).call_site(), None);
}

#[test]
fn display_renders_field_paths_dotted() {
    let mut path = FieldPath::new();
    path.push(11);
    path.push(22);
    let p = Place::Read { name: 7, path };
    let rendered = format!("{p}");
    assert!(rendered.contains("Read("));
    assert!(rendered.contains(".11"));
    assert!(rendered.contains(".22"));
}

#[test]
fn place_hashes_consistently() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = Place::read_field(7, 5);
    let b = Place::read_field(7, 5);
    let mut ha = DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = DefaultHasher::new();
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
}
