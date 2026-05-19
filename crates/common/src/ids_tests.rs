use super::*;

#[test]
fn invalid_sentinel_roundtrip() {
    let id = FileId::INVALID;
    assert!(!id.is_valid());
    assert!(FileId::new(0).is_valid());
}

#[test]
fn display_is_raw() {
    assert_eq!(FuncId::new(42).to_string(), "42");
}
