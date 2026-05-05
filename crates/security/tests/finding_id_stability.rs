//! Finding-id content-hash stability.

use bonsai_security::compute_finding_id;

#[test]
fn finding_id_is_deterministic() {
    let a = compute_finding_id("src1", "sink1", "G:abc", "python");
    let b = compute_finding_id("src1", "sink1", "G:abc", "python");
    assert_eq!(a, b);
    assert!(a.starts_with("S:"));
    assert_eq!(a.len(), 18);
    assert_eq!(a, "S:58f512049011d3c7");
}

#[test]
fn finding_id_changes_with_any_field() {
    let base = compute_finding_id("src1", "sink1", "G:abc", "python");
    assert_ne!(base, compute_finding_id("src2", "sink1", "G:abc", "python"));
    assert_ne!(base, compute_finding_id("src1", "sink2", "G:abc", "python"));
    assert_ne!(base, compute_finding_id("src1", "sink1", "G:def", "python"));
    assert_ne!(base, compute_finding_id("src1", "sink1", "G:abc", "javascript"));
}
