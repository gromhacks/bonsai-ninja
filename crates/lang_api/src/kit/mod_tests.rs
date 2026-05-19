use super::receiver_projected_alias_matches;

#[test]
fn receiver_projected_alias_matches_tuple_field_chains_only() {
    assert!(receiver_projected_alias_matches("repo.0", "repo"));

    assert!(!receiver_projected_alias_matches("r.Header", "r"));
    assert!(!receiver_projected_alias_matches("r.Header.Get", "r"));
    assert!(!receiver_projected_alias_matches("r", "r"));
    assert!(!receiver_projected_alias_matches("other.r", "r"));
    assert!(!receiver_projected_alias_matches("r.Header()", "r"));
}
