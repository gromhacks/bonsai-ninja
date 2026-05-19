use super::effective_optional_cap;

#[test]
fn zero_optional_tree_cap_means_unbounded() {
    assert_eq!(effective_optional_cap(None, 5), 5);
    assert_eq!(effective_optional_cap(Some(3), 5), 3);
    assert_eq!(effective_optional_cap(Some(0), 5), usize::MAX);
}
