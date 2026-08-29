use super::*;

#[test]
fn taint_analysis_has_one_public_semantic_contract() {
    assert_eq!(PUBLIC_SEMANTIC_MAX_PRECISION, Precision::Narrowed);
    assert!(Precision::Exact <= PUBLIC_SEMANTIC_MAX_PRECISION);
    assert!(Precision::Narrowed <= PUBLIC_SEMANTIC_MAX_PRECISION);
    assert!(Precision::OverApproximate > PUBLIC_SEMANTIC_MAX_PRECISION);
    assert!(Precision::Unknown > PUBLIC_SEMANTIC_MAX_PRECISION);
}
