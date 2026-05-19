use super::PrecisionFilter;
use bonsai_common::Precision;

#[test]
fn precision_filter_matches_semantic_classes_only() {
    assert!(PrecisionFilter::Exact.matches(Precision::Exact));
    assert!(PrecisionFilter::Narrowed.matches(Precision::Narrowed));
    assert!(!PrecisionFilter::OverApproximate.matches(Precision::OverApproximate));
    assert!(!PrecisionFilter::Unknown.matches(Precision::Unknown));
}
