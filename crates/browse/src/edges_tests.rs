use super::PrecisionClass;
use bonsai_common::Precision;

#[test]
fn precision_class_matches_semantic_classes_only() {
    assert!(PrecisionClass::Exact.matches(Precision::Exact));
    assert!(PrecisionClass::Narrowed.matches(Precision::Narrowed));
    assert!(!PrecisionClass::OverApproximate.matches(Precision::OverApproximate));
    assert!(!PrecisionClass::Unknown.matches(Precision::Unknown));
}
