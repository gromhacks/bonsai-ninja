use super::{edge_names_match_filters, EdgesFilters, PrecisionClass};
use bonsai_common::Precision;

#[test]
fn precision_class_matches_semantic_classes_only() {
    assert!(PrecisionClass::Exact.matches(Precision::Exact));
    assert!(PrecisionClass::Narrowed.matches(Precision::Narrowed));
    assert!(!PrecisionClass::OverApproximate.matches(Precision::OverApproximate));
    assert!(!PrecisionClass::Unknown.matches(Precision::Unknown));
}

#[test]
fn symbol_filters_match_before_edge_rendering() {
    let filters = EdgesFilters {
        from: Some("controller"),
        to: Some("execute"),
        ..EdgesFilters::default()
    };
    assert!(edge_names_match_filters(
        "admin_controller",
        "execute_command",
        &filters
    ));
    assert!(!edge_names_match_filters(
        "public_controller",
        "validate_command",
        &filters
    ));
}
