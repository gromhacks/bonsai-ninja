use super::{edge_names_match_filters, EdgesFilters};

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
