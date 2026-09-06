use std::sync::Arc;

#[test]
fn interpolated_switch_results_are_not_finite_literal_selections() {
    for result in [r#""\(key)""#, r##"#"\#(key)"#"##] {
        let source = format!(
            r#"func selected(_ key: String) -> String {{
  return switch key {{
    case "first": "safe"
    default: {result}
  }}
}}
"#
        );
        let workspace = bonsai_testkit::workspace_with(
            vec![Arc::new(bonsai_lang_swift::SwiftAdapter::new())],
            &[("Identity.swift", &source)],
        );
        let file = workspace.vfs().all_files()[0];
        let index = workspace.db().decl_index(file).expect("Swift declarations");
        assert!(
            index.finite_literal_selections.is_empty(),
            "{result}: {:?}",
            index.finite_literal_selections
        );
    }
}
