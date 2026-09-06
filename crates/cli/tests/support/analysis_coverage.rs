//! Exact coverage expectations: unsupported dependency formats are reported,
//! never mistaken for completed manifest analysis or for compiler failures.
#![allow(dead_code)]

pub(crate) fn gauntlet_manifest_reasons(language: &str) -> Vec<&'static str> {
    match language {
        "go" => vec!["dependency-manifest:unsupported:go:go.mod:files=1"],
        "objc" => vec!["dependency-manifest:unsupported:objc:Podfile:files=1"],
        "swift" => vec!["dependency-manifest:unsupported:swift:Package.swift:files=1"],
        _ => Vec::new(),
    }
}

pub(crate) fn assert_exact_coverage(value: &serde_json::Value, expected: &[&str], context: &str) {
    let actual = value["analysis_incomplete_reasons"]
        .as_array()
        .expect("analysis_incomplete_reasons array")
        .iter()
        .map(|reason| reason.as_str().expect("coverage reason string"))
        .collect::<std::collections::BTreeSet<_>>();
    let wanted = expected
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, wanted, "{context}: unexpected analysis coverage: {value}");
    assert_eq!(
        value["analysis_complete"].as_bool(),
        Some(expected.is_empty()),
        "{context}: coverage flag disagrees with its reasons"
    );
}
