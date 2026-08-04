use super::{call_candidate_matches_package_tail, import_matches_package};
use crate::loader::{PackageMatchSemantics, PackageTailBindingSemantics};

fn dotted() -> PackageMatchSemantics {
    PackageMatchSemantics {
        package_separators: vec![".".to_string()],
        ..Default::default()
    }
}

#[test]
fn exact_match_needs_no_language_policy() {
    assert!(import_matches_package(
        "dependency",
        "dependency",
        &PackageMatchSemantics::default()
    ));
}

#[test]
fn prefix_and_suffix_normalization_are_metadata_driven() {
    let semantics = PackageMatchSemantics {
        strip_import_prefixes: vec!["runtime:".to_string()],
        strip_import_suffixes: vec![".header".to_string()],
        package_separators: vec!["/".to_string()],
        ..Default::default()
    };
    assert!(import_matches_package("runtime:io/async", "io", &semantics));
    assert!(import_matches_package("storage.header", "storage", &semantics));
    assert!(!import_matches_package("runtime_tools", "tools", &semantics));
}

#[test]
fn namespace_separators_are_metadata_driven_and_boundary_safe() {
    let semantics = PackageMatchSemantics {
        package_separators: vec![".".to_string(), "::".to_string(), "\\".to_string()],
        ..Default::default()
    };
    assert!(import_matches_package(
        "org.example.Type",
        "org.example",
        &semantics
    ));
    assert!(import_matches_package("DB::Handle", "DB", &semantics));
    assert!(import_matches_package("Framework\\Data", "Framework", &semantics));
    assert!(!import_matches_package("async_driver", "async", &semantics));
}

#[test]
fn package_tail_binding_is_metadata_driven() {
    let semantics = PackageMatchSemantics {
        package_separators: vec!["/".to_string()],
        call_qualifier_from_package_tail: Some(PackageTailBindingSemantics {
            package_separator: "/".to_string(),
            call_separators: vec![".".to_string()],
        }),
        ..Default::default()
    };
    assert!(call_candidate_matches_package_tail(
        "runner.Execute",
        "runtime/runner",
        &semantics
    ));
    assert!(!call_candidate_matches_package_tail(
        "runtime.Execute",
        "runtime/runner",
        &semantics
    ));
    assert!(!call_candidate_matches_package_tail(
        "runner.Execute",
        "runtime/runner",
        &dotted()
    ));
}

#[test]
fn empty_package_never_matches() {
    assert!(!import_matches_package(
        "anything",
        "",
        &PackageMatchSemantics::default()
    ));
}
