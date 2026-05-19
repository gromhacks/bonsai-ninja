use super::*;

#[test]
fn taint_options_default_to_semantic_precision() {
    assert_eq!(
        TaintAnalysisOptions::default().max_precision,
        Some(Precision::Narrowed)
    );
}

#[test]
fn taint_options_clamp_broad_precision_to_semantic() {
    let exact = TaintAnalysisOptions {
        max_precision: Some(Precision::Exact),
        ..TaintAnalysisOptions::default()
    }
    .semantic_precision_only();
    assert_eq!(exact.max_precision, Some(Precision::Exact));

    let none = TaintAnalysisOptions {
        max_precision: None,
        ..TaintAnalysisOptions::default()
    }
    .semantic_precision_only();
    assert_eq!(none.max_precision, Some(Precision::Narrowed));

    let broad = TaintAnalysisOptions {
        max_precision: Some(Precision::OverApproximate),
        ..TaintAnalysisOptions::default()
    }
    .semantic_precision_only();
    assert_eq!(broad.max_precision, Some(Precision::Narrowed));

    let unknown = TaintAnalysisOptions {
        max_precision: Some(Precision::Unknown),
        ..TaintAnalysisOptions::default()
    }
    .semantic_precision_only();
    assert_eq!(unknown.max_precision, Some(Precision::Narrowed));
}
