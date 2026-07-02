use super::*;

#[test]
fn meet_picks_worse() {
    assert_eq!(Precision::Exact.meet(Precision::Narrowed), Precision::Narrowed);
    assert_eq!(
        Precision::Narrowed.meet(Precision::OverApproximate),
        Precision::OverApproximate
    );
    assert_eq!(Precision::Unknown.meet(Precision::Exact), Precision::Unknown);
}

#[test]
fn public_evidence_contract_excludes_diagnostic_precision() {
    assert!(Precision::Exact.is_proven_static_evidence());
    assert!(Precision::Narrowed.is_proven_static_evidence());
    assert!(!Precision::OverApproximate.is_proven_static_evidence());
    assert!(!Precision::Unknown.is_proven_static_evidence());

    assert!(!Precision::Exact.is_diagnostic_only());
    assert!(!Precision::Narrowed.is_diagnostic_only());
    assert!(Precision::OverApproximate.is_diagnostic_only());
    assert!(Precision::Unknown.is_diagnostic_only());
}
