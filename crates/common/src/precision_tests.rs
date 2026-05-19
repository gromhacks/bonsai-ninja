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
