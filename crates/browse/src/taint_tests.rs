use super::aggregate_flow_precision;
use bonsai_common::Precision;

#[test]
fn aggregate_flow_precision_keeps_worst_semantic_precision() {
    assert_eq!(
        aggregate_flow_precision([Precision::Exact, Precision::Narrowed, Precision::Exact]),
        Precision::Narrowed
    );
    assert_eq!(aggregate_flow_precision([]), Precision::Exact);
}
