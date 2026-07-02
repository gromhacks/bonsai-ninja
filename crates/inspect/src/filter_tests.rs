use super::{
    chain_matches_filters, chain_matches_filters_for_hit, FactKindFilter, FilterHit, InspectFilters,
    PrecisionFilter,
};
use bonsai_common::Precision;
use bonsai_taint::KindedTokens;
use std::sync::Arc;

#[test]
fn precision_filter_matches_semantic_classes_only() {
    assert!(PrecisionFilter::Exact.matches(Precision::Exact));
    assert!(PrecisionFilter::Narrowed.matches(Precision::Narrowed));
    assert!(!PrecisionFilter::OverApproximate.matches(Precision::OverApproximate));
    assert!(!PrecisionFilter::Unknown.matches(Precision::Unknown));
}

fn empty_tokens() -> Arc<KindedTokens> {
    Arc::new(KindedTokens::default())
}

#[test]
fn kind_filter_does_not_use_untyped_hit_text_as_evidence() {
    let filters = InspectFilters {
        to: Some("pickle"),
        to_kind: Some(FactKindFilter::Call),
        ..InspectFilters::default()
    };

    assert!(
        !chain_matches_filters(Some("model = pickle.loads"), &[], &empty_tokens, filters,),
        "untyped display text must not prove a kind-specific endpoint"
    );
}

#[test]
fn typed_hit_text_must_match_requested_kind() {
    let filters = InspectFilters {
        to: Some("pickle"),
        to_kind: Some(FactKindFilter::Call),
        ..InspectFilters::default()
    };

    assert!(chain_matches_filters_for_hit(
        Some(FilterHit::new("pickle.loads", FactKindFilter::Call)),
        &[],
        &empty_tokens,
        filters,
    ));
    assert!(!chain_matches_filters_for_hit(
        Some(FilterHit::new("model = pickle.loads", FactKindFilter::Write)),
        &[],
        &empty_tokens,
        filters,
    ));
}
