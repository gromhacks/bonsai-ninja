use super::{
    chain_matches_filters, chain_matches_filters_for_hit, FactKindFilter, FilterHit, InspectFilters,
};
use bonsai_taint::KindedTokens;
use std::sync::Arc;

#[test]
fn name_matching_preserves_unicode_case_and_identifier_boundaries() {
    for (haystack, needle, expected) in [
        ("Éclair.run", "écl", true),
        ("éclair.run", "ÉCL", true),
        ("éclair", "clair", false),
        ("éRun", "run", true),
        ("Δοκιμή.run", "δοκ", true),
        ("İsim", "i\u{307}s", true),
        ("调用.run", "run", true),
    ] {
        assert_eq!(
            super::name_token_match(haystack, needle),
            expected,
            "{haystack} / {needle}"
        );
    }
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
