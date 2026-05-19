use super::*;

#[test]
fn all_overrides_reference_real_scenarios() {
    for (_lang, ids, _status) in OVERRIDES {
        for id in *ids {
            assert!(
                SCENARIOS.iter().any(|s| s.id == *id),
                "applicability override references unknown scenario id `{id}`"
            );
        }
    }
}

#[test]
fn all_overrides_reference_real_languages() {
    for (lang, _ids, _status) in OVERRIDES {
        assert!(
            LANGUAGES.contains(lang),
            "applicability override references unknown language `{lang}`"
        );
    }
}

#[test]
fn applicable_count_per_language_matches_doc_estimate() {
    // Lower bound — sanity check that we don't accidentally mark
    // half the matrix as n/a. If a future edit drops a language's
    // applicable count below 40, this test fires and we revisit.
    for &lang in LANGUAGES {
        let applicable = SCENARIOS
            .iter()
            .filter(|s| status(lang, s.id) == Status::Applicable)
            .count();
        assert!(
            applicable >= 40,
            "{lang}: applicable cell count {applicable} too low — applicability table likely overreached"
        );
    }
}
