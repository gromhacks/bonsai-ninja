use super::*;

#[test]
fn is_enabled_returns_false_when_env_unset() {
    // The OnceLock caches per process — assertion holds only on
    // the FIRST `is_enabled` call. Subsequent tests in this
    // module will see the cached state.
    std::env::remove_var("BONSAI_DEBUG");
    // Read before any other test in this binary populates the
    // OnceLock with a different env value.
    if ENABLED.get().is_none() {
        assert!(!is_enabled("nonexistent"));
    }
}

#[test]
fn parse_handles_wildcard() {
    let set = EnabledSet {
        all: true,
        names: Vec::new(),
    };
    assert!(set.contains("anything"));
}

#[test]
fn parse_matches_exact_name() {
    let set = EnabledSet {
        all: false,
        names: vec!["idg-closure".to_string()],
    };
    assert!(set.contains("idg-closure"));
    assert!(!set.contains("idg-resolve"));
}
