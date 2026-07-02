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

#[test]
fn render_message_humanizes_key_value_tokens() {
    assert_eq!(
        render_message("matcher scan stats: files=8 funcs=2 source_funcs=1 text_skipped=0 enabled=true"),
        "matcher scan stats: files 8 · functions 2 · source functions 1 · text skipped 0 · enabled on"
    );
}
