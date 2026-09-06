use super::*;

#[test]
fn empty_config_disables_every_category() {
    assert!(!EnabledSet::from_raw("").contains("nonexistent"));
}

#[test]
fn reset_replaces_cached_configuration() {
    const CHILD: &str = "BONSAI_DEBUG_RESET_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert!(!is_enabled("idg-query"));
        std::env::set_var("BONSAI_DEBUG", "idg-query");
        reset_for_tests();
        assert!(is_enabled("idg-query"));
        assert!(!is_enabled("workspace-open"));
        std::env::set_var("BONSAI_DEBUG", " * ");
        reset_for_tests();
        assert!(is_enabled("workspace-open"));
        std::env::remove_var("BONSAI_DEBUG");
        reset_for_tests();
        assert!(!is_enabled("idg-query"));
        assert!(!is_enabled("workspace-open"));
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "debug::tests::reset_replaces_cached_configuration",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env_remove("BONSAI_DEBUG")
        .output()
        .unwrap();
    assert!(output.status.success(), "child failed: {output:?}");
}

#[test]
fn parse_handles_wildcard() {
    for raw in ["*", "all", " , all , "] {
        assert!(EnabledSet::from_raw(raw).contains("anything"));
    }
}

#[test]
fn parse_matches_exact_name() {
    let set = EnabledSet::from_raw(" , idg-closure , ");
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
