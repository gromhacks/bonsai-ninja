use super::*;

fn metadata() -> &'static RulepackMetadata {
    static METADATA: std::sync::OnceLock<RulepackMetadata> = std::sync::OnceLock::new();
    METADATA.get_or_init(|| {
        crate::loader::load_rulepack(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("security-patterns"),
        )
        .expect("bundled rulepack")
        .metadata
    })
}

#[test]
fn same_tag_credits() {
    assert!(sanitizer_credits_sink_tag(metadata(), Some("xss"), Some("xss")));
    assert!(sanitizer_credits_sink_tag(
        metadata(),
        Some("sql-injection"),
        Some("sql-injection")
    ));
}

#[test]
fn open_redirect_via_url_encode() {
    assert!(sanitizer_credits_sink_tag(
        metadata(),
        Some("url-encode"),
        Some("open-redirect")
    ));
    assert!(sanitizer_credits_sink_tag(
        metadata(),
        Some("open-redirect-sanitize"),
        Some("open-redirect")
    ));
}

#[test]
fn finite_allowlist_credits_ssti() {
    assert!(sanitizer_credits_sink_tag(
        metadata(),
        Some("allowlist-validate"),
        Some("ssti")
    ));
}

#[test]
fn html_encode_does_not_clear_open_redirect() {
    // The wrong-context preservation case: HTML-encoding a value
    // that ends up in a URL context isn't a real defense.
    assert!(!sanitizer_credits_sink_tag(
        metadata(),
        Some("html-encode"),
        Some("open-redirect")
    ));
}

#[test]
fn signed_token_verify_clears_eval_and_deser() {
    assert!(sanitizer_credits_sink_tag(
        metadata(),
        Some("signed-token-verify"),
        Some("code-injection")
    ));
    assert!(sanitizer_credits_sink_tag(
        metadata(),
        Some("signed-token-verify"),
        Some("insecure-deserialization")
    ));
}

#[test]
fn missing_tags_do_not_credit() {
    assert!(!sanitizer_credits_sink_tag(metadata(), None, Some("xss")));
    assert!(!sanitizer_credits_sink_tag(
        metadata(),
        Some("xss-sanitize"),
        None
    ));
    assert!(!sanitizer_credits_sink_tag(metadata(), None, None));
}

#[test]
fn passthrough_does_not_credit_any_sink() {
    // Passthrough sanitizers are identity edges, not credits — see
    // engine T104.
    assert!(!sanitizer_credits_sink_tag(
        metadata(),
        Some("passthrough-decode"),
        Some("path-traversal")
    ));
    assert!(sanitizer_tag_is_recognized_non_crediting(
        metadata(),
        "passthrough-decode"
    ));
}

#[test]
fn active_cross_tag_credits_remain_complete() {
    for (sanitizer, sink) in [
        ("html-sanitize", "xss"),
        ("path-sanitize", "path-traversal"),
        ("sql-parameter", "sql-injection"),
        ("same-origin-path", "header-injection"),
    ] {
        assert!(
            sanitizer_credits_sink_tag(metadata(), Some(sanitizer), Some(sink)),
            "metadata must retain the {sanitizer} -> {sink} credit"
        );
    }
}
