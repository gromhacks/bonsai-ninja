use super::*;

#[test]
fn same_tag_credits() {
    assert!(sanitizer_credits_sink_tag(Some("xss"), Some("xss")));
    assert!(sanitizer_credits_sink_tag(
        Some("sql-injection"),
        Some("sql-injection")
    ));
}

#[test]
fn dev_only_guard_credits_any_sink_family() {
    assert!(sanitizer_credits_sink_tag(
        Some("dev-only-guard"),
        Some("sql-injection")
    ));
    assert!(sanitizer_credits_sink_tag(Some("dev-only-guard"), Some("xss")));
}

#[test]
fn open_redirect_via_url_encode() {
    assert!(sanitizer_credits_sink_tag(
        Some("url-encode"),
        Some("open-redirect")
    ));
    assert!(sanitizer_credits_sink_tag(
        Some("open-redirect-sanitize"),
        Some("open-redirect")
    ));
}

#[test]
fn finite_allowlist_credits_ssti() {
    assert!(sanitizer_credits_sink_tag(
        Some("allowlist-validate"),
        Some("ssti")
    ));
}

#[test]
fn html_encode_does_not_clear_open_redirect() {
    // The wrong-context preservation case: HTML-encoding a value
    // that ends up in a URL context isn't a real defense.
    assert!(!sanitizer_credits_sink_tag(
        Some("html-encode"),
        Some("open-redirect")
    ));
}

#[test]
fn signed_token_verify_clears_eval_and_deser() {
    assert!(sanitizer_credits_sink_tag(
        Some("signed-token-verify"),
        Some("code-injection")
    ));
    assert!(sanitizer_credits_sink_tag(
        Some("signed-token-verify"),
        Some("insecure-deserialization")
    ));
}

#[test]
fn missing_tags_do_not_credit() {
    assert!(!sanitizer_credits_sink_tag(None, Some("xss")));
    assert!(!sanitizer_credits_sink_tag(Some("xss-sanitize"), None));
    assert!(!sanitizer_credits_sink_tag(None, None));
}

#[test]
fn passthrough_does_not_credit_any_sink() {
    // Passthrough sanitizers are identity edges, not credits — see
    // engine T104.
    assert!(!sanitizer_credits_sink_tag(
        Some("passthrough-decode"),
        Some("path-traversal")
    ));
}
