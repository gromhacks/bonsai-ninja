use super::{is_quoted_literal, normalise_qualified_text};

#[test]
fn normalizer_consumes_compiler_names_without_reparsing_source_syntax() {
    let vectors = [
        ("obj.cmd", "obj.cmd"),
        ("conn->host", "conn.host"),
        ("&value", "value"),
    ];
    for (input, expected) in vectors {
        assert_eq!(
            normalise_qualified_text(input),
            expected,
            "engine-side normaliser drifted on `{input}`"
        );
    }
    assert_eq!(
        normalise_qualified_text("params[:token]"),
        "params[:token]",
        "subscript syntax belongs to the language adapter, not the taint engine"
    );
}

#[test]
fn quoted_literal_detection_rejects_concat_expressions() {
    assert!(is_quoted_literal("\"static\""));
    assert!(is_quoted_literal("'static\\'value'"));
    assert!(is_quoted_literal("`static`"));
    assert!(!is_quoted_literal("\"<p>\" .. q .. \"</p>\""));
    assert!(!is_quoted_literal("\"<p>\" <> body <> \"</p>\""));
    assert!(!is_quoted_literal("'<p>' + comment + '</p>'"));
}
