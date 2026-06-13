use super::{is_quoted_literal, normalise_qualified_text, value_bearing_identifier_text};

#[test]
fn symbol_key_subscript_normalises_without_colon() {
    // Ruby / Elixir symbol keys canonicalise to the same dotted
    // projection as string keys, so a field seed (`params.token`)
    // addresses the projected read node regardless of key syntax.
    assert_eq!(normalise_qualified_text("params[:token]"), "params.token");
    assert_eq!(normalise_qualified_text("args[:cmd]"), "args.cmd");
    assert_eq!(normalise_qualified_text("args['cmd']"), "args.cmd");
}

#[test]
fn matches_shared_projection_canonicalization_spec() {
    // Engine-side copy of the projection canonicalization; pinned to
    // the shared vectors so it cannot drift from the adapter-side and
    // IDG-transfer copies. See
    // `bonsai_common::PROJECTION_CANONICALIZATION_VECTORS`.
    for (input, expected) in bonsai_common::PROJECTION_CANONICALIZATION_VECTORS {
        assert_eq!(
            &normalise_qualified_text(input),
            expected,
            "engine-side normaliser drifted on `{input}`"
        );
    }
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

#[test]
fn value_bearing_identifier_text_strips_static_size_operands() {
    assert_eq!(
        value_bearing_identifier_text("sizeof(c) * moduleTempClientCap"),
        "sizeof  * moduleTempClientCap"
    );
    assert_eq!(
        value_bearing_identifier_text("MALLOC_MIN_SIZE(size)+PREFIX_SIZE"),
        "MALLOC_MIN_SIZE(size)+PREFIX_SIZE"
    );
    assert_eq!(
        value_bearing_identifier_text("sizeof *ptr + len"),
        "sizeof  + len"
    );
    assert_eq!(
        value_bearing_identifier_text("nameof(user_input) + suffix"),
        "nameof  + suffix"
    );
}
