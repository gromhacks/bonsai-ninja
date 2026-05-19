use super::{is_quoted_literal, value_bearing_identifier_text};

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
