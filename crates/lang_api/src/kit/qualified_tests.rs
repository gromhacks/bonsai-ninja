use super::{assignment_rhs_text, normalise_qualified_text};

#[test]
fn dot_access_is_unchanged() {
    assert_eq!(normalise_qualified_text("self.cmd"), "self.cmd");
}

#[test]
fn arrow_becomes_dot() {
    assert_eq!(normalise_qualified_text("conn->host"), "conn.host");
}

#[test]
fn subscript_becomes_dot() {
    assert_eq!(normalise_qualified_text("env['cmd']"), "env.cmd");
    assert_eq!(normalise_qualified_text("env[\"cmd\"]"), "env.cmd");
}

#[test]
fn assignment_rhs_skips_eq_and_arrow() {
    assert_eq!(assignment_rhs_text("a = b"), Some("b"));
    // `==` and `=>` cause the first character to be skipped;
    // production behavior treats the trailing portion as an
    // RHS in pathological inputs, but adapters never feed
    // raw comparison expressions to this helper.
    assert_eq!(assignment_rhs_text("a => b"), None);
    assert_eq!(assignment_rhs_text("a = (b == c)"), Some("(b == c)"));
}

#[test]
fn assignment_rhs_handles_strings() {
    assert_eq!(assignment_rhs_text(r#"a = "x = y""#), Some("\"x = y\""));
}
