use super::{looks_like_bare_identifier, looks_like_identifier, looks_like_literal_value};

#[test]
fn identifier_kinds_recognized() {
    assert!(looks_like_identifier("identifier"));
    assert!(looks_like_identifier("type_identifier"));
    assert!(looks_like_identifier("scoped_identifier"));
    assert!(looks_like_identifier("field_name"));
    assert!(looks_like_identifier("name"));
    assert!(looks_like_identifier("word"));
    assert!(looks_like_identifier("var"));
    assert!(!looks_like_identifier("call_expression"));
    assert!(!looks_like_identifier("string_literal"));
    assert!(!looks_like_identifier(""));
}

#[test]
fn bare_identifier_predicate() {
    assert!(looks_like_bare_identifier("foo"));
    assert!(looks_like_bare_identifier("_foo"));
    assert!(looks_like_bare_identifier("Foo123"));
    assert!(looks_like_bare_identifier("snake_case_name"));
    assert!(!looks_like_bare_identifier(""));
    assert!(!looks_like_bare_identifier("123abc"));
    assert!(!looks_like_bare_identifier("foo.bar"));
    assert!(!looks_like_bare_identifier("foo->bar"));
    assert!(!looks_like_bare_identifier("foo bar"));
    assert!(!looks_like_bare_identifier("$foo"));
    assert!(!looks_like_bare_identifier("@foo"));
}

#[test]
fn literal_value_predicate_is_value_context_only() {
    assert!(looks_like_literal_value("none", "None"));
    assert!(looks_like_literal_value("value_argument", "nil"));
    assert!(looks_like_literal_value("null", "nullptr"));
    assert!(looks_like_literal_value("identifier", "undefined"));
    assert!(!looks_like_literal_value("var", "None"));
    assert!(!looks_like_literal_value("identifier", "token"));
}
