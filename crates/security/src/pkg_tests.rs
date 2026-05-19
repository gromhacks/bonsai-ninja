use super::import_matches_package;

#[test]
fn exact_match() {
    assert!(import_matches_package("asyncpg", "asyncpg"));
}

#[test]
fn c_header_strip() {
    assert!(import_matches_package("sqlite3.h", "sqlite3"));
    assert!(import_matches_package("openssl/ssl.hpp", "openssl"));
}

#[test]
fn directory_prefix() {
    assert!(import_matches_package("poco/URI.h", "poco"));
}

#[test]
fn dotted_prefix() {
    assert!(import_matches_package("xml.etree.ElementTree", "xml"));
    assert!(import_matches_package(
        "org.apache.velocity.app.Velocity",
        "org.apache.velocity"
    ));
}

#[test]
fn perl_scope_prefix() {
    assert!(import_matches_package("DBI::db", "DBI"));
}

#[test]
fn no_partial_match() {
    // `asyncpg` must not match `asyncpg_pool` — would create
    // false positives on partial-prefix collisions.
    assert!(!import_matches_package("asyncpg", "async"));
    // `pg` must not match `asyncpg` — package names must be
    // whole-word boundaries.
    assert!(!import_matches_package("asyncpg", "pg"));
}

#[test]
fn empty_needle_never_matches() {
    assert!(!import_matches_package("anything", ""));
}

#[test]
fn php_namespace_exact_and_prefix() {
    // PHP namespaces use backslash separators. Adapter emits
    // `cakephp\cakephp` for `use cakephp\cakephp;`.
    assert!(import_matches_package("cakephp\\cakephp", "cakephp\\cakephp"));
    assert!(import_matches_package("cakephp\\cakephp", "cakephp"));
    assert!(import_matches_package("Cake\\Datasource\\Connection", "Cake"));
}
