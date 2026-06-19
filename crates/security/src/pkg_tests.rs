use super::call_candidate_matches_package_tail;
use super::import_matches_package;
use super::java_like_fully_qualified_package;

#[test]
fn exact_match() {
    assert!(import_matches_package("asyncpg", "asyncpg"));
}

#[test]
fn go_path_package_tail_credits_fqn_call_candidate() {
    // WS1 FQN-no-import: `exec.Command(...)` / `http.Get(...)` with no
    // in-file import — the bare qualifier equals the package's last
    // `/`-segment.
    assert!(call_candidate_matches_package_tail("exec", "os/exec"));
    // The candidate is often the whole qualified callee, not the bare head.
    assert!(call_candidate_matches_package_tail("exec.Command", "os/exec"));
    assert!(call_candidate_matches_package_tail("http.Get", "net/http"));
    assert!(call_candidate_matches_package_tail("http", "net/http"));
    assert!(call_candidate_matches_package_tail(
        "gin",
        "github.com/gin-gonic/gin"
    ));
    assert!(call_candidate_matches_package_tail(
        "s3",
        "github.com/aws/aws-sdk-go/service/s3"
    ));
}

#[test]
fn package_tail_does_not_credit_non_tail_or_scoped() {
    // Non-tail segment must not match.
    assert!(!call_candidate_matches_package_tail("os", "os/exec"));
    // Single-segment packages are covered by import_matches_package, not here.
    assert!(!call_candidate_matches_package_tail("flask", "flask"));
    // npm scoped packages excluded — `client`/`hapi` are too generic to
    // credit without a real import (would loosen the gate).
    assert!(!call_candidate_matches_package_tail("client", "@prisma/client"));
    assert!(!call_candidate_matches_package_tail("hapi", "@hapi/hapi"));
    // Empty candidate never matches.
    assert!(!call_candidate_matches_package_tail("", "os/exec"));
}

#[test]
fn perl_arrow_method_separator() {
    // Perl FQN-no-use: `Net::HTTP->new` qualifier matches package Net::HTTP.
    assert!(import_matches_package("Net::HTTP->new", "Net::HTTP"));
    assert!(import_matches_package("LWP::UserAgent->new", "LWP::UserAgent"));
    // Must not match an unrelated package.
    assert!(!import_matches_package("Net::HTTP->new", "Net::FTP"));
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
fn java_like_fqn_package_prefix() {
    assert_eq!(
        java_like_fully_qualified_package("javax.naming.directory.InitialDirContext"),
        Some("javax.naming.directory")
    );
    assert_eq!(
        java_like_fully_qualified_package("new javax.naming.directory.InitialDirContext"),
        Some("javax.naming.directory")
    );
    assert_eq!(
        java_like_fully_qualified_package("org.example.Factory.create"),
        Some("org.example")
    );
    assert_eq!(java_like_fully_qualified_package("javax.naming.directory"), None);
    assert_eq!(java_like_fully_qualified_package("InitialDirContext"), None);
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
fn node_builtin_scheme_strip() {
    // Node.js builtin modules imported with the explicit `node:`
    // scheme must match rules keyed on the bare builtin name.
    assert!(import_matches_package("node:child_process", "child_process"));
    assert!(import_matches_package("node:fs", "fs"));
    assert!(import_matches_package("node:fs/promises", "fs"));
    // The bare form still matches.
    assert!(import_matches_package("child_process", "child_process"));
    // A non-builtin specifier that merely starts with `node` is not
    // stripped (only the `node:` scheme is).
    assert!(!import_matches_package("nodemailer", "mailer"));
}

#[test]
fn php_namespace_exact_and_prefix() {
    // PHP namespaces use backslash separators. Adapter emits
    // `cakephp\cakephp` for `use cakephp\cakephp;`.
    assert!(import_matches_package("cakephp\\cakephp", "cakephp\\cakephp"));
    assert!(import_matches_package("cakephp\\cakephp", "cakephp"));
    assert!(import_matches_package("Cake\\Datasource\\Connection", "Cake"));
}
