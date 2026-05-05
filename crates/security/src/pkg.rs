//! Shared package-name matching used by both the dependency
//! inventory (`deps.rs`) and the per-file lax-tail gate
//! (`matcher.rs`).
//!
//! Adapters surface import targets in the form they appear in source
//! (`asyncpg`, `sqlite3.h`, `poco/URI.h`, `DBI::db`,
//! `org.apache.velocity.app.VelocityEngine`). Rules declare packages
//! using the same adapter-visible import roots (`asyncpg`, `sqlite3`,
//! `poco`, `DBI`, `org.apache.velocity`). One helper decides whether
//! an import target represents a given package, with
//! the same prefix-stripping / dotted-prefix tolerance both call
//! sites need.

/// True when `imported` (an adapter-emitted import target) names
/// the package `needle`. Matches:
///
/// - exact equality (`asyncpg` == `asyncpg`),
/// - C/C++ header forms with `.h` / `.hpp` / `.hxx` stripped
///   (`sqlite3.h` → matches `sqlite3`),
/// - directory-prefix form (`poco/URI.h` matches `poco`),
/// - dotted-prefix form (`xml.etree.ElementTree` matches `xml`,
///   `org.apache.velocity.app.Velocity` matches `org.apache.velocity`),
/// - Perl-scope prefix (`DBI::db` matches `DBI`).
#[must_use]
pub(crate) fn import_matches_package(imported: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    // Strip C/C++ header suffix so `sqlite3.h` matches a `sqlite3` rule.
    let header_stripped = imported
        .strip_suffix(".h")
        .or_else(|| imported.strip_suffix(".hpp"))
        .or_else(|| imported.strip_suffix(".hxx"))
        .unwrap_or(imported);
    imported == needle
        || header_stripped == needle
        || imported.starts_with(&format!("{needle}/"))
        || imported.starts_with(&format!("{needle}."))
        || imported.starts_with(&format!("{needle}::"))
        // PHP namespaces use backslash separators
        // (`Cake\Datasource`, `Symfony\Component\Console`).
        || imported.starts_with(&format!("{needle}\\"))
}

#[cfg(test)]
mod tests {
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
}
