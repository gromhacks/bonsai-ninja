//! Shared package-name matching used by both the dependency
//! inventory (`deps.rs`) and the per-file package context gate
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
    // Node.js builtin modules can be imported with an explicit
    // `node:` scheme (`require("node:child_process")`,
    // `import "node:fs/promises"`). Rules key on the bare builtin name
    // (`child_process`, `fs`), so strip the scheme before matching —
    // otherwise modern Node code that uses the prefixed form silently
    // bypasses every builtin-module package gate.
    let imported = imported.strip_prefix("node:").unwrap_or(imported);
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

/// Go-style path packages (`os/exec`, `net/http`, `github.com/x/gin`) bind
/// the LAST `/`-segment as the local qualifier (`exec.Command`,
/// `http.Get`, `gin.New`). A fully-qualified call therefore exposes only
/// that bare segment as its package candidate, which the prefix matcher in
/// `import_matches_package` (it only handles `needle`-prefixed forms)
/// misses — so `exec.Command(tainted)` with no in-file import stayed dark
/// (WS1 FQN-no-import). This credits the gate when a CALL CANDIDATE equals
/// the package's last path segment. Scoped to the candidate direction
/// (call qualifier / receiver-type / alias target) — never used for real
/// import-spec matching, so a bare local module named `exec` cannot
/// spoof `os/exec`. Single-segment packages (`os`, `flask`) return false
/// here; they are already covered by `import_matches_package`.
pub(crate) fn call_candidate_matches_package_tail(candidate: &str, needle: &str) -> bool {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return false;
    }
    // EXCLUDE npm scoped packages (`@prisma/client`, `@hapi/hapi`): their
    // last segment (`client`, `hapi`) is a generic word, and the package
    // is bound to a CHOSEN name (`const Hapi = require("@hapi/hapi")`), not
    // the tail — so tail-matching there would credit any `client.x(...)`
    // without an import, loosening the gate. Go path packages don't use
    // `@`, so this keeps the WS1 fix to the case it's sound for.
    if needle.starts_with('@') {
        return false;
    }
    let Some((needle_head, needle_tail)) = needle.rsplit_once('/') else {
        return false;
    };
    if needle_head.is_empty() || needle_tail.is_empty() {
        return false;
    }
    // The candidate is the call's qualifier — either the bare binding
    // (`exec`) or the whole qualified callee (`exec.Command`). Compare its
    // leading segment (`exec`) to the package's last path segment.
    let candidate_head = candidate
        .split(['.', ':'])
        .next()
        .unwrap_or(candidate)
        .trim();
    !candidate_head.is_empty() && candidate_head == needle_tail
}

#[cfg(test)]
#[path = "pkg_tests.rs"]
mod tests;
