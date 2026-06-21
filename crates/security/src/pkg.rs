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
        || starts_with_package_sep(imported, needle, b'/')
        || starts_with_package_sep(imported, needle, b'.')
        || starts_with_package_str_sep(imported, needle, "::")
        // PHP namespaces use backslash separators
        // (`Cake\Datasource`, `Symfony\Component\Console`).
        || starts_with_package_sep(imported, needle, b'\\')
        // Perl method calls separate the package qualifier from the method
        // with `->` (`Net::HTTP->new`, `LWP::UserAgent->new`). The
        // qualifier before `->` IS the exact package, so a fully-qualified
        // call credits the gate even with no `use` — precise, no widening
        // beyond the named package.
        || starts_with_package_str_sep(imported, needle, "->")
}

fn starts_with_package_sep(imported: &str, needle: &str, sep: u8) -> bool {
    let imported = imported.as_bytes();
    let needle = needle.as_bytes();
    imported.len() > needle.len() && imported.starts_with(needle) && imported.get(needle.len()) == Some(&sep)
}

fn starts_with_package_str_sep(imported: &str, needle: &str, sep: &str) -> bool {
    imported.len() > needle.len() + sep.len()
        && imported.starts_with(needle)
        && imported[needle.len()..].starts_with(sep)
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
    let candidate_head = candidate.split(['.', ':']).next().unwrap_or(candidate).trim();
    !candidate_head.is_empty() && candidate_head == needle_tail
}

/// Extract the package prefix from a Java-like fully-qualified type or
/// constructor/call reference. Examples:
///
/// - `javax.naming.directory.InitialDirContext` -> `javax.naming.directory`
/// - `new javax.naming.directory.InitialDirContext` -> `javax.naming.directory`
/// - `org.example.Factory.create` -> `org.example`
///
/// The heuristic is intentionally syntax-only: Java/Kotlin/Scala package
/// segments conventionally begin lowercase, while type segments begin
/// uppercase. If every segment is lowercase, there is no type boundary and
/// the string is not accepted as FQN package evidence.
pub(crate) fn java_like_fully_qualified_package(name: &str) -> Option<&str> {
    let trimmed = name.trim().strip_prefix("new ").unwrap_or(name.trim());
    if !trimmed.contains('.') {
        return None;
    }
    let mut offset = 0usize;
    let mut saw_lowercase_package_segment = false;
    for segment in trimmed.split('.') {
        if segment.is_empty() {
            return None;
        }
        let first = segment.chars().next()?;
        if first.is_ascii_uppercase() {
            return saw_lowercase_package_segment
                .then_some(trimmed[..offset.saturating_sub(1)].trim_end_matches('.'));
        }
        if !segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
        {
            return None;
        }
        if !first.is_ascii_lowercase() {
            return None;
        }
        saw_lowercase_package_segment = true;
        offset += segment.len() + 1;
    }
    None
}

#[cfg(test)]
#[path = "pkg_tests.rs"]
mod tests;
