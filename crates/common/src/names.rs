//! Name normalization helpers shared across crates.
//!
//! Owns the cross-crate constants for identifier sigils
//! ([`IDENTIFIER_SIGILS`]) and qualified-name separators
//! ([`QUALIFIED_NAME_SEPARATORS`]) plus the canonical
//! `short_qualified_tail`, `qualified_names_match`, and
//! `callable_reference_variants` helpers.

/// Identifier sigils used by adapters to mark scalar/array/hash
/// (`$`, `@`, `%`) variables (Perl, PHP). The engine treats `$foo`,
/// `@foo`, `%foo`, and `foo` as referring to the same identifier
/// when the sigil is missing in the queried form, since adapters
/// emit the same identifier with and without sigil depending on the
/// surrounding syntactic context.
///
/// Kept here because three crates (`bonsai_taint::text`,
/// `bonsai_taint`'s IDG compatibility API, `bonsai_security::matcher` indirectly via
/// `qualified_access_bases`) all need the same set; defining it
/// once prevents drift.
pub const IDENTIFIER_SIGILS: &[char] = &['$', '@', '%'];

/// Reference / pointer sigils that adapters keep on raw type and
/// expression text — Rust's `&` borrow, C/C++'s `*` pointer, mixed
/// usage in PHP `&$ref` and Perl. Engine code that compares names
/// strips these because `&Foo`, `*Foo`, and `Foo` denote the same
/// underlying identifier for taint and resolution purposes.
///
/// Defined alongside [`IDENTIFIER_SIGILS`] so the two sets can be
/// composed without re-listing characters at every call site.
pub const REFERENCE_SIGILS: &[char] = &['&', '*'];

/// Combined punctuation strip used at qualified-text comparison
/// sites (`actual.trim_start_matches(ALL_NAME_PUNCTUATION)`). The
/// union of [`IDENTIFIER_SIGILS`] and [`REFERENCE_SIGILS`] — adapter
/// emissions can carry either family on raw expression text and the
/// engine should normalise both before comparing.
pub const ALL_NAME_PUNCTUATION: &[char] = &['$', '@', '%', '&', '*'];

/// Qualified-name separators recognized by the workspace. `.` is the
/// universal member access; `::` is Rust/C++/Perl module separator;
/// `->` is C/C++/PHP/Perl pointer member access; `:` is Erlang
/// remote call; and `\\` is a PHP namespace separator. Order matters
/// when used by callers that try candidates in priority order — pick
/// the longer alternative first.
pub const QUALIFIED_NAME_SEPARATORS: &[&str] = &["::", "->", ".", ":", "\\"];

/// Canonical projection forms that EVERY `normalise_qualified_text`-style
/// canonicalizer must agree on. Subscript / arrow / symbol-key field
/// access all collapse to one dotted key, so the taint engine and the
/// security matcher hash `obj['x']`, `obj.x`, `obj->x`, and `obj[:x]`
/// to the same `obj.x`. There are THREE independent copies of this
/// canonicalization — the adapter kit (`bonsai_lang_api::kit::qualified`),
/// the taint engine (`bonsai_taint::text`), and the IDG transfer pass
/// (`bonsai_idg::transfer`). Each carries a conformance test asserting it
/// matches these vectors, so the copies cannot silently drift. This guards
/// the exact class of bug that shipped a real recall regression: the Ruby
/// `[:sym]` colon-strip diverging between two of the copies.
///
/// Only includes forms where all copies AGREE — i.e. no leading `&`/`*`
/// sigils or interior whitespace, which the engine copy strips but the
/// adapter copy (grammar-clean tree-sitter input) does not.
pub const PROJECTION_CANONICALIZATION_VECTORS: &[(&str, &str)] = &[
    ("obj.cmd", "obj.cmd"),
    ("obj['cmd']", "obj.cmd"),
    ("obj[\"cmd\"]", "obj.cmd"),
    ("conn->host", "conn.host"),
    ("params[:token]", "params.token"),
    ("args[:cmd]", "args.cmd"),
];

/// Filename prefix used by the VFS case-sensitivity probe.
///
/// The probe is a short-lived filesystem artifact, not source code. Consumers
/// that render raw filesystem views may hide files matching
/// [`is_bonsai_case_probe_path`], but source ingest should not broadly ignore
/// arbitrary user files that merely share this prefix.
pub const BONSAI_CASE_PROBE_PREFIX: &str = ".bonsai_case_probe_";

/// True when `path` is the exact temporary file shape created by the VFS
/// case-sensitivity probe: `.bonsai_case_probe_<pid>_<nanos>`.
///
/// This intentionally rejects names with extensions or non-numeric suffixes so
/// a user-owned file such as `.bonsai_case_probe_notes.py` is not hidden.
#[must_use]
pub fn is_bonsai_case_probe_path(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let Some(rest) = name.strip_prefix(BONSAI_CASE_PROBE_PREFIX) else {
        return false;
    };
    let Some((pid, nanos)) = rest.split_once('_') else {
        return false;
    };
    !pid.is_empty()
        && !nanos.is_empty()
        && pid.chars().all(|c| c.is_ascii_digit())
        && nanos.chars().all(|c| c.is_ascii_digit())
}

/// Tail of a qualified call/reference name.
///
/// Handles every separator in [`QUALIFIED_NAME_SEPARATORS`]. This is a
/// lexical operation over an adapter-emitted callable name; semantic
/// resolution remains the responsibility of the resolver.
#[must_use]
pub fn short_qualified_tail(name: &str) -> &str {
    let cut = QUALIFIED_NAME_SEPARATORS
        .iter()
        .filter_map(|separator| name.rfind(separator).map(|index| index + separator.len()))
        .max()
        .unwrap_or(0);
    &name[cut..]
}

/// True when two adapter-emitted qualified names are identical or
/// share the same non-empty callable tail.
///
/// Tail equality is intentionally a candidate/de-duplication rule, not
/// proof that two symbols resolve to the same declaration. Callers that
/// need symbol identity must still use the resolver.
#[must_use]
pub fn qualified_names_match(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let left_tail = short_qualified_tail(left);
    !left_tail.is_empty() && left_tail == short_qualified_tail(right)
}

/// Return normalized callable-reference spellings for language syntax
/// that passes a function as a value rather than calling it directly.
///
/// This is intentionally syntax-only. It does not decide whether the
/// value is safe, dangerous, source, sink, or sanitizer; resolver users
/// still have to prove that the returned name reaches a workspace
/// callable under the caller's semantic context.
#[must_use]
pub fn callable_reference_variants(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    push_callable_variant(&mut out, raw);

    let mut s = raw.trim();
    if s.is_empty() {
        return out;
    }

    if let Some(rest) = s.strip_prefix("fun ") {
        s = rest.trim();
        push_callable_variant(&mut out, strip_arity_suffix(s));
    }

    if let Some(rest) = s.strip_prefix('&') {
        push_callable_variant(&mut out, strip_arity_suffix(rest.trim()));
    }

    if let Some(rest) = s.strip_prefix("\\&") {
        push_callable_variant(&mut out, rest.trim());
    }

    if let Some(inner) = quoted_bare_callable(s) {
        push_callable_variant(&mut out, inner);
    }

    if let Some(inner) = method_symbol_callable(s) {
        push_callable_variant(&mut out, inner);
    }

    if let Some(trimmed) = s.strip_suffix('.') {
        push_callable_variant(&mut out, trimmed.trim());
    }

    if let Some(trimmed) = s.strip_suffix("->") {
        push_callable_variant(&mut out, trimmed.trim());
    }

    let tail = short_qualified_tail(s);
    if tail != s && !tail.is_empty() {
        push_callable_variant(&mut out, tail);
    }

    out
}

fn push_callable_variant(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() || out.iter().any(|existing| existing == value) {
        return;
    }
    out.push(value.to_string());
}

fn strip_arity_suffix(value: &str) -> &str {
    let value = value.trim();
    if let Some((name, arity)) = value.rsplit_once('/') {
        if !name.is_empty() && arity.chars().all(|c| c.is_ascii_digit()) {
            return name.trim();
        }
    }
    value
}

fn quoted_bare_callable(value: &str) -> Option<&str> {
    let value = value.trim();
    let quote = value.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || value.as_bytes().last().copied()? != quote {
        return None;
    }
    let inner = value.get(1..value.len().saturating_sub(1))?.trim();
    looks_like_callable_ident(inner).then_some(inner)
}

fn method_symbol_callable(value: &str) -> Option<&str> {
    let value = value.trim();
    let inner = value.strip_prefix("method(")?.strip_suffix(')')?.trim();
    let inner = inner.strip_prefix(':').unwrap_or(inner).trim();
    looks_like_callable_ident(inner).then_some(inner)
}

fn looks_like_callable_ident(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Per-workspace bonsai cache/state directory.
///
/// The default is an OS cache location namespaced by the canonical workspace
/// path, for example
/// `~/Library/Caches/bonsai-ninja/workspaces/project-0123abcd...` on macOS.
/// Analysis must not dirty the repository it inspects. Set
/// `BONSAI_WORKSPACE_DIR` to an exact directory when a workflow deliberately
/// wants a different location; relative overrides remain workspace-relative
/// for compatibility with earlier releases.
#[must_use]
pub fn workspace_bonsai_dir(workspace_root: &std::path::Path) -> std::path::PathBuf {
    match std::env::var_os("BONSAI_WORKSPACE_DIR") {
        Some(raw) if !raw.is_empty() => {
            let path = std::path::PathBuf::from(raw);
            if path.is_absolute() {
                path
            } else {
                workspace_root.join(path)
            }
        }
        _ => default_workspace_bonsai_dir(workspace_root, dirs::cache_dir().as_deref()),
    }
}

fn default_workspace_bonsai_dir(
    workspace_root: &std::path::Path,
    system_cache_root: Option<&std::path::Path>,
) -> std::path::PathBuf {
    let identity = workspace_root.canonicalize().unwrap_or_else(|_| {
        if workspace_root.is_absolute() {
            workspace_root.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(workspace_root))
                .unwrap_or_else(|_| workspace_root.to_path_buf())
        }
    });
    let mut hasher = bonsai_hash::Hasher::new();
    hasher.absorb(identity.to_string_lossy().as_bytes());
    let digest = hasher.finish();
    let slug = identity
        .file_name()
        .and_then(|name| name.to_str())
        .map(workspace_cache_slug)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "workspace".to_string());
    system_cache_root
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir)
        .join("bonsai-ninja")
        .join("workspaces")
        .join(format!("{slug}-{digest:016x}"))
}

fn workspace_cache_slug(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .take(48)
        .collect()
}

#[cfg(test)]
#[path = "names_tests.rs"]
mod tests;
