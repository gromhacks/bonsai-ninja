//! Name normalization helpers shared across crates.
//!
//! Owns the cross-crate constants for identifier sigils
//! ([`IDENTIFIER_SIGILS`]) and qualified-name separators
//! ([`QUALIFIED_NAME_SEPARATORS`]) plus the canonical
//! `short_qualified_tail` and `callable_reference_variants` helpers.

/// Identifier sigils used by adapters to mark scalar/array/hash
/// (`$`, `@`, `%`) variables (Perl, PHP). The engine treats `$foo`,
/// `@foo`, `%foo`, and `foo` as referring to the same identifier
/// when the sigil is missing in the queried form, since adapters
/// emit the same identifier with and without sigil depending on the
/// surrounding syntactic context.
///
/// Kept here because three crates (`bonsai_taint::text`,
/// `bonsai_taint::inter`, `bonsai_security::matcher` indirectly via
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
/// remote call. Order matters when used by callers that try
/// candidates in priority order — pick the longer alternative first.
pub const QUALIFIED_NAME_SEPARATORS: &[&str] = &["::", "->", ".", ":"];

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

/// Implicit-receiver prefixes recognized across object-oriented
/// languages: `self.` (Python / Ruby / Rust), `this.` (Java / Kotlin
/// / JS / TS / C# / Dart / Swift / PHP). Engine code that needs to
/// detect "is this a method call on the implicit receiver" walks
/// this list rather than enumerating language keywords inline. The
/// list is the union — adapters that don't use a given prefix never
/// emit text starting with it.
pub const IMPLICIT_RECEIVER_PREFIXES: &[&str] = &["self.", "this."];

/// Bare implicit-receiver tokens (the [`IMPLICIT_RECEIVER_PREFIXES`]
/// entries minus the trailing `.`). Used at sites that compare a
/// receiver *expression* for equality with the implicit-receiver
/// keyword — not a prefix match against a dotted call.
pub const IMPLICIT_RECEIVER_TOKENS: &[&str] = &["self", "this"];

/// Super / parent receiver tokens used to dispatch into a base
/// class. `super` covers Java / Kotlin / JS / TS / Python / Ruby /
/// Swift / Dart / Scala; `parent` and `self` cover PHP's
/// `parent::method` and `self::method` qualifiers; `base` covers
/// C# and Lua; `SUPER` (case-sensitive) covers Perl's
/// `$self->SUPER::method()`. The set is the union of
/// receiver-equality tokens for the cross-language
/// `is_super_receiver` predicate; adapters that want to narrow
/// further declare their own `super_receiver_tokens` slice in
/// `LanguageCapabilities` and the engine prefers
/// `effective_super_receiver_tokens()` when the adapter is known.
pub const SUPER_RECEIVER_TOKENS: &[&str] = &["super", "parent", "base", "SUPER"];

/// Absolute-path prefixes that adapters may surface on
/// fully-qualified call names — Rust's `crate::` (this crate's
/// root) and `self::` (current module), PHP / C++ leading `\` and
/// `::` (global namespace). Used by the resolver's
/// workspace-rooted call lookup to peel off the absolute-path mark
/// before splitting on a module separator.
///
/// `super::` is *not* listed here because it can repeat (`super::super::foo`);
/// the resolver iterates `super::` strips separately and handles
/// non-repeatable prefixes via this list.
///
/// Files only use one language at a time, so a Rust prefix never
/// appears on PHP source and vice versa — the list is safe to
/// apply without per-language gating.
pub const ABSOLUTE_PATH_PREFIXES: &[&str] = &["crate::", "self::", "::", "\\"];

/// Statement / expression keyword prefixes that adapters can include
/// on raw `FlowEvent::Return.value_text` — the leading `return ` of
/// a return statement and the constructor `new ` of object-creation
/// expressions in C-family languages. The engine peels these
/// defensively so dispatch helpers see the bare expression
/// (`Foo()`, `Bar.baz()`) regardless of how the adapter shaped the
/// raw text.
///
/// Adapters that use `bonsai_lang_api::kit::extract_return_value_text`
/// already get clean text — this list exists so engine sites that
/// receive less-processed text (factory-method inference,
/// constructor-shape detection) don't have to enumerate the
/// keywords inline.
pub const VALUE_TEXT_LEADING_KEYWORDS: &[&str] = &["return ", "new "];

/// Self-typed constructor expressions used by Rust (`Self`, `self`)
/// and PHP late static binding (`static`). When an adapter emits a
/// return value of the form `Self { ... }`, `Self(...)`, `self(...)`,
/// or `new static(...)`, the engine treats it as a class-typed
/// constructor return for dispatch.
pub const SELF_CONSTRUCTOR_HEADS: &[&str] = &["Self(", "Self {", "self(", "static("];

/// Canonical constructor method names across the supported
/// languages. Used as a *fallback* when a class's
/// `DeclKind::Constructor` lookup misses — adapters that don't (or
/// can't) tag their constructor decls structurally still emit the
/// method by one of these well-known names:
///
/// - `__init__` — Python.
/// - `constructor` — JavaScript / TypeScript class syntax.
/// - `__construct` — PHP magic method.
/// - `init` — Swift / Objective-C.
/// - `new` — Ruby idiom, PHP factory convention.
pub const CONSTRUCTOR_METHOD_NAMES: &[&str] = &["__init__", "constructor", "__construct", "init", "new"];

/// True when `value_text` returns a self-typed constructor
/// expression — Rust `Self(...)` / `Self { ... }` / `self(...)`,
/// PHP `new static(...)` late static binding. Both the taint
/// engine and the callgraph need to recognise this shape so a
/// `return Self::new(...)` body resolves to its enclosing class's
/// constructor; the helper lives here so both crates share one
/// source of truth.
#[must_use]
pub fn value_text_returns_self_constructor(value_text: &str) -> bool {
    let mut text = value_text.trim();
    text = text.strip_prefix("return ").unwrap_or(text).trim();
    if SELF_CONSTRUCTOR_HEADS.iter().any(|head| text.starts_with(*head)) {
        return true;
    }
    matches!(
        text.strip_prefix("new ").map(str::trim),
        Some(rest) if SELF_CONSTRUCTOR_HEADS.iter().any(|head| rest.starts_with(*head))
    )
}

/// Tail of a qualified call/reference name.
///
/// Handles the separators emitted by supported adapters: dotted
/// namespaces, Rust/C++ `::`, pointer/member `->`, and Erlang-style
/// single `:` module calls. The single-colon case deliberately ignores
/// the second byte of `::`.
#[must_use]
pub fn short_qualified_tail(name: &str) -> &str {
    let last_dot = name.rfind('.').map(|i| i + 1).unwrap_or(0);
    let last_double_colon = name.rfind("::").map(|i| i + 2).unwrap_or(0);
    let last_arrow = name.rfind("->").map(|i| i + 2).unwrap_or(0);
    let last_single_colon = name
        .rfind(':')
        .filter(|&i| {
            let bytes = name.as_bytes();
            !(i > 0 && bytes[i - 1] == b':')
        })
        .map(|i| i + 1)
        .unwrap_or(0);
    let cut = last_dot
        .max(last_double_colon)
        .max(last_arrow)
        .max(last_single_colon);
    &name[cut..]
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

/// Repository-local bonsai state directory.
///
/// Defaults to `<workspace>/.bonsai`. `BONSAI_WORKSPACE_DIR` may point
/// at an alternate directory; relative values are resolved under the
/// workspace root so each project can still keep isolated state.
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
        _ => workspace_root.join(".bonsai"),
    }
}

#[cfg(test)]
#[path = "names_tests.rs"]
mod tests;
