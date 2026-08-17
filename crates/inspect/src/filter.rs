//! `inspect --from` / `--to` / `--from-kind` / `--to-kind` filter
//! engine.
//!
//! The filter is deliberately **flow-connected only**: a chain passes
//! if the needle lands somewhere that is syntactically AND by data
//! flow connected to the chain's endpoints. Three signals, all
//! "connected" by construction:
//!
//! 1. **hit_text** — the rendered hit (decl / call / var / string /
//!    etc.) the chain was enumerated for. The needle matches here
//!    when the user is filtering on the endpoint itself.
//!
//! 2. **chain function names** — the names of the functions on the
//!    call-chain path from entry to target. These are syntactically
//!    connected by definition (they're the chain).
//!
//! 3. **taint facts** — [`KindedTokens`] produced by the
//!    interprocedural taint pass for the chain's entry. The needle
//!    matches here when a tainted value named like the needle
//!    actually propagates through this chain. `--from-kind` /
//!    `--to-kind` filter this by fact kind (arg, call, decl, ...).
//!
//! What is deliberately NOT a signal: tokens merely lexically visible
//! in the chain's files (imports, unrelated decls, class names). Two
//! unrelated modules imported in the same file don't imply a flow
//! between them. The old "reachability" signal was removed — it
//! produced false-positive chains that matched only because the two
//! needles happened to be imported somewhere nearby.
//!
//! Two pieces remain on the surface:
//!
//! - [`name_token_match`] — case-insensitive token-boundary substring
//!   match. Defines what counts as "the needle appears in the
//!   haystack": `os` matches `os.system` but not `conn.close`,
//!   `req` matches `handleRequest` but not `acquire`.
//!
//! - [`chain_matches_filters`] — the per-chain decision: given the
//!   hit's text, the chain's function names, and a lazy producer for
//!   the entry's taint facts, does the chain pass the active filters?

use bonsai_taint::KindedTokens;
use std::sync::Arc;

/// Browse-fact kinds the `--from-kind` / `--to-kind` flags accept.
/// Mirror of [`bonsai_taint::FactKind`] with stable, public spellings
/// so any frontend (CLI, MCP, LSP) can use the same enum.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FactKindFilter {
    Decl,
    Call,
    Read,
    Write,
    Arg,
    StringLit,
    Import,
    Class,
}

impl FactKindFilter {
    /// Project to the underlying [`bonsai_taint::FactKind`] used in
    /// [`KindedTokens::by_kind`] lookups.
    #[must_use]
    pub fn to_taint_kind(self) -> bonsai_taint::FactKind {
        match self {
            Self::Decl => bonsai_taint::FactKind::Decl,
            Self::Call => bonsai_taint::FactKind::Call,
            Self::Read => bonsai_taint::FactKind::Read,
            Self::Write => bonsai_taint::FactKind::Write,
            Self::Arg => bonsai_taint::FactKind::Arg,
            Self::StringLit => bonsai_taint::FactKind::StringLit,
            Self::Import => bonsai_taint::FactKind::Import,
            Self::Class => bonsai_taint::FactKind::Class,
        }
    }
}

/// Stable, library-level mirror of `bonsai_common::Precision`. Frontends
/// may still parse broad legacy labels, but public flow/call surfaces
/// are semantic-only: only exact and narrowed classes can match.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrecisionFilter {
    /// `Precision::Exact` — structural facts; no approximation.
    Exact,
    /// `Precision::Narrowed` — single-candidate resolved call.
    Narrowed,
    /// `Precision::OverApproximate` — diagnostic-only broad edges.
    OverApproximate,
    /// `Precision::Unknown` — diagnostic-only opaque edges.
    Unknown,
}

impl PrecisionFilter {
    #[must_use]
    pub fn matches(self, precision: bonsai_common::Precision) -> bool {
        use bonsai_common::Precision;
        matches!(
            (self, precision),
            (Self::Exact, Precision::Exact) | (Self::Narrowed, Precision::Narrowed),
        )
    }
}

#[cfg(test)]
#[path = "filter_tests.rs"]
mod tests;

/// Active inspect filters. All needles are substring patterns matched
/// against the visible tokens of a rendered chain (or the hit's own
/// text). `_kind` variants narrow the match to a single browse-fact
/// kind so `--from-kind read` only fires when the needle appears as
/// a read reference (not as a call name, import, or string).
#[derive(Copy, Clone, Default, Debug)]
pub struct InspectFilters<'a> {
    pub from: Option<&'a str>,
    pub from_kind: Option<FactKindFilter>,
    pub to: Option<&'a str>,
    pub to_kind: Option<FactKindFilter>,
    pub file: Option<&'a str>,
    pub in_fn: Option<&'a str>,
}

/// Concrete hit evidence supplied to [`chain_matches_filters_for_hit`].
/// The text alone is not enough when `--from-kind` / `--to-kind` is
/// active: `model = pickle.loads` contains `pickle`, but the hit itself
/// is a write, not a call.
#[derive(Copy, Clone, Debug)]
pub struct FilterHit<'a> {
    pub text: &'a str,
    pub kind: Option<FactKindFilter>,
}

impl<'a> FilterHit<'a> {
    #[must_use]
    pub fn new(text: &'a str, kind: FactKindFilter) -> Self {
        Self {
            text,
            kind: Some(kind),
        }
    }

    #[must_use]
    pub fn untyped(text: &'a str) -> Self {
        Self { text, kind: None }
    }
}

/// Case-insensitive "word-boundary" match: the needle matches the
/// haystack if it appears as a prefix of some identifier token.
/// Tokens are split on non-alphanumeric characters (`.`, `_`, space,
/// etc.) AND lower→upper camel-case transitions. So:
///
///   * `os`  matches `os.system`   (token `os` starts with `os`)
///   * `os`  matches `OsConfig`    (token `Os` starts with `os`)
///   * `os`  does NOT match `conn.close` (no token starts with `os`)
///   * `req` matches `request`, `handleRequest`, `handle_request`
///   * `req` does NOT match `acquire` (middle of a word)
///
/// This gives fuzzy matching the user wants (short prefixes find
/// long names) without the "substring of a substring" false-
/// positives that plain `.contains()` creates (e.g. `os` ⊂ `close`).
#[must_use]
pub fn name_token_match(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle_lower = needle.to_lowercase();
    let haystack_bytes = haystack.as_bytes();
    let haystack_len = haystack_bytes.len();
    let needle_len = needle_lower.len();
    if needle_len > haystack_len {
        return false;
    }
    // A position counts as a token boundary when the previous char isn't
    // alphanumeric (separator-style) OR when we're at a camelCase hump
    // (lowercase-or-digit followed by uppercase).
    let is_boundary = |byte_index: usize| -> bool {
        if byte_index == 0 {
            return true;
        }
        if !haystack.is_char_boundary(byte_index) {
            return false;
        }
        let prev_byte = haystack_bytes[byte_index - 1];
        let current_byte = haystack_bytes[byte_index];
        if !prev_byte.is_ascii_alphanumeric() {
            return true;
        }
        let prev_is_lower_or_digit = prev_byte.is_ascii_lowercase() || prev_byte.is_ascii_digit();
        let current_is_upper = current_byte.is_ascii_uppercase();
        prev_is_lower_or_digit && current_is_upper
    };
    for candidate_start in 0..=(haystack_len - needle_len) {
        if !is_boundary(candidate_start) {
            continue;
        }
        // Ensure the slice end falls on a char boundary too (multi-byte UTF-8).
        if !haystack.is_char_boundary(candidate_start + needle_len) {
            continue;
        }
        if haystack[candidate_start..candidate_start + needle_len].eq_ignore_ascii_case(&needle_lower) {
            return true;
        }
    }
    false
}

/// Apply `--from` / `--to` filters to one bounded structural evidence unit.
///
/// `taint_facts` is a closure so callers skip the interprocedural
/// pass when `hit_text` / `chain_func_names` already decide the match
/// (huge speedup on large workspaces). With both `--from` and `--to`,
/// the hit must be one endpoint and the other must be flow-connected;
/// with only one, it must appear in any of the three signals
/// (hit text / chain function name / taint fact). See SPEC §12.
pub fn chain_matches_filters(
    hit_text: Option<&str>,
    chain_func_names: &[String],
    taint_facts: &dyn Fn() -> Arc<KindedTokens>,
    filters: InspectFilters<'_>,
) -> bool {
    let hit = hit_text.map(FilterHit::untyped);
    chain_matches_filters_for_hit(hit, chain_func_names, taint_facts, filters)
}

/// Typed variant of [`chain_matches_filters`]. Prefer this when the
/// caller knows the browse-fact kind of the rendered hit.
pub fn chain_matches_filters_for_hit(
    hit: Option<FilterHit<'_>>,
    chain_func_names: &[String],
    taint_facts: &dyn Fn() -> Arc<KindedTokens>,
    filters: InspectFilters<'_>,
) -> bool {
    let hit_matches = |needle: &str, kind: Option<FactKindFilter>| -> bool {
        hit.is_some_and(|hit| {
            kind.is_none_or(|kind| hit.kind == Some(kind)) && name_token_match(hit.text, needle)
        })
    };
    let chain_name_matches = |needle: &str, kind: Option<FactKindFilter>| -> bool {
        kind.is_none_or(|kind| kind == FactKindFilter::Decl)
            && chain_func_names.iter().any(|n| name_token_match(n, needle))
    };
    let tokens_contain = |tokens: &KindedTokens, needle: &str, kind: Option<FactKindFilter>| -> bool {
        match kind {
            Some(kind_filter) => tokens
                .by_kind
                .get(&kind_filter.to_taint_kind())
                .is_some_and(|t| t.iter().any(|s| name_token_match(s, needle))),
            None => tokens
                .by_kind
                .values()
                .any(|t| t.iter().any(|s| name_token_match(s, needle))),
        }
    };
    let taint_matches = |needle: &str, kind: Option<FactKindFilter>| -> bool {
        let tokens = taint_facts();
        tokens_contain(&tokens, needle, kind)
    };
    // Match if the needle lands on this exact call path: hit text,
    // a chain hop / tail callee, or a propagated taint fact.
    let taint_or_hit = |needle: &str, kind: Option<FactKindFilter>| -> bool {
        hit_matches(needle, kind) || chain_name_matches(needle, kind) || taint_matches(needle, kind)
    };
    match (filters.from, filters.to) {
        (None, None) => true,
        (Some(from), None) => taint_or_hit(from, filters.from_kind),
        (None, Some(to)) => taint_or_hit(to, filters.to_kind),
        (Some(from), Some(to)) => {
            let hit_from = hit_matches(from, filters.from_kind);
            let hit_to = hit_matches(to, filters.to_kind);
            if !hit_from && !hit_to {
                return false;
            }
            if hit_from && hit_to {
                return true;
            }
            if hit_from {
                taint_or_hit(to, filters.to_kind)
            } else {
                taint_or_hit(from, filters.from_kind)
            }
        }
    }
}
