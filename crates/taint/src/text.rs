//! Vocabulary-free helpers for compiler-classified names carried by taint IR.

/// Canonicalize an adapter-emitted name/place through the structural compiler
/// name contract. Source-language projection and subscript syntax must already
/// have been lowered by the owning adapter; the taint engine never reparses it.
pub(crate) fn normalise_qualified_text(text: &str) -> String {
    let text = bonsai_common::trim_leading_name_punctuation(text.trim());
    bonsai_common::normalize_qualified_name(text)
}

/// Return bare bases of qualified/member-access expressions mentioned
/// in `text`. This lets taint token fallbacks ignore the carrier token
/// in `obj.field` / `obj->field` while still seeing independent
/// operands in compound expressions such as `obj.field + user`.
pub(crate) fn qualified_access_bases(text: &str) -> Vec<String> {
    let mut bases = Vec::new();
    // Compiler places normalize source-language separators before the engine
    // scans them. This catches member, subscript, and mixed projections
    // without carrying a second source-syntax inventory in taint.
    let normalised = normalise_qualified_text(text);
    collect_qualified_access_bases(&normalised, &mut bases);
    bases
}

/// Tokenise `text` into identifier-like segments and append each
/// segment's base (everything before its first `.`) to `bases`.
fn collect_qualified_access_bases(text: &str, bases: &mut Vec<String>) {
    let mut segment = String::new();
    // Trailing space flushes the final segment without a special case.
    for ch in text.chars().chain(std::iter::once(' ')) {
        if ch == '.' || ch == '_' || ch == '$' || ch == '@' || ch == '%' || ch.is_ascii_alphanumeric() {
            segment.push(ch);
            continue;
        }
        push_qualified_base(&segment, bases);
        segment.clear();
    }
}

/// Push the dotted-base of one identifier segment, plus its
/// sigil-stripped form so callers indexing on the bare name still hit.
fn push_qualified_base(segment: &str, bases: &mut Vec<String>) {
    // Bare segments without a dot aren't qualified accesses — skip them.
    let Some((base, _)) = segment.split_once('.') else {
        return;
    };
    let base = base.trim();
    if base.is_empty() {
        return;
    }
    // Strip leading `&` / `*` so `&obj.x` and `obj.x` produce the same base.
    let base = base.trim_start_matches(bonsai_common::is_name_punctuation);
    if base.is_empty() {
        return;
    }
    if !bases.iter().any(|existing| existing == base) {
        bases.push(base.to_string());
    }
    // Also surface the sigil-stripped base (e.g. `$user` -> `user`)
    // so callers indexing on the bare name still match.
    let sigil_stripped = base.trim_start_matches(bonsai_common::is_name_punctuation);
    if sigil_stripped != base
        && !sigil_stripped.is_empty()
        && !bases.iter().any(|existing| existing == sigil_stripped)
    {
        bases.push(sigil_stripped.to_string());
    }
}

/// True when an adapter-emitted compiler name has a structural owner.
pub(crate) fn text_looks_qualified(text: &str) -> bool {
    bonsai_common::qualified_name_owner(text.trim()).is_some()
}

/// True when `text` is exactly one quoted literal, not merely an
/// expression whose first and last tokens happen to be string
/// literals. Concats such as `"<p>" .. q .. "</p>"`,
/// `"<p>" <> q <> "</p>"`, and `"<p>" + q + "</p>"` must return
/// false so identifier-token taint checks can see `q`.
pub(crate) fn is_quoted_literal(text: &str) -> bool {
    let trimmed = text.trim();
    let mut chars = trimmed.char_indices();
    // First non-whitespace char must be a string-literal opener.
    let Some((_, quote @ ('"' | '\'' | '`'))) = chars.next() else {
        return false;
    };
    let mut escaped = false;
    for (offset, ch) in chars {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        // Closing quote at the very end means the whole input is one literal.
        if ch == quote {
            return offset + ch.len_utf8() == trimmed.len();
        }
    }
    false
}

#[cfg(test)]
#[path = "text_tests.rs"]
mod tests;
