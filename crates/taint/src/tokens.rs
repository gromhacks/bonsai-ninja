use crate::{reachable::TokenSet, text::is_quoted_literal};

pub(crate) fn canonical_bare_name(text: &str) -> String {
    crate::text::normalise_qualified_text(text)
        .trim_start_matches(bonsai_common::is_name_punctuation)
        .trim()
        .to_string()
}

pub(crate) fn rhs_has_descendant_shape(source_names: &[String]) -> bool {
    let mut distinct = Vec::new();
    for name in source_names {
        let name = name.trim();
        if name.is_empty() || is_quoted_literal(name) {
            continue;
        }
        let canonical = canonical_bare_name(name);
        if canonical.is_empty() || distinct.iter().any(|existing| existing == &canonical) {
            continue;
        }
        distinct.push(canonical);
    }
    distinct.len() > 1
}

pub(crate) fn qualified_wildcard_seed_matches(normalised_text: &str, state: &TokenSet) -> bool {
    state.iter().any(|seed| {
        let Some(prefix) = seed.strip_suffix(".*") else {
            return false;
        };
        let prefix = crate::text::normalise_qualified_text(prefix);
        !prefix.is_empty()
            && (normalised_text == prefix
                || normalised_text
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('.')))
    })
}

pub(crate) fn receiver_method_projection_is_tainted(
    text: &str,
    state: &TokenSet,
    normalize_scoped_names: bool,
) -> bool {
    if receiver_method_projection_in_text_is_tainted(text, state) {
        return true;
    }
    if !normalize_scoped_names {
        return false;
    }
    let normalised = bonsai_common::normalize_qualified_name(&crate::text::normalise_qualified_text(text));
    normalised != text && receiver_method_projection_in_text_is_tainted(&normalised, state)
}

fn receiver_method_projection_in_text_is_tainted(text: &str, state: &TokenSet) -> bool {
    for open_paren in text.match_indices('(').map(|(idx, _)| idx) {
        let before_call = text[..open_paren].trim_end();
        let start = before_call
            .char_indices()
            .rev()
            .find(|&(_, c)| {
                !(c == '.'
                    || c == '_'
                    || c == '$'
                    || c == '@'
                    || c == '%'
                    || c == ']'
                    || c == '['
                    || c == '\''
                    || c == '"'
                    || c.is_ascii_alphanumeric())
            })
            .map_or(0, |(idx, c)| idx + c.len_utf8());
        let candidate = before_call[start..].trim();
        let Some((receiver, method)) = candidate.rsplit_once('.') else {
            continue;
        };
        if receiver.trim().is_empty() || method.trim().is_empty() {
            continue;
        }
        let receiver = crate::text::normalise_qualified_text(receiver);
        if !receiver.is_empty()
            && (state.contains(&receiver) || qualified_wildcard_seed_matches(&receiver, state))
        {
            return true;
        }
    }
    false
}
