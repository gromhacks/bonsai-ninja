//! Text helpers shared by the intraprocedural and interprocedural taint
//! passes. Kept as a tiny private module so dotted-form normalisation
//! stays consistent wherever call-site argument text is matched
//! against tainted seeds.

/// `env['cmd']` → `env.cmd` — canonicalise subscript syntax to dotted
/// so taint-state lookup is consistent regardless of the caller's
/// source syntax.
///
/// ## Two-variant invariant
///
/// This is the **engine-side** normalizer. There is also an
/// adapter-side variant at `bonsai_lang_api::kit::qualified::normalise_qualified_text`
/// which is intentionally simpler. The two functions are NOT
/// interchangeable because their inputs have different invariants:
///
/// | Property                | Engine variant (this) | Adapter variant            |
/// |-------------------------|------------------------|----------------------------|
/// | Nested brackets         | tracked via i64 depth | bool flag (incorrect on nesting) |
/// | Whitespace adjacent to `.` | stripped           | preserved                  |
/// | Leading `&` / `*`       | stripped              | preserved                  |
/// | Underflow safety        | saturating            | (n/a — no depth)           |
/// | Input shape             | engine-derived text  | tree-sitter node text      |
///
/// The adapter-side version takes input from `node_text(...)` which
/// is grammar-clean: no nested brackets in qualified-target shapes
/// (the tree-sitter parser produces a `subscript_expression` for
/// each level). The engine-side input comes from FlowEvent texts
/// that may have been concatenated, sigil-stripped, or aliased, so
/// it needs the richer machinery.
///
/// **Do not** unify them. The simpler version would silently
/// truncate engine-input edge cases; the richer version would
/// over-process clean tree-sitter output.
pub(crate) fn normalise_qualified_text(text: &str) -> String {
    let mut normalised = String::with_capacity(text.len());
    // Depth (not flag) so nested subscripts like `a[b[c]+'d']` keep
    // treating the inner `'d'` as in-bracket string punctuation.
    // Signed type so malformed input (`]]]aaa[[[`) can't pin a
    // u32 counter at MAX and silently swallow every later quote.
    let mut bracket_depth: i64 = 0;
    let mut chars = text.trim().chars().peekable();
    // Strip leading address-of / dereference sigils so `&obj.x` and
    // `*obj.x` normalise to the same key as `obj.x`.
    while matches!(chars.peek(), Some('&' | '*')) {
        chars.next();
    }
    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {
                let next_non_ws = chars.clone().find(|next| !next.is_whitespace());
                // Drop whitespace adjacent to `.` so `obj . field` collapses to `obj.field`.
                if normalised.ends_with('.') || matches!(next_non_ws, Some('.')) {
                    continue;
                }
                normalised.push(ch);
            }
            '-' if matches!(chars.peek(), Some('>')) => {
                // Map C-style `->` to dotted form to share one lookup key.
                chars.next();
                normalised.push('.');
            }
            '[' => {
                bracket_depth = bracket_depth.saturating_add(1);
                normalised.push('.');
            }
            ']' => {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
                // Unmatched `]` is silently absorbed; no underflow.
            }
            // Quotes inside brackets are subscript-key punctuation, not identifier text.
            '\'' | '"' if bracket_depth > 0 => {}
            // Ruby / Elixir symbol-key sigil inside a subscript
            // (`params[:token]`) is punctuation too — drop it so the
            // key normalises to `params.token`, matching the kit's
            // adapter-side `normalise_qualified_text` and the field
            // seed spelling a rule author writes (`params.token`).
            ':' if bracket_depth > 0 => {}
            _ => normalised.push(ch),
        }
    }
    normalised.trim_matches('.').to_string()
}

/// Return bare bases of qualified/member-access expressions mentioned
/// in `text`. This lets taint token fallbacks ignore the carrier token
/// in `obj.field` / `obj->field` while still seeing independent
/// operands in compound expressions such as `obj.field + user`.
pub(crate) fn qualified_access_bases(text: &str) -> Vec<String> {
    let mut bases = Vec::new();
    // Pass 1: scan the raw text with `->` rewritten so C/PHP-style bases register.
    collect_qualified_access_bases(&text.replace("->", "."), &mut bases);
    // Pass 2: scan the normalised form to catch subscript / mixed cases the raw scan misses.
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
    let base = base.trim_start_matches(bonsai_common::REFERENCE_SIGILS);
    if base.is_empty() {
        return;
    }
    if !bases.iter().any(|existing| existing == base) {
        bases.push(base.to_string());
    }
    // Also surface the sigil-stripped base (e.g. `$user` -> `user`)
    // so callers indexing on the bare name still match.
    let sigil_stripped = base.trim_start_matches(bonsai_common::IDENTIFIER_SIGILS);
    if sigil_stripped != base
        && !sigil_stripped.is_empty()
        && !bases.iter().any(|existing| existing == sigil_stripped)
    {
        bases.push(sigil_stripped.to_string());
    }
}

/// True when `text` syntactically looks like a qualified or
/// subscripted access (`obj.field`, `obj['k']`, `obj->field`).
/// Used by the intraprocedural and assignment passes to gate
/// descendant-token bookkeeping; bare identifiers take a different
/// fast path.
pub(crate) fn text_looks_qualified(text: &str) -> bool {
    text.contains('.') || text.contains('[') || text.contains("->")
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

/// Remove operands of value-free type/size operators before the loose
/// identifier-token fallback runs. These constructs mention identifiers in
/// source text, but they do not read the identifier's attacker-controlled
/// runtime value. Without this, `sizeof(user) * cap` looks tainted because the
/// tokenizer sees `user`, even though the runtime value controlling the size is
/// `cap`.
pub(crate) fn value_bearing_identifier_text(text: &str) -> String {
    // Operators whose operand mentions an identifier without reading
    // its runtime value. C's `sizeof`, C#'s `nameof`, etc.
    const PAREN_OPERATORS: &[&str] = &[
        "sizeof",
        "_Alignof",
        "alignof",
        "__alignof__",
        "__typeof__",
        "typeof",
        "nameof",
    ];

    let mut sanitised = String::with_capacity(text.len());
    let mut cursor = 0;
    while cursor < text.len() {
        if let Some(operator) = keyword_at(text, cursor, PAREN_OPERATORS) {
            let mut after_keyword = cursor + operator.len();
            // C++ pack expansion: `sizeof...(pack)` — consume the `...` before parens.
            if operator == "sizeof" && text[after_keyword..].starts_with("...") {
                after_keyword += 3;
            }
            let after_ws = skip_ws(text, after_keyword);
            if text[after_ws..].starts_with('(') {
                // Parenthesised form — drop the entire balanced operand region.
                sanitised.push_str(operator);
                sanitised.push(' ');
                cursor = skip_balanced_parens(text, after_ws);
                continue;
            }
            // C-style `sizeof expr` and `typeof expr` accept a unary operand sans parens.
            if operator == "sizeof" || operator == "typeof" {
                sanitised.push_str(operator);
                sanitised.push(' ');
                cursor = skip_unary_operand(text, after_ws);
                continue;
            }
        }

        // No operator matched here — copy one char verbatim and advance.
        let Some(ch) = text[cursor..].chars().next() else {
            break;
        };
        sanitised.push(ch);
        cursor += ch.len_utf8();
    }
    sanitised
}

/// Return the keyword at `offset` if one of `keywords` matches with
/// identifier boundaries on both sides — so `sizeof_a` doesn't match `sizeof`.
fn keyword_at<'a>(text: &str, offset: usize, keywords: &'a [&'a str]) -> Option<&'a str> {
    keywords.iter().copied().find(|keyword| {
        text[offset..].starts_with(keyword)
            // Boundary before: start-of-string or non-identifier byte.
            && (offset == 0 || !is_ident_byte(text.as_bytes()[offset - 1]))
            // Boundary after: end-of-string or non-identifier byte.
            && text
                .as_bytes()
                .get(offset + keyword.len())
                .is_none_or(|byte| !is_ident_byte(*byte))
    })
}

/// True when `byte` could appear inside an identifier (alphanumeric, `_`, `$`).
fn is_ident_byte(byte: u8) -> bool {
    byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric()
}

/// Advance `offset` past any leading whitespace and return the new position.
fn skip_ws(text: &str, mut offset: usize) -> usize {
    while let Some(ch) = text[offset..].chars().next() {
        if !ch.is_whitespace() {
            break;
        }
        offset += ch.len_utf8();
    }
    offset
}

/// Advance past a balanced `(...)` group starting at `open_pos`,
/// honouring quotes and escapes so `f("(")` doesn't close early.
fn skip_balanced_parens(text: &str, open_pos: usize) -> usize {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut cursor = open_pos;
    while cursor < text.len() {
        let Some(ch) = text[cursor..].chars().next() else {
            break;
        };
        cursor += ch.len_utf8();
        if let Some(open_quote) = quote {
            // Inside a string literal — track escapes and the closing quote.
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' => depth += 1,
            ')' => {
                // Saturating sub guards against malformed input where `)` outruns `(`.
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return cursor;
                }
            }
            _ => {}
        }
    }
    // Unterminated parens — consume to end so the caller doesn't loop.
    text.len()
}

/// Skip a unary operand after `sizeof` / `typeof` without parens —
/// optional unary prefixes followed by a parenthesised group or a
/// bare identifier.
fn skip_unary_operand(text: &str, mut offset: usize) -> usize {
    offset = skip_ws(text, offset);
    // Consume any number of unary prefixes (`*p`, `-x`, `!!flag`, etc.).
    while let Some(ch) = text[offset..].chars().next() {
        if matches!(ch, '*' | '&' | '+' | '-' | '!' | '~') {
            offset += ch.len_utf8();
            offset = skip_ws(text, offset);
        } else {
            break;
        }
    }
    // Parenthesised operand: defer to the balanced scanner.
    if text[offset..].starts_with('(') {
        return skip_balanced_parens(text, offset);
    }
    // Bare identifier operand: consume the contiguous identifier run.
    while let Some(ch) = text[offset..].chars().next() {
        if ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() {
            offset += ch.len_utf8();
        } else {
            break;
        }
    }
    offset
}

#[cfg(test)]
#[path = "text_tests.rs"]
mod tests;
