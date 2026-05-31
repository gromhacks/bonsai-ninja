//! Foreach / for-of / for-in header parsing.
//!
//! Adapters surface for-each loops as `FlowEvent::Loop`; the kit
//! converts the binding shape (`for x in xs`, `for (await y of ys)`,
//! `foreach my $z (@zs)`) into a synthetic `Assign` so the taint
//! engine sees `x = xs`, `y = ys`, `z = @zs` without needing per-
//! grammar binding extractors.
//!
//! This module owns only the *header parsing* — the substring split
//! that recognises supported header shapes. The synthesis itself
//! (`extract_foreach_binding_assigns`) stays in `kit::mod` because
//! it threads through binding-token / span helpers shared with other
//! flow-event constructors.
//!
//! Recognised shapes (covers all 21 supported languages):
//!
//! - `for x in xs:` (Python)
//! - `async for x in xs:` (Python)
//! - `for (let x of xs)` (JS/TS, with `const`/`let`/`var`/`final`)
//! - `for (await y of ys)` (JS/TS async iteration)
//! - `foreach (var x in xs)` (C#/Dart)
//! - `for x := range xs { ... }` (Go — note the trailing `:`)
//! - `for (Type x : xs)` / `for (auto x : xs)` (Java / C++ range-for)
//! - `for my $part (split /\s+/, $cmd) { ... }` (Perl)
//! - `for my $t (@tokens) { ... }` (Perl)
//! - `for (x <- xs) { ... }` (Scala for-comprehension generator)
//!
//! Binding-keyword stripping (`const`/`let`/`var`/`final`) is
//! intentionally narrow; adding new keywords requires a test case
//! since the strip is greedy on prefix-match.

/// Split a for-loop header into `(lhs_binding_pattern, rhs_iterable)`.
/// Returns `None` if the header doesn't match any supported shape.
pub(super) fn split_foreach_header(text: &str) -> Option<(&str, &str)> {
    let trimmed = text.trim_start();
    let mut after_for = trimmed
        .strip_prefix("async for ")
        .or_else(|| trimmed.strip_prefix("for "))
        .or_else(|| trimmed.strip_prefix("foreach "))
        .or_else(|| trimmed.find("for ").map(|idx| &trimmed[idx + 4..]))?;
    after_for = after_for.trim_start();
    if let Some(rest) = after_for.strip_prefix("await ") {
        after_for = rest.trim_start();
    }
    // Adapters hand us the WHOLE foreach node (header + body), not a
    // pre-sliced header. A foreach header never legitimately contains a
    // top-level `{`, so truncate at the body brace: this keeps body text
    // (and any stray `)` inside body calls like `system($cmd)`) out of the
    // paren `rsplit_once(')')` below, which would otherwise grab a body `)`
    // and route body identifiers onto the binding side (PHP `as` shape).
    //
    // BUT the iterable expression itself may contain a `{` (Lua
    // `for _, x in ipairs({...})` packs a table literal inside the
    // iterable). Only truncate at a `{` that sits OUTSIDE any parenthesis
    // / bracket nesting (paren-depth 0) -- the real body brace -- so a `{`
    // nested in the iterable's call args is preserved. Lua bodies use
    // `do ... end` (no `{`), so this leaves Lua headers untouched.
    let mut depth = 0i32;
    let mut body_open = None;
    for (idx, ch) in after_for.char_indices() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '{' if depth <= 0 => {
                body_open = Some(idx);
                break;
            }
            _ => {}
        }
    }
    if let Some(idx) = body_open {
        after_for = after_for[..idx].trim_end();
    }
    if let Some(paren_body) = after_for
        .strip_prefix('(')
        .and_then(|rest| rest.rsplit_once(')').map(|(body, _)| body))
    {
        if let Some((lhs, rhs)) = split_foreach_lhs_rhs(paren_body) {
            return Some((strip_foreach_binding_keywords(lhs), rhs.trim()));
        }
    }
    if let Some((lhs, rest)) = split_foreach_lhs_rhs(after_for) {
        // Go-style `for x := range xs { ... }` — strip a trailing
        // block-open marker (`:`) so the iterable text is clean.
        let rhs = rest.split_once(':').map_or(rest, |(head, _)| head).trim();
        return Some((strip_foreach_binding_keywords(lhs), rhs));
    }
    // Perl-style: `for my $part (split /\\s+/, $cmd) { ... }` and
    // `for my $t (@tokens) { ... }`. The iterable lives between the
    // first `(` and the last `)` of the header — substring slice.
    let open = after_for.find('(')?;
    let close = after_for.rfind(')')?;
    if close <= open {
        return None;
    }
    let lhs = after_for[..open].trim();
    let rhs = after_for[open + 1..close].trim();
    if lhs.is_empty() || rhs.is_empty() {
        return None;
    }
    Some((lhs, rhs))
}

/// Split on the iteration keyword (`in` or `of`) — the two surface forms
/// most supported languages reduce to. PHP's `foreach ($xs as $x)`
/// reverses the written order, so return `(binding, iterable)` for
/// that spelling too. Scala for-comprehension generators bind with the
/// `<-` arrow (`for (x <- xs)`), so recognise that spelling as well.
fn split_foreach_lhs_rhs(text: &str) -> Option<(&str, &str)> {
    text.split_once(" in ")
        .or_else(|| text.split_once(" of "))
        .or_else(|| text.split_once(" : "))
        .or_else(|| text.split_once(" <- "))
        .or_else(|| {
            text.split_once(" as ").map(|(iterable, binding)| {
                let binding = binding.rsplit_once("=>").map_or(binding, |(_, value)| value);
                (binding, iterable)
            })
        })
}

/// Strip a leading binding keyword (`const`/`let`/`var`/`final`) so the
/// returned lhs is the bare binding pattern. Greedy on prefix-match: only
/// the first matching keyword is removed.
fn strip_foreach_binding_keywords(text: &str) -> &str {
    let mut binding_text = text.trim();
    for keyword in ["const ", "let ", "var ", "final "] {
        if let Some(after_keyword) = binding_text.strip_prefix(keyword) {
            binding_text = after_keyword.trim_start();
            break;
        }
    }
    binding_text
}

#[cfg(test)]
#[path = "foreach_header_tests.rs"]
mod tests;
