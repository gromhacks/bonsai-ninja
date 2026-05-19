use super::split_foreach_header;

#[test]
fn python_simple() {
    assert_eq!(split_foreach_header("for x in xs:\n    pass"), Some(("x", "xs")));
}

#[test]
fn python_async() {
    assert_eq!(
        split_foreach_header("async for item in stream:\n    pass"),
        Some(("item", "stream"))
    );
}

#[test]
fn js_let_of_clean_header() {
    // Header-only form (what kit::walk produces when it pulls
    // out a clean header substring before invoking us). Real
    // for-loop nodes also contain the body; downstream gates
    // the iterable through `looks_like_bare_identifier` so
    // body-contaminated extractions fall through to token
    // tagging rather than bare-name binding.
    assert_eq!(
        split_foreach_header("for (let row of rows)"),
        Some(("row", "rows"))
    );
}

#[test]
fn js_await_of_clean_header() {
    // `await` inside parens is preserved on the lhs binding
    // pattern; it is not in the stripped-keyword list because
    // adapters that emit `for await (x of xs)` declare `await`
    // before the paren (handled by the outer-await strip).
    assert_eq!(
        split_foreach_header("for (await chunk of stream)"),
        Some(("await chunk", "stream"))
    );
}

#[test]
fn js_for_await_outer_form() {
    // `for await (x of xs)` — outer form recognized by the
    // outer-await strip path. Result has clean lhs.
    assert_eq!(split_foreach_header("for await (x of xs)"), Some(("x", "xs")));
}

#[test]
fn java_enhanced_for_colon_form() {
    assert_eq!(
        split_foreach_header("for (Cookie theCookie : theCookies)"),
        Some(("Cookie theCookie", "theCookies"))
    );
}

#[test]
fn cpp_range_for_colon_form() {
    assert_eq!(
        split_foreach_header("for (auto item : items)"),
        Some(("auto item", "items"))
    );
}

#[test]
fn perl_paren_body() {
    let (lhs, rhs) = split_foreach_header("for my $part (split /\\s+/, $cmd) { ... }").expect("perl shape");
    assert_eq!(lhs, "my $part");
    assert_eq!(rhs, "split /\\s+/, $cmd");
}

#[test]
fn rejects_non_for() {
    assert_eq!(split_foreach_header("while (x) { }"), None);
}
