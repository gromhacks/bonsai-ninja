use super::truncate_at_char_boundary;

#[test]
fn short_string_passes_through() {
    assert_eq!(truncate_at_char_boundary("short", 80, "..."), "short");
}

#[test]
fn ascii_truncates_exact() {
    let s = "a".repeat(100);
    let out = truncate_at_char_boundary(&s, 80, "...");
    assert!(out.ends_with("..."));
    assert_eq!(out.len(), 83); // 80 + "..."
}

#[test]
fn box_drawing_char_across_cut_doesnt_panic() {
    // Regression for the TypeScript-compiler crash — `│` is a
    // 3-byte UTF-8 char. Truncating at byte 80 of a string that
    // has `│` at bytes 78..81 used to panic with
    // "byte index 80 is not a char boundary".
    let prefix = "x".repeat(78);
    let s = format!("{prefix}│ and more text that pushes past 80");
    // Truncation must not panic and must produce valid UTF-8.
    let out = truncate_at_char_boundary(&s, 80, "...");
    // `out` is already a String — the mere fact that this line
    // compiles + runs proves the slice was valid.
    assert!(out.ends_with("..."));
    // The `│` at bytes 78..81 straddles the 80-byte cut; we
    // round down to 78 so the char gets dropped.
    assert!(
        !out.contains('│'),
        "truncated form should have rounded down past the straddling char: {out:?}"
    );
}

#[test]
fn emoji_truncates_safely() {
    // Emoji are 4 bytes each. Truncating at a byte index inside
    // an emoji should round down.
    let s = "👍".repeat(30); // 120 bytes total
    let out = truncate_at_char_boundary(&s, 50, "…");
    // Should round down to a multiple of 4 (emoji boundary).
    let body = out.trim_end_matches('…');
    assert_eq!(body.len() % 4, 0);
}
