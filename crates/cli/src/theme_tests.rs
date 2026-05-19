use super::Theme;

#[test]
fn parse_earthy_spelling_variants() {
    assert_eq!(Theme::parse("earthy"), Some(Theme::EarthyDark));
    assert_eq!(Theme::parse("earthy-dark"), Some(Theme::EarthyDark));
    assert_eq!(Theme::parse("earth"), Some(Theme::EarthyDark));
    assert_eq!(Theme::parse("EARTHY-DARK"), Some(Theme::EarthyDark));
}

#[test]
fn parse_dracula() {
    assert_eq!(Theme::parse("dracula"), Some(Theme::Dracula));
    assert_eq!(Theme::parse("DRACULA"), Some(Theme::Dracula));
}

#[test]
fn parse_retro_amber_variants() {
    assert_eq!(Theme::parse("retro"), Some(Theme::RetroAmber));
    assert_eq!(Theme::parse("retro-amber"), Some(Theme::RetroAmber));
    assert_eq!(Theme::parse("amber"), Some(Theme::RetroAmber));
}

#[test]
fn parse_moss_variants() {
    // The bonsai-ninja house theme accepts moss / bonsai / forest
    // as the name — they all round-trip to Theme::Moss.
    assert_eq!(Theme::parse("moss"), Some(Theme::Moss));
    assert_eq!(Theme::parse("bonsai"), Some(Theme::Moss));
    assert_eq!(Theme::parse("forest"), Some(Theme::Moss));
    assert_eq!(Theme::parse("MOSS"), Some(Theme::Moss));
    assert_eq!(Theme::parse("Bonsai"), Some(Theme::Moss));
}

#[test]
fn parse_unknown_returns_none() {
    assert_eq!(Theme::parse("neon-nope"), None);
    assert_eq!(Theme::parse(""), None);
}

#[test]
fn each_theme_has_a_palette_and_syntect_name() {
    for theme in [Theme::EarthyDark, Theme::Dracula, Theme::RetroAmber, Theme::Moss] {
        let _ = theme.palette();
        let name = theme.syntect_theme_name();
        assert!(!name.is_empty(), "theme {theme:?} lacks syntect name");
    }
}

/// The bundled moss tmTheme must parse cleanly — if someone
/// hand-edits the plist and breaks the XML, this catches it at
/// test time instead of silently falling back to another theme at
/// runtime.
#[test]
fn moss_tmtheme_parses() {
    const MOSS_TMTHEME: &[u8] = include_bytes!("moss.tmTheme");
    let theme = syntect::highlighting::ThemeSet::load_from_reader(&mut std::io::Cursor::new(MOSS_TMTHEME))
        .expect("moss.tmTheme should parse");
    assert_eq!(theme.name.as_deref(), Some("Moss"));
    // At least the background must be set to our deep-loam base.
    let bg = theme.settings.background.expect("background set");
    // Expect R < 60, G < 60, B < 60 — we want a dark surface, not
    // a bright one. Guards against accidentally inverting the
    // theme later.
    assert!(
        bg.r < 60 && bg.g < 60 && bg.b < 60,
        "moss background should be dark, got rgb({},{},{})",
        bg.r,
        bg.g,
        bg.b
    );
}
