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
fn each_theme_has_a_palette() {
    for theme in [Theme::EarthyDark, Theme::Dracula, Theme::RetroAmber, Theme::Moss] {
        let _ = theme.palette();
    }
}
