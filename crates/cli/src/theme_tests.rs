use super::Theme;

#[test]
fn parse_earthy_dark() {
    assert_eq!(Theme::parse("earthy-dark"), Some(Theme::EarthyDark));
    assert_eq!(Theme::parse("EARTHY-DARK"), None);
}

#[test]
fn parse_dracula() {
    assert_eq!(Theme::parse("dracula"), Some(Theme::Dracula));
    assert_eq!(Theme::parse("DRACULA"), None);
}

#[test]
fn parse_retro_amber() {
    assert_eq!(Theme::parse("retro-amber"), Some(Theme::RetroAmber));
}

#[test]
fn parse_moss() {
    assert_eq!(Theme::parse("moss"), Some(Theme::Moss));
    assert_eq!(Theme::parse("MOSS"), None);
}

#[test]
fn parse_unknown_returns_none() {
    assert_eq!(Theme::parse("neon-nope"), None);
    assert_eq!(Theme::parse("earthy"), None);
    assert_eq!(Theme::parse("retro"), None);
    assert_eq!(Theme::parse("bonsai"), None);
    assert_eq!(Theme::parse(""), None);
}

#[test]
fn each_theme_has_a_palette() {
    for theme in [Theme::EarthyDark, Theme::Dracula, Theme::RetroAmber, Theme::Moss] {
        let _ = theme.palette();
    }
}
