//! Color themes for CLI chrome and syntax highlighting.
//!
//! Chrome (borders/headers/badges) uses [`owo_colors::Style`] with
//! RGB palettes (independent of terminal ANSI remaps). Syntax inside
//! `refs` / `inspect` snippets is handed to Tree-sitter. Chrome stays
//! subdued; the single accent slot is reserved for the user's match.

use clap::builder::styling::{AnsiColor, Color, RgbColor, Style as ClapStyle, Styles as ClapStyles};
use owo_colors::{Rgb, Style};

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Theme {
    // Muted brown-olive-amber. Borders dim, accents warm.
    EarthyDark,
    // Popular purple/teal Dracula palette.
    Dracula,
    // Amber-on-near-black phosphor look. Four colors only.
    RetroAmber,
    // Dark-forest bonsai house palette and the CLI default.
    Moss,
}

impl Theme {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        <Self as clap::ValueEnum>::from_str(name, false).ok()
    }

    pub(crate) fn palette(self) -> ChromePalette {
        match self {
            Self::EarthyDark => ChromePalette::earthy_dark(),
            Self::Dracula => ChromePalette::dracula(),
            Self::RetroAmber => ChromePalette::retro_amber(),
            Self::Moss => ChromePalette::moss(),
        }
    }

    /// Build the ANSI styles clap uses when rendering `--help` output.
    ///
    /// Maps our chrome palette onto clap's named slots so the help menu
    /// picks up the same colors as table headers / browse output.
    /// * `header`     → section titles (Options, Commands, Usage)
    /// * `usage`      → the usage line label
    /// * `literal`    → command / flag / literal text
    /// * `placeholder`→ `<WORKSPACE>`, `<QUERY>`, default values
    /// * `error`      → clap's error prefix
    /// * `valid`      → recommended values on suggestions
    /// * `invalid`    → the offending bit of an error message
    pub(crate) fn clap_styles(self) -> ClapStyles {
        let (header, literal, placeholder, accent) = match self {
            Self::EarthyDark => (
                RgbColor(217, 195, 141), // warm sand
                RgbColor(152, 146, 110), // olive kind-tone
                RgbColor(139, 130, 110), // dim path-tone
                RgbColor(214, 154, 91),  // amber accent
            ),
            Self::Dracula => (
                RgbColor(189, 147, 249), // purple
                RgbColor(139, 233, 253), // cyan
                RgbColor(98, 114, 164),  // comment blue-gray
                RgbColor(255, 121, 198), // pink
            ),
            Self::RetroAmber => (
                RgbColor(255, 176, 0),
                RgbColor(204, 136, 0),
                RgbColor(148, 98, 0),
                RgbColor(204, 68, 0),
            ),
            Self::Moss => (
                RgbColor(138, 192, 156), // misted pine — header
                RgbColor(110, 170, 140), // evergreen — literal
                RgbColor(92, 118, 110),  // slate-moss — placeholder
                RgbColor(100, 180, 172), // cold spruce teal — accent pop
            ),
        };
        let fg = |c: RgbColor| ClapStyle::new().fg_color(Some(Color::Rgb(c)));
        ClapStyles::styled()
            .header(fg(header).bold().underline())
            .usage(fg(header).bold())
            .literal(fg(literal).bold())
            .placeholder(fg(placeholder))
            .valid(fg(literal))
            .invalid(fg(accent).bold())
            .error(
                ClapStyle::new()
                    .fg_color(Some(Color::Ansi(AnsiColor::Red)))
                    .bold(),
            )
    }
}

/// Colors used by the non-syntax CLI surface. Every slot is an
/// `owo_colors::Style`, which falls back to identity when styling is off.
#[derive(Clone, Debug)]
pub(crate) struct ChromePalette {
    /// Table borders and rulers.
    pub border: Style,
    /// Column headers and top-level section titles.
    pub header: Style,
    /// Identifier / symbol name — the primary thing being listed.
    pub name: Style,
    /// Kind tags (function / class / import / decorator).
    pub kind: Style,
    /// File paths and line:col locations.
    pub path: Style,
    /// Secondary values and counts.
    pub dim: Style,
    /// Reserved for the single "important" marker (SOURCE / MATCH / SINK).
    pub accent: Style,
    /// Warning flavor (unresolved, wildcards, suppressed rows, saturated
    /// trace summaries).
    pub warn: Style,
}

impl ChromePalette {
    fn earthy_dark() -> Self {
        // Muted brown + olive + amber palette. Nothing saturated; names
        // stay readable on dark and light terminals alike.
        let border = Style::new().color(Rgb(90, 82, 70));
        let header = Style::new().color(Rgb(217, 195, 141)).bold();
        let name = Style::new().color(Rgb(217, 195, 141)).bold();
        let kind = Style::new().color(Rgb(152, 146, 110));
        let path = Style::new().color(Rgb(139, 130, 110));
        let dim = Style::new().color(Rgb(120, 110, 96));
        let accent = Style::new().color(Rgb(214, 154, 91)).bold();
        let warn = Style::new().color(Rgb(188, 132, 61)).bold();
        Self {
            border,
            header,
            name,
            kind,
            path,
            dim,
            accent,
            warn,
        }
    }

    fn dracula() -> Self {
        // Official Dracula swatches (https://draculatheme.com/contribute).
        // Chrome intentionally uses the paler Dracula foreground tones so
        // it doesn't out-shout the Dracula syntax colors.
        let border = Style::new().color(Rgb(68, 71, 90));
        let header = Style::new().color(Rgb(189, 147, 249)).bold(); // purple
        let name = Style::new().color(Rgb(139, 233, 253)).bold(); // cyan
        let kind = Style::new().color(Rgb(80, 250, 123)); // green
        let path = Style::new().color(Rgb(98, 114, 164)); // comment blue-gray
        let dim = Style::new().color(Rgb(98, 114, 164));
        let accent = Style::new().color(Rgb(255, 121, 198)).bold(); // pink
        let warn = Style::new().color(Rgb(255, 184, 108)).bold(); // orange
        Self {
            border,
            header,
            name,
            kind,
            path,
            dim,
            accent,
            warn,
        }
    }

    fn retro_amber() -> Self {
        // Monochrome phosphor with one hot accent. Five tones, no more.
        let amber_bright = Style::new().color(Rgb(255, 176, 0)).bold();
        let amber = Style::new().color(Rgb(204, 136, 0));
        let amber_dim = Style::new().color(Rgb(148, 98, 0));
        let amber_muted = Style::new().color(Rgb(110, 74, 0));
        Self {
            border: amber_muted,
            header: amber_bright,
            name: amber_bright,
            kind: amber,
            path: amber_dim,
            dim: amber_muted,
            accent: amber,
            warn: amber_dim,
        }
    }

    fn moss() -> Self {
        // Dark-forest palette restricted to the cool half of the spectrum:
        // evergreens, teals, sky blues, slate. No tan, no amber, no lime —
        // every slot sits between deep blue and forest green so the
        // terminal feels like a misted clearing under moonlight, not a
        // cabin interior.
        //
        // The visual pop (`accent`) is a clean cyan that reads like still
        // water under pines. `warn` is a cool sky blue — distinct from
        // accent, draws the eye, but stays inside the cool band. `error`
        // (defined elsewhere) keeps the weathered crimson so errors still
        // register unambiguously.
        //
        //   pine-ink / border     — deep spruce shadow, nearly black
        //   misted-pine / header  — cool fresh-needle teal
        //   frost-mint / name     — bright readable mint with a blue lean
        //   evergreen / kind      — mid-forest conifer with cyan lift
        //   slate-moss / path     — old stone under lichen
        //   deep-shade / dim      — undergrowth at dusk
        //   spruce-cyan / accent  — cold still water, the pop
        //   sky-pine / warn       — cool sky blue, draws the eye, no tan
        let border = Style::new().color(Rgb(42, 58, 60));
        let header = Style::new().color(Rgb(120, 188, 180)).bold();
        let name = Style::new().color(Rgb(168, 222, 218)).bold();
        let kind = Style::new().color(Rgb(96, 168, 160));
        let path = Style::new().color(Rgb(92, 118, 122));
        let dim = Style::new().color(Rgb(72, 96, 100));
        let accent = Style::new().color(Rgb(110, 196, 210)).bold();
        let warn = Style::new().color(Rgb(120, 168, 210)).bold();
        Self {
            border,
            header,
            name,
            kind,
            path,
            dim,
            accent,
            warn,
        }
    }
}

#[cfg(test)]
#[path = "theme_tests.rs"]
mod tests;
