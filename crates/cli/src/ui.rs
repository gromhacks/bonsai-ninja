//! CLI presentation helpers: colors, tables, syntax-highlighted source.
//!
//! A single `Ui` handle is threaded into every text renderer. When stdout
//! is not a TTY, or the user passed `--no-color`, or `NO_COLOR` is set in
//! the environment, all styling functions become identity passes so
//! downstream pipes stay clean.
//!
//! The UI splits presentation into two layers:
//!
//! * **Chrome** — borders, headers, names, paths, kind tags. Driven by a
//!   [`Theme`]'s [`ChromePalette`].
//! * **Syntax** — source-code snippets inside refs/inspect. Driven by
//!   syntect using the theme's registered `syntect_theme_name()`.

use crate::theme::{ChromePalette, Theme};
use comfy_table::{presets::NOTHING, Cell, ContentArrangement, Table, TableComponent};
use once_cell::sync::OnceCell;
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use syntect::{
    easy::HighlightLines,
    highlighting::{Style as SynStyle, ThemeSet},
    parsing::{SyntaxReference, SyntaxSet},
    util::as_24_bit_terminal_escaped,
};

pub(crate) struct Ui {
    colors: bool,
    palette: ChromePalette,
    theme: Theme,
}

impl Ui {
    /// Build a UI honoring `--no-color`, `NO_COLOR`, and stdout-is-TTY.
    /// The theme selection comes from `--theme` / `BONSAI_THEME` (default:
    /// `moss` — the bonsai-ninja house palette).
    #[must_use]
    pub(crate) fn new(no_color: bool, theme: Theme) -> Self {
        let nc_env = std::env::var_os("NO_COLOR").is_some();
        let tty = std::io::stdout().is_terminal();
        let colors = !no_color && !nc_env && tty;
        Self {
            colors,
            palette: theme.palette(),
            theme,
        }
    }

    /// Applies a palette style to `text`, but only when color is on.
    fn apply(&self, text: &str, style: &owo_colors::Style) -> String {
        if self.colors {
            text.style(*style).to_string()
        } else {
            text.to_string()
        }
    }

    // --- chrome styles ---------------------------------------------------

    pub(crate) fn heading(&self, text: &str) -> String {
        if self.colors {
            format!("\n{}", text.style(self.palette.header).underline())
        } else {
            format!("\n{text}")
        }
    }

    pub(crate) fn label(&self, text: &str) -> String {
        self.apply(text, &self.palette.accent)
    }

    pub(crate) fn path(&self, text: &str) -> String {
        self.apply(text, &self.palette.path)
    }

    pub(crate) fn loc(&self, text: &str) -> String {
        self.apply(text, &self.palette.dim)
    }

    pub(crate) fn kind(&self, text: &str) -> String {
        self.apply(text, &self.palette.kind)
    }

    pub(crate) fn name(&self, text: &str) -> String {
        self.apply(text, &self.palette.name)
    }

    pub(crate) fn annotation(&self, text: &str) -> String {
        self.apply(text, &self.palette.accent)
    }

    pub(crate) fn step(&self, text: &str) -> String {
        self.apply(text, &self.palette.accent)
    }

    pub(crate) fn dim(&self, text: &str) -> String {
        self.apply(text, &self.palette.dim)
    }

    pub(crate) fn warn(&self, text: &str) -> String {
        self.apply(text, &self.palette.warn)
    }

    pub(crate) fn ruler(&self, ch: char, width: usize) -> String {
        let line: String = std::iter::repeat_n(ch, width).collect();
        self.apply(&line, &self.palette.border)
    }

    // --- tables ----------------------------------------------------------

    /// Make a horizontal-rule table (header underline + bottom border
    /// only, no per-row separators). Cleaner than the full grid for
    /// browse listings while still giving a visible header break.
    #[must_use]
    pub(crate) fn table(&self, headers: &[&str]) -> Table {
        let mut t = Table::new();
        // Minimal chrome: header underline + bottom rule, no per-row
        // divider lines. We also force the header/bottom *intersections*
        // to the same dash character so the rule prints as one
        // continuous line instead of gapping at column boundaries.
        t.load_preset(NOTHING);
        t.set_style(TableComponent::HeaderLines, '─');
        t.set_style(TableComponent::MiddleHeaderIntersections, '─');
        t.set_style(TableComponent::LeftHeaderIntersection, '─');
        t.set_style(TableComponent::RightHeaderIntersection, '─');
        t.set_style(TableComponent::BottomBorder, '─');
        t.set_style(TableComponent::BottomBorderIntersections, '─');
        t.set_style(TableComponent::BottomLeftCorner, '─');
        t.set_style(TableComponent::BottomRightCorner, '─');
        t.set_content_arrangement(ContentArrangement::Dynamic);
        t.set_width(terminal_width().unwrap_or(140));
        let cells: Vec<Cell> = headers
            .iter()
            .map(|h| Cell::new(self.apply(h, &self.palette.header)))
            .collect();
        t.set_header(cells);
        t
    }

    // --- syntax highlighting --------------------------------------------

    /// Highlight a full code block (multi-line) using syntect.
    #[must_use]
    pub(crate) fn highlight(&self, code: &str, extension: &str) -> String {
        if !self.colors {
            return code.to_string();
        }
        syntect_cache().highlight(code, extension, self.theme)
    }

    /// Highlight a short (usually one-line) snippet and trim trailing
    /// whitespace. Guaranteed to not contain line terminators so it sits
    /// nicely in a table cell.
    #[must_use]
    pub(crate) fn snippet(&self, code: &str, extension: &str) -> String {
        let trimmed = code.trim_end_matches(['\n', '\r']).trim();
        if !self.colors {
            return trimmed.to_string();
        }
        let highlighted = syntect_cache().highlight(trimmed, extension, self.theme);
        // Strip the trailing reset so it doesn't leak past the cell.
        highlighted.trim_end_matches("\x1b[0m").trim_end().to_string()
    }
}

// Lazy-loaded syntect syntax / theme set. Amortized once across the process.
struct SyntectCache {
    syntaxes: SyntaxSet,
    themes: ThemeSet,
}

fn syntect_cache() -> &'static SyntectCache {
    static CACHE: OnceCell<SyntectCache> = OnceCell::new();
    CACHE.get_or_init(|| {
        // `two_face` bundles bat's curated SyntaxSet. Syntect's own
        // `load_defaults_newlines()` is missing Swift, Kotlin, and
        // TypeScript — three of our supported languages — which made
        // their source render as plain single-color text in the
        // `inspect` and `refs` views. two-face fills the gap without
        // hand-vendoring .sublime-syntax files.
        let syntaxes = two_face::syntax::extra_newlines();

        // Theme set: merge syntect's bundled themes with the ones we
        // specifically use from two-face (Dracula, GruvboxDark,
        // Zenburn, etc. — the base syntect defaults ship only 7
        // themes and don't include the real Dracula or Gruvbox).
        let mut themes = ThemeSet::load_defaults();
        {
            use two_face::theme::{extra, EmbeddedThemeName};
            let extra = extra();
            // Pull each theme we map to in `Theme::syntect_theme_name`
            // and insert it under a stable lookup name. Clone because
            // two_face's `get` returns `&Theme`.
            let to_pull: &[(EmbeddedThemeName, &str)] = &[
                (EmbeddedThemeName::Dracula, "Dracula"),
                (EmbeddedThemeName::GruvboxDark, "Gruvbox Dark"),
                (EmbeddedThemeName::Zenburn, "Zenburn"),
                (EmbeddedThemeName::Nord, "Nord"),
                (
                    EmbeddedThemeName::MonokaiExtendedOrigin,
                    "Monokai Extended Origin",
                ),
            ];
            for (name, key) in to_pull {
                let t = extra.get(*name).clone();
                themes.themes.insert((*key).to_string(), t);
            }
        }

        // Bundle the moss tmTheme — none of the pre-built themes hit
        // the green / brown / pine-teal family the moss chrome needs,
        // so we ship our own.
        const MOSS_TMTHEME: &[u8] = include_bytes!("moss.tmTheme");
        if let Ok(theme) =
            syntect::highlighting::ThemeSet::load_from_reader(&mut std::io::Cursor::new(MOSS_TMTHEME))
        {
            themes.themes.insert("moss".to_string(), theme);
        }
        SyntectCache { syntaxes, themes }
    })
}

impl SyntectCache {
    fn highlight(&self, code: &str, extension: &str, theme: Theme) -> String {
        let syntax: &SyntaxReference = self
            .syntaxes
            .find_syntax_by_extension(extension)
            .or_else(|| self.syntaxes.find_syntax_by_name(extension))
            .unwrap_or_else(|| self.syntaxes.find_syntax_plain_text());
        let theme_obj = self
            .themes
            .themes
            .get(theme.syntect_theme_name())
            .or_else(|| self.themes.themes.get("base16-ocean.dark"))
            .or_else(|| self.themes.themes.values().next())
            .expect("at least one syntect theme");
        let mut h = HighlightLines::new(syntax, theme_obj);
        // Some sublime-syntax grammars require a file-level preamble
        // to enter the proper parse context — without it, every token
        // falls back to the default foreground. PHP needs `<?php`;
        // Solidity needs a `contract … { function … {` scope. Run the
        // preamble through the highlighter first so its parse state
        // advances, then discard the preamble's output and highlight
        // the real snippet as if it were mid-file.
        if let Some(preamble) = syntax_preamble_for(extension) {
            for line in preamble.split_inclusive('\n') {
                let _ = h.highlight_line(line, &self.syntaxes);
            }
        }
        let mut out = String::new();
        for line in code.split_inclusive('\n') {
            let ranges: Vec<(SynStyle, &str)> = match h.highlight_line(line, &self.syntaxes) {
                Ok(r) => r,
                Err(_) => return code.to_string(),
            };
            out.push_str(&as_24_bit_terminal_escaped(&ranges[..], false));
        }
        out.push_str("\x1b[0m");
        out
    }
}

/// File-level preamble required to put certain sublime-syntax grammars
/// into their normal token-emitting state. When `inspect` / `calls` /
/// `vars` feed a single mid-file line to the highlighter, languages
/// whose grammar starts in a "text/plain wrapping the embedded code"
/// state (PHP inside HTML, Solidity inside a file preamble) leave
/// every token as the default foreground. Running the preamble
/// through the highlighter before the real snippet advances its
/// parse state so the snippet tokenises as if it lived mid-file.
///
/// `None` for every other grammar — their initial state already
/// emits proper token scopes.
fn syntax_preamble_for(extension: &str) -> Option<&'static str> {
    match extension {
        // PHP's sublime-syntax boots into `text.html.basic` and only
        // enters `source.php` after `<?php`. Without this prefix, a
        // one-line PHP snippet renders as plain HTML text.
        "php" | "phtml" | "phps" => Some("<?php\n"),
        // Solidity's grammar expects the first interesting tokens to
        // sit inside a contract + function scope. Establishing that
        // nesting up front makes `require(...)` / `amount > 0` /
        // bare statement snippets tokenise correctly.
        "sol" => Some("contract _Ctx { function _fn() public {\n"),
        _ => None,
    }
}

/// Best-effort terminal-width probe. Returns `None` when the size isn't
/// discoverable so callers can fall back to a fixed default.
fn terminal_width() -> Option<u16> {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|w| *w >= 40)
}

/// Best-effort extension extraction from a workspace path.
#[must_use]
pub(crate) fn extension_for(path: &str) -> &str {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::syntect_cache;
    use crate::theme::Theme;

    /// Every supported language must have a syntect
    /// grammar available, otherwise `inspect` / `refs` render source
    /// as plain uniform text. Caught Swift / Kotlin / TypeScript
    /// missing when we were on syntect's defaults — now we pull from
    /// `two_face` which bundles bat's full set.
    #[test]
    fn every_supported_lang_has_a_syntect_grammar() {
        let cache = syntect_cache();
        for adapter in bonsai_adapters::all_adapters() {
            let name = adapter.language_id().as_str();
            let extensions = adapter.file_extensions();
            assert!(
                !extensions.is_empty(),
                "adapter `{name}` must declare at least one file extension",
            );
            for ext in extensions {
                let found = cache.syntaxes.find_syntax_by_extension(ext);
                assert!(
                    found.is_some(),
                    "no syntect grammar registered for .{ext} ({name}) — \
                 `inspect`'s inlined source will render uniformly for this language"
                );
            }
        }
    }

    /// Every theme's `syntect_theme_name()` must resolve to a theme
    /// actually present in the cache. Guards against copy-paste typos
    /// in the chrome↔syntax mapping (e.g. renaming "Gruvbox Dark" to
    /// "gruvbox-dark" in `Theme::syntect_theme_name` without updating
    /// the insert key in `syntect_cache`).
    #[test]
    fn every_theme_has_a_registered_syntax_theme() {
        let cache = syntect_cache();
        for theme in [Theme::EarthyDark, Theme::Dracula, Theme::RetroAmber, Theme::Moss] {
            let name = theme.syntect_theme_name();
            assert!(
                cache.themes.themes.contains_key(name),
                "theme {theme:?} points at syntax theme `{name}` which \
                 isn't in the SyntectCache — `inspect` will fall back \
                 to an arbitrary theme for this chrome preset"
            );
        }
    }

    /// Mid-file one-line snippets in every supported language must
    /// produce at least two distinct token colors. Catches the class
    /// of bug where a grammar needs a file preamble to reach its
    /// proper parse state (PHP inside HTML, Solidity inside a
    /// contract / function scope) and otherwise emits every token
    /// in the default foreground. The `syntax_preamble_for` helper
    /// in [`SyntectCache::highlight`] runs that preamble through the
    /// highlighter first; this test proves it actually fires.
    #[test]
    fn mid_file_snippets_produce_distinct_token_colors() {
        let cache = syntect_cache();
        // One realistic snippet per language, representative of what
        // the `calls` / `vars` tables inline into the code column.
        let cases = [
            ("c", "int x = foo(bar);"),
            ("cpp", "std::string s = q.exec();"),
            ("cs", "var x = Sink(token);"),
            ("dart", "var x = Process.run('ping', [input]);"),
            ("erl", "Y = lists:map(fun sink/1, [X])."),
            ("ex", "System.cmd(\"ping\", [input])"),
            ("go", "x := exec.Command(\"ping\", token)"),
            ("java", "String s = obj.method(arg);"),
            ("js", "const x = require('fs').readFileSync(p);"),
            ("kt", "val x = conn.createStatement().executeQuery(q)"),
            ("lua", "local r = os.execute(\"ping \" .. cmd)"),
            ("m", "NSString *s = [obj method:arg];"),
            ("pl", "my $x = system(\"ping \", $cmd);"),
            ("php", "$stmt->execute([$userId]);"),
            ("py", "cursor.execute(\"SELECT\", (user_id,))"),
            ("rb", "@db.execute(\"SELECT\", [token])"),
            ("rs", "let x = Command::new(\"sh\").arg(\"-c\").output();"),
            ("scala", "val x = stmt.executeQuery(q)"),
            ("sol", "require(amount > 0, \"z\");"),
            ("swift", "let s = sqlite3_prepare_v2(db, q, -1, &stmt, nil)"),
            ("ts", "const x: Buffer = execSync('ping ' + cmd);"),
        ];
        for (ext, code) in cases {
            let rendered = cache.highlight(code, ext, Theme::Moss);
            // Count the distinct 24-bit foreground codes emitted.
            // Form: `\x1b[38;2;R;G;Bm`. Skip the trailing `\x1b[0m`.
            let mut distinct = std::collections::BTreeSet::new();
            for chunk in rendered.split("\x1b[38;2;") {
                if let Some(end) = chunk.find('m') {
                    let code = &chunk[..end];
                    if code.split(';').count() == 3 {
                        distinct.insert(code.to_string());
                    }
                }
            }
            assert!(
                distinct.len() >= 2,
                "`.{ext}` snippet `{code}` produced only {} distinct token \
                 color(s) — syntect is falling back to the default fg. \
                 Likely needs a `syntax_preamble_for` entry to reach its \
                 normal parse state.",
                distinct.len(),
            );
        }
    }

    /// Render a small snippet through every theme and confirm each
    /// produces DIFFERENT highlighted output. Catches silent
    /// mis-wires where two themes both end up using the fallback.
    #[test]
    fn themes_produce_distinct_output() {
        let cache = syntect_cache();
        let code =
            "fn hello(x: i32) -> String {\n    let s = \"hi\"; // note\n    return format!(\"{}\", x);\n}\n";
        let outputs: Vec<_> = [Theme::EarthyDark, Theme::Dracula, Theme::RetroAmber, Theme::Moss]
            .iter()
            .map(|t| cache.highlight(code, "rs", *t))
            .collect();
        for (i, a) in outputs.iter().enumerate() {
            for (j, b) in outputs.iter().enumerate().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "themes #{i} and #{j} produced identical syntax output — \
                     one is silently falling back to the other"
                );
            }
        }
    }
}
