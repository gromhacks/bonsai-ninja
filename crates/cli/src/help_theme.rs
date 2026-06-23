//! Themed `--help` rendering.
//!
//! Clap's default help is already structured; the pieces here
//! supplement it with:
//!
//! - A grouped root command index (`HELP_GROUPS`) that replaces
//!   clap's auto `COMMANDS:` list with a curated layout.
//! - An `EXAMPLES` block ([`HELP_EXAMPLES`]) themed with the same
//!   palette as the rest of the CLI.
//! - Post-processing of clap's rendered help so indented body text
//!   picks up the active theme color (clap doesn't expose a style
//!   slot for body prose).
//!
//! Entry points: [`themed_command_groups`] / [`themed_after_help`] for
//! the root `--help`, [`themed_subcommand_long_about`] /
//! [`themed_subcommand_after_help`] for per-subcommand `--help`, and
//! [`try_themed_help`] as the early dispatcher that intercepts
//! `--help` / `-h` before clap runs.

use crate::theme;
use crate::{resolve_theme_early, Cli};

pub(crate) const CLI_LONG_ABOUT: &str = "\
bonsai-ninja indexes a source tree and lets you browse symbols, trace
cross-file execution, inspect source-backed flows, and run rulepack-driven
security taint analysis across 21 languages.";

const MAX_HELP_DESCRIPTION_LINES: usize = 2;
const MAX_SUBCOMMAND_EXAMPLE_COMMANDS: usize = 3;

/// Apply the active theme to the root `Cli` long-about prose. Runs at
/// command-construction time so clap receives an already-colored
/// string; `try_themed_help`'s `colorize_help_body` then skips these
/// lines (they already contain ANSI) and leaves them intact.
pub(crate) fn themed_cli_long_about() -> String {
    themed_subcommand_long_about(CLI_LONG_ABOUT)
}

/// The command groups shown in the help index.
///
/// Keeping the list here (instead of recomputing it from the `Cmd`
/// variants) lets us write one-line human descriptions tuned for the
/// help menu without coupling them to the per-command `about` text.
pub(crate) const HELP_GROUPS: &[(&str, &[(&str, &str)])] = &[
    (
        "Flow",
        &[
            ("inspect", "Find hits and source-backed flows"),
            ("trace", "Expand one entry point's call tree"),
            ("show", "Open an F:/T:/E:/S: id"),
        ],
    ),
    (
        "Workspace",
        &[
            ("index", "Parse a workspace and print stats"),
            ("export", "Export the graph as JSON"),
        ],
    ),
    (
        "Cache",
        &[
            ("cache stats", "Show cache config and sidecar size"),
            ("cache clear", "Delete `.bonsai/` sidecars"),
            ("cache rebuild", "Rebuild the dataflow sidecar"),
        ],
    ),
    (
        "Browse",
        &[
            ("defs", "Definitions"),
            ("entrypoints", "Likely callable roots"),
            ("calls", "Call sites"),
            ("imports", "Imports/includes"),
            ("vars", "Assignments"),
            ("strings", "String literals"),
            ("comments", "Comments"),
            ("args", "Call arguments"),
            ("classes", "Classes and structs"),
            ("refs", "Symbol references"),
            ("search", "Fuzzy search"),
        ],
    ),
    (
        "Navigation",
        &[
            ("tree", "Annotated workspace tree"),
            ("read-file", "Annotated source view"),
        ],
    ),
    (
        "Security",
        &[
            ("security sources", "Rulepack source matches"),
            ("security sinks", "Rulepack sink matches"),
            ("security sanitizers", "Sanitizer matches"),
            ("security deps", "Rulepack dependency hits"),
            ("security taint-analysis", "Source-to-sink findings"),
            ("security source-analysis", "Downstream source flows"),
            ("security pack", "Rulepack audit"),
        ],
    ),
    (
        "Debug",
        &[
            ("dump-ast", "Parse tree"),
            ("dump-hir", "HIR for one function"),
            ("dump-cfg", "CFG for one function"),
            ("dump-callgraph", "Caller/callee counts"),
            ("dump-edges", "Resolved call edges"),
            ("dump-resolve", "Resolver stages"),
            ("dump-taint", "Taint propagation"),
            ("diagnostics", "Adapter diagnostics"),
        ],
    ),
];

/// Commands & arguments shown in `EXAMPLES`. Split into text + command
/// fragments so the builder can paint commands / flags separately.
pub(crate) const HELP_EXAMPLES: &[(&str, &[&str])] = &[
    (
        "Inspect a sink and its flows:",
        &["bonsai-ninja inspect ./src --query os.system"],
    ),
    (
        "Trace behavior from an entry point:",
        &["bonsai-ninja trace ./src handle_request"],
    ),
    (
        "Browse before drilling in:",
        &["bonsai-ninja calls ./src --callee os.system"],
    ),
    (
        "Run security analysis:",
        &["bonsai-ninja security ./src taint-analysis --severity high"],
    ),
    (
        "Emit machine-readable output:",
        &["bonsai-ninja export ./src > index.json"],
    ),
    ("Change the theme:", &["bonsai-ninja --theme dracula defs ./src"]),
];

/// Build the grouped root command index. The root template places this
/// before global options so the command surface is the first scannable
/// section after usage.
pub(crate) fn themed_command_groups() -> String {
    let theme = resolve_theme_early();
    let palette = theme.palette();
    let colors = help_colors_enabled();

    // Pad command names so descriptions line up even as grouped
    // labels grow (for example, `security source-analysis`).
    let pad = |name: &str, width: usize| -> String {
        if name.chars().count() >= width {
            format!("{name} ")
        } else {
            format!("{name}{}", " ".repeat(width - name.chars().count()))
        }
    };

    let mut out = String::new();
    let command_pad_width = HELP_GROUPS
        .iter()
        .flat_map(|(_, entries)| entries.iter().map(|(cmd, _)| cmd.chars().count()))
        .max()
        .unwrap_or(0)
        + 2;

    out.push_str(&help_section_header("COMMAND GROUPS", &palette, colors));
    out.push('\n');
    for (group, entries) in HELP_GROUPS {
        out.push('\n');
        out.push_str("  ");
        out.push_str(&paint_help_text(group, &palette.accent, colors));
        out.push('\n');
        for (cmd, desc) in *entries {
            out.push_str("    ");
            out.push_str(&paint_help_text(
                &pad(cmd, command_pad_width),
                &palette.name,
                colors,
            ));
            out.push_str(&paint_help_text(desc, &palette.dim, colors));
            out.push('\n');
        }
    }
    out
}

/// Build the root after-help block shown below global options. Colors
/// are applied via ANSI when the target terminal supports them;
/// otherwise the output is plain text. The theme is resolved from
/// `--theme` / `BONSAI_THEME` so the help menu picks up the same palette
/// as the rest of the CLI.
pub(crate) fn themed_after_help() -> String {
    let theme = resolve_theme_early();
    let palette = theme.palette();
    let colors = help_colors_enabled();

    let mut out = String::new();
    out.push_str(&help_section_header("EXAMPLES", &palette, colors));
    out.push('\n');
    for (prose, cmds) in HELP_EXAMPLES {
        out.push('\n');
        out.push_str("  ");
        out.push_str(&paint_help_text(prose, &palette.dim, colors));
        out.push('\n');
        for cmd in *cmds {
            out.push_str("    ");
            out.push_str(&paint_help_text("$ ", &palette.dim, colors));
            out.push_str(&paint_command(cmd, &palette, colors));
            out.push('\n');
        }
    }
    out.push('\n');

    out.push_str(&help_section_header("SEE ALSO", &palette, colors));
    out.push_str("\n\n  ");
    out.push_str(&paint_help_text(
        "Run `bonsai-ninja <command> --help` for per-command usage + examples.",
        &palette.dim,
        colors,
    ));
    out.push_str("\n  ");
    out.push_str(&paint_help_text("Common starting points: ", &palette.dim, colors));
    for (i, cmd) in ["inspect", "trace", "defs", "calls", "refs"].iter().enumerate() {
        if i > 0 {
            out.push_str(&paint_help_text(", ", &palette.dim, colors));
        }
        out.push_str(&paint_help_text(cmd, &palette.name, colors));
    }
    out.push('\n');
    out
}

fn help_section_header(text: &str, palette: &theme::ChromePalette, colors: bool) -> String {
    use owo_colors::OwoColorize;
    if colors {
        text.style(palette.header).underline().to_string()
    } else {
        text.to_string()
    }
}

fn paint_help_text(text: &str, style: &owo_colors::Style, colors: bool) -> String {
    use owo_colors::OwoColorize;
    if colors {
        text.style(*style).to_string()
    } else {
        text.to_string()
    }
}

/// Colorize a subcommand's `long_about` prose — the paragraph(s)
/// that render at the top of `<cmd> --help`. Clap doesn't expose a
/// style slot for body text, so we wrap the raw string with ANSI
/// escapes at build time (via a runtime function call in the
/// `#[command(long_about = ...)]` attribute). Every ``backtick``
/// identifier inside gets an extra highlight in the `literal` style
/// so code references pop visually.
///
/// The body itself uses the palette's `dim` slot — a muted tone
/// distinct from pure white so the prose reads as "themed body text"
/// without competing with the brighter chrome colors on section
/// headings and flag names.
pub(crate) fn themed_subcommand_long_about(raw_prose: &str) -> String {
    use owo_colors::OwoColorize;
    let theme = resolve_theme_early();
    let palette = theme.palette();
    let compact = compact_long_about(raw_prose);
    if !help_colors_enabled() {
        return compact;
    }
    // Split on backticks to highlight `ident` code references in the
    // `literal` slot color while the surrounding prose stays in the
    // dim body tone. The iterator alternates: even indices are
    // outside-backtick prose, odd indices are inside-backtick code.
    let mut colorized = String::new();
    for (segment_index, segment) in compact.split('`').enumerate() {
        let is_code_span = segment_index % 2 == 1;
        if is_code_span {
            colorized.push('`');
            colorized.push_str(&segment.style(palette.name).bold().to_string());
            colorized.push('`');
        } else {
            colorized.push_str(&segment.style(palette.dim).to_string());
        }
    }
    colorized
}

fn compact_long_about(raw_prose: &str) -> String {
    let paragraph = raw_prose
        .split("\n\n")
        .find(|paragraph| !paragraph.trim().is_empty())
        .unwrap_or(raw_prose)
        .trim();
    wrap_words(paragraph, 88)
}

/// Colorize a subcommand's `after_help` block — the
/// `EXAMPLES\n\n  $ bonsai-ninja <cmd> ...` text attached to every
/// subcommand via `#[command(after_help = ...)]`. Before this
/// helper existed, subcommands' after-help was plain monochrome
/// text even when the root `--help` was fully themed, so
/// `inspect --help` looked bland compared to `--help`.
///
/// The logic is intentionally simple so it works on any after-help
/// text: lines starting with `$ ` get painted as shell commands
/// (same style as top-level HELP_EXAMPLES); ALL-CAPS-at-column-0
/// lines are treated as section headings (underlined + accent
/// color); everything else stays dim. The heading heuristic matches
/// the shape we actually use (`EXAMPLES`, `NOTES`, `SEE ALSO`) —
/// there is no surprise coloring of normal prose that happens to
/// be uppercase.
pub(crate) fn themed_subcommand_after_help(raw_after_help: &str) -> String {
    use owo_colors::OwoColorize;
    let theme = resolve_theme_early();
    let palette = theme.palette();
    let colors_enabled = help_colors_enabled();
    let compact = compact_after_help(raw_after_help);
    if !colors_enabled {
        return compact;
    }
    let leading_whitespace =
        |line: &str| -> String { line.chars().take_while(|c| c.is_whitespace()).collect() };
    let mut colorized = String::new();
    for line in compact.split('\n') {
        // Section heading: any line whose non-space chars are all
        // uppercase ASCII letters / spaces / hyphens. Catches
        // `EXAMPLES`, `SEE ALSO`, `NOTES` etc. without matching
        // prose that happens to start with a capital.
        let trimmed_line = line.trim_start();
        let is_heading = !trimmed_line.is_empty()
            && trimmed_line.len() < 40
            && trimmed_line
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == ' ' || c == '-');
        if is_heading {
            colorized.push_str(&leading_whitespace(line));
            colorized.push_str(&trimmed_line.style(palette.header).underline().to_string());
            colorized.push('\n');
            continue;
        }
        if let Some(shell_command) = trimmed_line.strip_prefix("$ ") {
            colorized.push_str(&leading_whitespace(line));
            colorized.push_str(&"$ ".style(palette.dim).to_string());
            colorized.push_str(&paint_command(shell_command, &palette, colors_enabled));
            colorized.push('\n');
            continue;
        }
        // Comment-style prose lines (our after_help blocks use `#` for
        // the explanatory line above each command). Render dim so the
        // example shell lines read as the primary content.
        if let Some(comment_body) = trimmed_line.strip_prefix("# ") {
            colorized.push_str(&leading_whitespace(line));
            colorized.push_str(&format!("# {comment_body}").style(palette.dim).to_string());
            colorized.push('\n');
            continue;
        }
        // Anything else: unchanged (typically a blank line or
        // prose that we want to remain uncolored).
        colorized.push_str(line);
        colorized.push('\n');
    }
    // `split('\n')` yields an empty trailing element for text ending
    // in `\n`; strip the extra newline our loop appended.
    if colorized.ends_with('\n') && !compact.ends_with('\n') {
        colorized.pop();
    }
    colorized
}

fn compact_after_help(raw_after_help: &str) -> String {
    let mut out = String::new();
    let mut command_count = 0usize;
    let mut keep_next_command_comment = true;
    let mut previous_blank = false;
    for line in raw_after_help.lines() {
        let trimmed = line.trim_start();
        if trimmed == "SAMPLE OUTPUT" {
            break;
        }
        if trimmed.starts_with("# ") {
            keep_next_command_comment = command_count < MAX_SUBCOMMAND_EXAMPLE_COMMANDS;
            if !keep_next_command_comment {
                continue;
            }
        } else if trimmed.starts_with("$ ") {
            if command_count >= MAX_SUBCOMMAND_EXAMPLE_COMMANDS {
                keep_next_command_comment = false;
                continue;
            }
            command_count += 1;
            keep_next_command_comment = true;
        } else if !trimmed.is_empty() {
            keep_next_command_comment = true;
        } else if !keep_next_command_comment {
            continue;
        }
        if trimmed.is_empty() {
            if previous_blank {
                continue;
            }
            previous_blank = true;
        } else {
            previous_blank = false;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_end().to_string()
}

/// Paint a shell command line: the binary + subcommand get `name`
/// color, flags get `kind`, positional / string arguments stay dim.
pub(crate) fn paint_command(cmd: &str, palette: &theme::ChromePalette, colors: bool) -> String {
    use owo_colors::OwoColorize;
    if !colors {
        return cmd.to_string();
    }
    let mut out = String::new();
    for (token_index, tok) in cmd.split_whitespace().enumerate() {
        if token_index > 0 {
            out.push(' ');
        }
        if tok.starts_with("--") || tok.starts_with('-') {
            out.push_str(&tok.style(palette.kind).to_string());
        } else if token_index == 0 || (token_index == 1 && !tok.starts_with("./") && !tok.contains('=')) {
            // `bonsai-ninja` or its subcommand name.
            out.push_str(&tok.style(palette.name).bold().to_string());
        } else {
            out.push_str(&tok.style(palette.dim).to_string());
        }
    }
    out
}

/// Custom root help template. Matches clap's default shape but drops
/// `{subcommands}` (we render our own grouped list before global
/// options) and colorizes the `OPTIONS:` section heading with the
/// active theme.
pub(crate) fn themed_help_template() -> String {
    let theme = resolve_theme_early();
    let palette = theme.palette();
    let colors = help_colors_enabled();
    let usage_heading = help_section_header("USAGE:", &palette, colors);
    let options_heading = help_section_header("OPTIONS:", &palette, colors);
    let command_groups = themed_command_groups();
    format!(
        "{{about-with-newline}}\n\
         {usage_heading} {{usage}}\n\
         \n\
         {command_groups}\n\
         \n\
         {options_heading}\n\
         {{options}}{{after-help}}"
    )
}

/// If argv contains `--help` / `-h`, render the target command's
/// full help with body-text coloring applied, print it, and return
/// the exit code the caller should use. Returns `None` when no help
/// was requested, letting main() fall through to clap's normal
/// parsing.
///
/// Clap's derive-generated help colors chrome (Usage, section
/// headings, flag literals, placeholders) via the `styles`
/// attribute, but has no style slot for per-flag description body
/// text. That body text comes from `///` doc comments and clap
/// emits it as raw terminal-default. This function fixes that by
/// post-processing clap's already-rendered help: lines that look
/// like flag descriptions (indented >= 10 spaces, no existing ANSI
/// escape) get wrapped in the palette's `dim` slot so they read as
/// muted body text consistent with the rest of the themed output.
pub(crate) fn try_themed_help() -> Option<i32> {
    use clap::CommandFactory;
    use std::io::Write;

    let argv: Vec<String> = std::env::args().collect();
    // Find either `--help` or `-h` anywhere after the first argument.
    // Anything after a `--` marker is ignored (positional argument
    // scope).
    let mut help_requested = false;
    let mut long_help_requested = false;
    for arg in argv.iter().skip(1) {
        if arg == "--" {
            break;
        }
        if arg == "--help" {
            help_requested = true;
            long_help_requested = true;
            break;
        }
        if arg == "-h" {
            help_requested = true;
            break;
        }
    }
    if !help_requested {
        return None;
    }

    // Walk argv collecting the subcommand CHAIN (e.g. `cache stats`,
    // `security <WORKSPACE> pack`) — not just the first level. Flags
    // we handle ourselves: --theme, --no-color, --no-cache,
    // --no-progress. Unrecognised tokens at a level that DOES have
    // subcommands (like `security`'s `<WORKSPACE>` positional before
    // the action) are treated as positionals and skipped so the walker
    // keeps scanning for a subcommand match. When the current command
    // has no subcommands, any unrecognised token ends the walk.
    let mut command = Cli::command();
    let mut argv_iter = argv.iter().skip(1).peekable();
    while let Some(arg) = argv_iter.next() {
        if arg == "--help" || arg == "-h" || arg == "--" {
            break;
        }
        if arg == "--theme" || arg == "--no-color" || arg == "--no-cache" || arg == "--no-progress" {
            if arg == "--theme" {
                argv_iter.next();
            }
            continue;
        }
        if arg.starts_with("--") || arg.starts_with('-') {
            return None;
        }
        match command.find_subcommand(arg.as_str()) {
            Some(next) => {
                command = next.clone();
            }
            None => {
                // If the current command still has subcommands, this
                // token is a positional for the current level (e.g.
                // `security <WORKSPACE>` before `pack`). Skip it and
                // keep looking. If not, we've fully descended.
                if command.get_subcommands().next().is_some() {
                    continue;
                }
                break;
            }
        }
    }

    // Render clap help. `write_long_help(writer)` strips ANSI
    // when the target isn't a TTY (our `Vec<u8>`, clap can't tell),
    // which would drop the pre-colored escapes embedded by
    // `themed_subcommand_long_about`. Use `render_long_help()` — it
    // returns a `StyledStr` — and emit the ANSI-bearing form when
    // colors are enabled, plain `Display` otherwise. `-h` intentionally
    // uses clap's short renderer; `--help` uses the long renderer.
    let styled = if long_help_requested {
        command.render_long_help()
    } else {
        command.render_help()
    };
    let rendered_help = if help_colors_enabled() {
        styled.ansi().to_string()
    } else {
        styled.to_string()
    };
    let rendered_help = rendered_help
        .replace("Print help (see more with '--help')", "Print help")
        .replace("Print help (see a summary with '-h')", "Print help");
    let rendered_help = normalize_help_section_casing(&rendered_help);

    // `colorize_help_body` both reflows `COMMANDS:` blocks into the
    // roomier name-on-its-own-line shape AND paints description
    // bodies in the palette's dim slot. The reflow runs
    // unconditionally (it's a readability fix, not a color-only
    // concern); the color pass short-circuits when colors are off.
    let rendered = colorize_help_body(&rendered_help);
    let stdout_handle = std::io::stdout();
    let mut stdout_lock = stdout_handle.lock();
    let _ = stdout_lock.write_all(rendered.as_bytes());
    let _ = stdout_lock.flush();
    Some(0)
}

fn normalize_help_section_casing(rendered_help: &str) -> String {
    rendered_help
        .replace("Usage:", "USAGE:")
        .replace("Arguments:", "ARGUMENTS:")
        .replace("Options:", "OPTIONS:")
        .replace("Commands:", "COMMANDS:")
}

/// Post-process a clap-rendered help string. Two concerns:
///
/// 1. Flag-description body lines (10+ space-indented, plain text
///    without ANSI) get painted in the `dim` body slot.
/// 2. Parent-subcommand `COMMANDS:` blocks, which clap renders as a
///    single dense line per entry, get reflowed into the same shape
///    as the `OPTIONS:` list — command name on its own line, indented
///    dim description below, blank line between entries — so parent
///    helps read consistently with leaf helps.
pub(crate) fn colorize_help_body(rendered_help: &str) -> String {
    use owo_colors::OwoColorize;
    let theme = resolve_theme_early();
    let palette = theme.palette();
    let colors = help_colors_enabled();
    let mut out = String::with_capacity(rendered_help.len() + 256);
    let lines: Vec<&str> = rendered_help.split('\n').collect();
    let mut line_index = 0usize;
    let mut description_lines_for_item = 0usize;
    let mut compact_item_section = false;
    while line_index < lines.len() {
        let line = lines[line_index];
        let header_probe = strip_ansi_roughly(line);
        let header_trimmed = header_probe.trim();
        if matches!(
            header_trimmed,
            "Arguments:" | "ARGUMENTS:" | "Options:" | "OPTIONS:"
        ) {
            compact_item_section = true;
        } else if looks_like_section_header(line) && !header_probe.starts_with(char::is_whitespace) {
            compact_item_section = false;
        }
        if compact_item_section && line.trim().is_empty() {
            line_index += 1;
            continue;
        }
        if is_commands_header(line) {
            description_lines_for_item = 0;
            out.push_str(line);
            out.push('\n');
            line_index += 1;
            let mut first_entry = true;
            while line_index < lines.len() {
                let entry = lines[line_index];
                let trimmed = entry.trim_start();
                if trimmed.is_empty() || looks_like_section_header(entry) {
                    break;
                }
                let leading = entry.chars().take_while(|c| *c == ' ').count();
                if leading != 2 {
                    if !entry.trim().is_empty() {
                        out.push_str("          ");
                        if colors {
                            out.push_str(&trimmed.style(palette.dim).to_string());
                        } else {
                            out.push_str(trimmed);
                        }
                        out.push('\n');
                    }
                    line_index += 1;
                    continue;
                }
                if !first_entry {
                    out.push('\n');
                }
                first_entry = false;
                reflow_commands_entry(&mut out, entry, &palette, colors);
                line_index += 1;
            }
            out.push('\n');
            continue;
        }
        let already_has_ansi = line.contains('\x1b');
        let leading_space_count = line.chars().take_while(|c| *c == ' ').count();
        let has_content = !line.trim().is_empty();
        let is_description_body = !already_has_ansi && leading_space_count >= 10 && has_content;
        let stripped = strip_ansi_roughly(line);
        let trimmed = stripped.trim_start();
        let is_item_header = has_content
            && leading_space_count <= 6
            && (trimmed.starts_with('-') || trimmed.starts_with('<') || trimmed.starts_with('['));
        let is_section_header = looks_like_section_header(line);
        let is_value_metadata = trimmed.starts_with('[')
            || trimmed == "Possible values:"
            || trimmed == "Value hint:"
            || trimmed.starts_with("- ");
        let line = if compact_item_section && is_item_header && !is_description_body {
            compact_inline_item_line(line)
        } else {
            line.to_string()
        };
        if is_item_header || is_section_header || !has_content {
            description_lines_for_item = 0;
        }
        if is_description_body && colors {
            if !is_value_metadata {
                description_lines_for_item += 1;
                if description_lines_for_item > MAX_HELP_DESCRIPTION_LINES {
                    line_index += 1;
                    continue;
                }
            }
            let line = if is_value_metadata {
                line.to_string()
            } else {
                compact_description_line(&line)
            };
            out.push_str(&line.style(palette.dim).to_string());
        } else if is_description_body && !is_value_metadata {
            description_lines_for_item += 1;
            if description_lines_for_item > MAX_HELP_DESCRIPTION_LINES {
                line_index += 1;
                continue;
            }
            out.push_str(&compact_description_line(&line));
        } else {
            out.push_str(&line);
        }
        out.push('\n');
        line_index += 1;
    }
    if out.ends_with('\n') && !rendered_help.ends_with('\n') {
        out.pop();
    }
    out
}

fn compact_inline_item_line(line: &str) -> String {
    let leading: String = line.chars().take_while(|c| c.is_whitespace()).collect();
    let body = line.trim_start();
    let Some(split_at) = find_inline_help_split(body) else {
        return line.to_string();
    };
    let name = body[..split_at].trim_end();
    let desc = body[split_at..].trim_start();
    if desc.is_empty() {
        return line.to_string();
    }
    let compact_desc = compact_description_line(&format!("          {desc}"));
    format!("{leading}{name}  {}", compact_desc.trim_start())
}

fn find_inline_help_split(body: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        if bytes[idx] == b' ' && bytes[idx + 1] == b' ' {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

fn compact_description_line(line: &str) -> String {
    const MAX_CHARS: usize = 112;

    let leading: String = line.chars().take_while(|c| c.is_whitespace()).collect();
    let body = line.trim_start();
    if body.chars().count() <= MAX_CHARS {
        return line.to_string();
    }
    let compact_body = if let Some(sentence_end) = first_sentence_end(body) {
        body[..sentence_end].trim_end()
    } else {
        body
    };
    if compact_body.chars().count() <= MAX_CHARS {
        return format!("{leading}{compact_body}");
    }

    let mut end = 0usize;
    for (count, (idx, ch)) in compact_body.char_indices().enumerate() {
        if count >= MAX_CHARS {
            break;
        }
        end = idx + ch.len_utf8();
    }
    if let Some(word_boundary) = compact_body[..end].rfind(char::is_whitespace) {
        end = word_boundary;
    }
    let truncated =
        compact_body[..end].trim_end_matches(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == ':');
    format!("{leading}{truncated}...")
}

fn wrap_words(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line_len = 0usize;
    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if line_len > 0 && line_len + 1 + word_len > width {
            out.push('\n');
            line_len = 0;
        } else if line_len > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += word_len;
    }
    out
}

fn first_sentence_end(body: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    for (idx, ch) in body.char_indices() {
        if ch != '.' && ch != '!' && ch != '?' {
            continue;
        }
        let next = idx + ch.len_utf8();
        let sentence = &body[..next];
        if sentence.ends_with("e.g.") || sentence.ends_with("i.e.") {
            continue;
        }
        if next >= body.len() || bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
            return Some(next);
        }
    }
    None
}

/// `COMMANDS:` header detector. Matches either the plain string or a
/// clap-styled variant (ANSI escapes around it).
fn is_commands_header(line: &str) -> bool {
    matches!(strip_ansi_roughly(line).trim_end(), "Commands:" | "COMMANDS:")
}

/// Generic section-header detector used to know when a block has
/// ended. Trims to a colon-terminated or ALL-CAPS label at column 0.
fn looks_like_section_header(line: &str) -> bool {
    let stripped = strip_ansi_roughly(line);
    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        return false;
    }
    if !stripped.starts_with(|c: char| !c.is_whitespace()) {
        return false;
    }
    trimmed.ends_with(':')
        || trimmed
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == ' ' || c == '-')
}

/// Cheap ANSI CSI stripper — just enough to make
/// `"\x1b[1mCOMMANDS:\x1b[0m"` match `COMMANDS:` for header
/// detection. Not for measurement.
fn strip_ansi_roughly(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut byte_index = 0;
    while byte_index < bytes.len() {
        if bytes[byte_index] == 0x1b && byte_index + 1 < bytes.len() && bytes[byte_index + 1] == b'[' {
            byte_index += 2;
            while byte_index < bytes.len() && !(0x40..=0x7E).contains(&bytes[byte_index]) {
                byte_index += 1;
            }
            if byte_index < bytes.len() {
                byte_index += 1;
            }
            continue;
        }
        let slice = &s[byte_index..];
        if let Some(ch) = slice.chars().next() {
            out.push(ch);
            byte_index += ch.len_utf8();
        } else {
            byte_index += 1;
        }
    }
    out
}

/// Rewrite one `  name  description` line into a two-row entry: the
/// name on a 2-space-indented row (themed bold + `palette.name`), the
/// description indented 10 spaces + dim below. Matches the `OPTIONS:`
/// block shape so parent subcommand helps read consistently.
fn reflow_commands_entry(out: &mut String, entry: &str, palette: &theme::ChromePalette, colors: bool) {
    use owo_colors::OwoColorize;
    let body = &entry[2..];
    let mut split_index: Option<usize> = None;
    let bytes = body.as_bytes();
    let mut split_scan_index = 0;
    while split_scan_index + 1 < bytes.len() {
        if bytes[split_scan_index] == b' ' && bytes[split_scan_index + 1] == b' ' {
            split_index = Some(split_scan_index);
            break;
        }
        split_scan_index += 1;
    }
    let (name_span, desc) = match split_index {
        Some(idx) => (&body[..idx], body[idx..].trim_start()),
        None => (body, ""),
    };
    out.push_str("  ");
    // clap paints subcommand names bold (no color slot); strip its
    // styling so we can repaint with bold + palette.name, matching
    // the rest of the themed chrome.
    let clean_name = if name_span.contains('\x1b') {
        strip_ansi_roughly(name_span)
    } else {
        name_span.to_string()
    };
    if colors {
        out.push_str(&clean_name.style(palette.name).bold().to_string());
    } else {
        out.push_str(&clean_name);
    }
    out.push('\n');
    if !desc.is_empty() {
        let desc = compact_description_line(&format!("          {desc}"));
        if colors {
            out.push_str(&desc.style(palette.dim).to_string());
        } else {
            out.push_str(&desc);
        }
        out.push('\n');
    }
}

/// Whether ANSI escapes should be emitted in the help output. Mirrors
/// the same rules as `Ui::new`: NO_COLOR env, --no-color flag, and a
/// non-TTY stdout all disable colors.
pub(crate) fn help_colors_enabled() -> bool {
    use std::io::IsTerminal;
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::args().any(|a| a == "--no-color") {
        return false;
    }
    std::io::stdout().is_terminal()
}
