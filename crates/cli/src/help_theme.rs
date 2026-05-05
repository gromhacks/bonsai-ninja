//! Themed `--help` rendering.
//!
//! Clap's default help is already structured; the pieces here
//! supplement it with:
//!
//! - A grouped `after_long_help` block (`HELP_GROUPS`) that
//!   replaces clap's auto `Commands:` list with a curated layout.
//! - An `EXAMPLES` block ([`HELP_EXAMPLES`]) themed with the same
//!   palette as the rest of the CLI.
//! - Post-processing of clap's rendered help so indented body text
//!   picks up the active theme color (clap doesn't expose a style
//!   slot for body prose).
//!
//! Entry points: [`themed_after_help`] for the root `--help`,
//! [`themed_subcommand_long_about`] / [`themed_subcommand_after_help`]
//! for per-subcommand `--help`, and [`try_themed_help`] as the early
//! dispatcher that intercepts `--help` / `-h` before clap runs.

use crate::theme;
use crate::{resolve_theme_early, Cli};

pub(crate) const CLI_LONG_ABOUT: &str = "\
bonsai-ninja reads a directory of source code, builds a workspace-wide
index of decls / calls / refs / imports / strings / assignments /
comments, and lets you trace execution flow across modules and
classes in 21 languages.

The headline command is `inspect` — give it a query, it surfaces every
flow that reaches the match. The headline security command is
`security taint-analysis` — it applies YAML source/sink/sanitizer
rules to the indexed graph with exact source seeds and emits a
paginated source→sink finding report.
`export` dumps the full taint graph (functions, call edges,
propagations, entry-points, chains) as JSON so downstream tooling can
reproduce every finding without re-running the analyzer.

Supports: Python, JavaScript, TypeScript, Java, Kotlin, C#, Swift,
Scala, Go, Rust, PHP, Ruby, C, C++, Perl, Dart, Lua, Elixir,
Erlang, Objective-C, Solidity.

Run `bonsai-ninja --version` to print the binary version.";

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
        "Flow analysis",
        &[
            ("inspect", "Find every cross-module flow that reaches a match"),
            ("trace", "Expand a function's call tree end-to-end"),
        ],
    ),
    (
        "Workspace",
        &[
            ("index", "Ingest a workspace and print stats"),
            ("export", "Dump the full index as JSON"),
        ],
    ),
    (
        "Cache",
        &[
            // The dataflow sidecar (`.bonsai/dataflow.v2.bin`) stores
            // the workspace-wide taint facts built at `Workspace::open`.
            // These subcommands are the UI for inspecting and
            // invalidating it without leaving the CLI.
            (
                "cache stats",
                "Report cache config + on-disk `.bonsai/` sidecar size",
            ),
            (
                "cache clear",
                "Delete `.bonsai/` sidecars (add `--dataflow-only` for just the taint cache)",
            ),
            (
                "cache rebuild",
                "Delete the dataflow sidecar and rebuild it from scratch",
            ),
        ],
    ),
    (
        "Browse facts",
        &[
            ("defs", "Functions / methods / classes / structs"),
            ("calls", "Call sites with caller, location, code"),
            ("imports", "import / use / include statements (alias, wildcard)"),
            ("vars", "Assignments captured from each function's flow"),
            ("strings", "String / char literals with category (sql / url / …)"),
            (
                "comments",
                "Comments classified by kind (todo / fixme / security / doc)",
            ),
            ("args", "Call-site arguments with position + value"),
            ("classes", "Classes / structs / traits / interfaces / enums"),
            ("refs", "Every reference to a symbol (read / call / type)"),
            ("search", "Prefix-first fuzzy search over every browse fact"),
        ],
    ),
    (
        "Navigation",
        &[
            (
                "tree",
                "Workspace tree with finding / flow / cross-file edge annotations per file",
            ),
            (
                "read-file",
                "Single-file view with marks for findings / sources / sinks plus cross-file caller / callee bodies",
            ),
        ],
    ),
    (
        // Rulepack-driven security analysis. Every subcommand under
        // `security` loads the YAML pack at `./security-patterns/`
        // (override with `--rules-dir`) and uses the rules as the
        // query — no search string required.
        "Security",
        &[
            (
                "security sources",
                "Enumerate source matches — table, rulepack is the query",
            ),
            (
                "security sinks",
                "Enumerate sink matches with severity column + `--severity` filter",
            ),
            (
                "security sanitizers",
                "Enumerate sanitizer call sites — cleansing ops the pack recognizes",
            ),
            (
                "security deps",
                "Packages the rulepack mentions whose imports the workspace uses",
            ),
            (
                "security taint-analysis",
                "Apply source/sink rules to taint; paginated finding report",
            ),
            (
                "security source-analysis",
                "Map downstream taint/call paths from source matches",
            ),
            (
                "security pack",
                "Audit the rulepack itself — per-lang / per-category coverage + gaps",
            ),
        ],
    ),
    (
        "Debug dumps",
        &[
            // One command per analysis-pipeline layer. Order mirrors
            // the pipeline itself: parse → HIR → CFG → call graph →
            // resolver → taint. When `inspect` produces a surprising
            // result, walk down the list to find the layer that
            // already disagrees with your expectation.
            ("dump-ast", "Tree-sitter parse tree (per file or per function)"),
            ("dump-hir", "HIR — flow-event tree of a single function"),
            ("dump-cfg", "CFG — basic blocks derived from the flow-event tree"),
            (
                "dump-callgraph",
                "Per-function caller / outgoing counts (sorted hottest-first)",
            ),
            (
                "dump-edges",
                "Resolved call edges (FuncId-keyed, with precision tag + call site)",
            ),
            (
                "dump-resolve",
                "Name resolver — every stage's input + output for one name",
            ),
            (
                "dump-taint",
                "Intraprocedural + interprocedural taint propagation from a seeded entry",
            ),
            ("diagnostics", "Run every adapter's diagnostic pass"),
        ],
    ),
];

/// Commands & arguments shown in `EXAMPLES`. Split into text + command
/// fragments so the builder can paint commands / flags separately.
pub(crate) const HELP_EXAMPLES: &[(&str, &[&str])] = &[
    (
        "Find every flow that reaches a suspected sink (command injection):",
        &[
            "bonsai-ninja inspect ./src --query os.system",
            "bonsai-ninja inspect ./src --query exec --regex",
        ],
    ),
    (
        "Browse every call site that invokes a specific callee:",
        &["bonsai-ninja calls ./src --callee os.system"],
    ),
    (
        "List every definition in a file, JSON output for tooling:",
        &["bonsai-ninja defs ./src --file auth_service.py --format json"],
    ),
    (
        "Sweep TODO / FIXME / SECURITY markers across the workspace:",
        &[
            "bonsai-ninja comments ./src --kind todo",
            "bonsai-ninja comments ./src --kind security",
        ],
    ),
    (
        "Trace a specific entry point end-to-end:",
        &["bonsai-ninja trace ./src handle_request"],
    ),
    (
        "Run the rulepack security scan (source → sink flows):",
        &[
            "bonsai-ninja security ./src taint-analysis --severity high",
            "bonsai-ninja security ./src sinks --tag command-injection",
            "bonsai-ninja security ./src pack --audit",
        ],
    ),
    (
        "Emit SARIF 2.1.0 for SAST-tool integration (GitHub code scanning / IDEs):",
        &[
            "bonsai-ninja security ./src taint-analysis --format sarif > findings.sarif.json",
            "BONSAI_RULES_DIR=/path/to/security-patterns bonsai-ninja security ./src taint-analysis --format sarif",
        ],
    ),
    (
        "Navigate the workspace with finding / cross-file annotations:",
        &[
            "bonsai-ninja tree ./src --severity high",
            "bonsai-ninja read-file ./src auth/verify_token.py --compact",
        ],
    ),
    (
        "Export the full taint graph for downstream tooling:",
        &[
            "bonsai-ninja export ./src > index.json",
            "bonsai-ninja export ./src | jq '.taint_graph | keys'",
        ],
    ),
    (
        "Stable content-hash ids round-trip across runs:",
        &[
            "bonsai-ninja inspect ./src --flow F:0123456789abcdef",
            "bonsai-ninja dump-edges ./src --edge E:aabbccdd",
            "bonsai-ninja dump-taint ./src --source handle_request --taint T:abc123",
        ],
    ),
    (
        "Theme selection (default: moss):",
        &[
            "BONSAI_THEME=dracula bonsai-ninja defs ./src",
            "bonsai-ninja --theme retro-amber calls ./src",
            "bonsai-ninja --theme earthy-dark defs ./src",
        ],
    ),
];

/// Build the after-help block shown below clap's auto-generated options
/// list. Colors are applied via ANSI when the target terminal supports
/// them; otherwise the output is plain text. The theme is resolved from
/// `--theme` / `BONSAI_THEME` so the help menu picks up the same palette as
/// the rest of the CLI.
pub(crate) fn themed_after_help() -> String {
    use owo_colors::OwoColorize;

    let theme = resolve_theme_early();
    let palette = theme.palette();
    let colors = help_colors_enabled();

    // Local painter: apply the palette slot only when colors are on.
    let paint = |text: &str, style: &owo_colors::Style| -> String {
        if colors {
            text.style(*style).to_string()
        } else {
            text.to_string()
        }
    };
    // Section header: underlined + palette.header.
    let header = |text: &str| -> String {
        if colors {
            text.style(palette.header).underline().to_string()
        } else {
            text.to_string()
        }
    };

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

    // ── COMMAND GROUPS ────────────────────────────────────────────────
    out.push_str(&header("COMMAND GROUPS"));
    out.push('\n');
    for (group, entries) in HELP_GROUPS {
        out.push('\n');
        out.push_str("  ");
        out.push_str(&paint(group, &palette.accent));
        out.push('\n');
        for (cmd, desc) in *entries {
            out.push_str("    ");
            out.push_str(&paint(&pad(cmd, command_pad_width), &palette.name));
            out.push_str(&paint(desc, &palette.dim));
            out.push('\n');
        }
    }
    out.push('\n');

    // ── EXAMPLES ──────────────────────────────────────────────────────
    out.push_str(&header("EXAMPLES"));
    out.push('\n');
    for (prose, cmds) in HELP_EXAMPLES {
        out.push('\n');
        out.push_str("  ");
        out.push_str(&paint(prose, &palette.dim));
        out.push('\n');
        for cmd in *cmds {
            out.push_str("    ");
            out.push_str(&paint("$ ", &palette.dim));
            out.push_str(&paint_command(cmd, &palette, colors));
            out.push('\n');
        }
    }
    out.push('\n');

    // ── SEE ALSO ──────────────────────────────────────────────────────
    out.push_str(&header("SEE ALSO"));
    out.push_str("\n\n  ");
    out.push_str(&paint(
        "Run `bonsai-ninja <command> --help` for per-command usage + examples.",
        &palette.dim,
    ));
    out.push_str("\n  ");
    out.push_str(&paint("Common starting points: ", &palette.dim));
    for (i, cmd) in ["inspect", "trace", "defs", "calls", "refs"].iter().enumerate() {
        if i > 0 {
            out.push_str(&paint(", ", &palette.dim));
        }
        out.push_str(&paint(cmd, &palette.name));
    }
    out.push('\n');
    out
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
    if !help_colors_enabled() {
        return raw_prose.to_string();
    }
    // Split on backticks to highlight `ident` code references in the
    // `literal` slot color while the surrounding prose stays in the
    // dim body tone. The iterator alternates: even indices are
    // outside-backtick prose, odd indices are inside-backtick code.
    let mut colorized = String::new();
    for (segment_index, segment) in raw_prose.split('`').enumerate() {
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
    if !colors_enabled {
        return raw_after_help.to_string();
    }
    let leading_whitespace =
        |line: &str| -> String { line.chars().take_while(|c| c.is_whitespace()).collect() };
    let mut colorized = String::new();
    for line in raw_after_help.split('\n') {
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
    if colorized.ends_with('\n') && !raw_after_help.ends_with('\n') {
        colorized.pop();
    }
    colorized
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

/// Custom help template. Matches clap's default shape but drops
/// `{subcommands}` (we render our own grouped list in `after_help`) and
/// colorizes the `Options:` section heading with the active theme.
pub(crate) fn themed_help_template() -> String {
    use owo_colors::OwoColorize;
    let theme = resolve_theme_early();
    let palette = theme.palette();
    let options_heading = if help_colors_enabled() {
        "Options:".style(palette.header).underline().to_string()
    } else {
        "Options:".to_string()
    };
    format!(
        "{{about-with-newline}}\n\
         {{usage-heading}} {{usage}}\n\
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
    for arg in argv.iter().skip(1) {
        if arg == "--" {
            break;
        }
        if arg == "--help" || arg == "-h" {
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

    // Render clap's long help. `write_long_help(writer)` strips ANSI
    // when the target isn't a TTY (our `Vec<u8>`, clap can't tell),
    // which would drop the pre-colored escapes embedded by
    // `themed_subcommand_long_about`. Use `render_long_help()` — it
    // returns a `StyledStr` — and emit the ANSI-bearing form when
    // colors are enabled, plain `Display` otherwise.
    let styled = command.render_long_help();
    let rendered_help = if help_colors_enabled() {
        styled.ansi().to_string()
    } else {
        styled.to_string()
    };

    // `colorize_help_body` both reflows `Commands:` blocks into the
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

/// Post-process a clap-rendered help string. Two concerns:
///
/// 1. Flag-description body lines (10+ space-indented, plain text
///    without ANSI) get painted in the `dim` body slot.
/// 2. Parent-subcommand `Commands:` blocks, which clap renders as a
///    single dense line per entry, get reflowed into the same shape
///    as the `Options:` list — command name on its own line, indented
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
    while line_index < lines.len() {
        let line = lines[line_index];
        if is_commands_header(line) {
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
        if is_description_body && colors {
            out.push_str(&line.style(palette.dim).to_string());
        } else {
            out.push_str(line);
        }
        out.push('\n');
        line_index += 1;
    }
    if out.ends_with('\n') && !rendered_help.ends_with('\n') {
        out.pop();
    }
    out
}

/// `Commands:` header detector. Matches either the plain string or a
/// clap-styled variant (ANSI escapes around it).
fn is_commands_header(line: &str) -> bool {
    strip_ansi_roughly(line).trim_end() == "Commands:"
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
/// `"\x1b[1mCommands:\x1b[0m"` match `Commands:` for header
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
/// description indented 10 spaces + dim below. Matches the `Options:`
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
        out.push_str("          ");
        if colors {
            out.push_str(&desc.style(palette.dim).to_string());
        } else {
            out.push_str(desc);
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
