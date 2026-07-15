// The `cli_println!` / `cli_print!` macros do one extra
// `format_args!` expansion around the user's format string; a
// handful of deeply-nested interpolation call sites push the
// default 128-frame macro recursion limit slightly over. 256 is
// ample and cheap.
#![recursion_limit = "256"]
//! `bonsai-ninja` — the bonsai-ninja CLI.
//!
//! Two command groups:
//!
//! - **Flow commands** (the headline): `trace`, `diagnostics`,
//!   `dump-hir`, `dump-cfg`, `dump-callgraph`, `index`.
//! - **Browse / inspect commands**: `defs`, `entrypoints`, `calls`,
//!   `imports`, `vars`, `strings`, `args`, `operations`, `classes`, `refs`, `search`,
//!   `inspect`, `export`.
//!   All read from the same `GlobalIndex` + per-file `DeclIndex`, so
//!   behavior is uniform across every supported language.

use anyhow::Result;
use clap::Parser;
use theme::Theme;
use ui::Ui;

mod args;
mod commands;
mod filter;
mod footer;
mod help_theme;
mod output;
mod page_cache;
mod paging;
mod progress;
mod theme;
mod ui;

use args::{CacheAction, Cli, Cmd, SecurityAction};
use commands::{
    cmd_args, cmd_cache, cmd_calls, cmd_classes, cmd_comments, cmd_context, cmd_defs, cmd_diagnostics,
    cmd_dump_ast, cmd_dump_callgraph, cmd_dump_cfg, cmd_dump_edges, cmd_dump_hir, cmd_dump_resolution,
    cmd_dump_resolve, cmd_dump_taint, cmd_entrypoints, cmd_export, cmd_imports, cmd_index, cmd_inspect,
    cmd_operations, cmd_path, cmd_refs, cmd_search, cmd_slice, cmd_strings, cmd_trace, cmd_vars,
    paging_from_cli, paging_from_cli_output, resolve_symbol_arg, ArgsFilters, CallsFilters, ClassesFilters,
    CommentsFilters, DefsFilters, EntryPointsFilters, ImportsFilters, IndexCommandOptions,
    InspectCommandOptions, InspectFilters, InspectRenderOptions, OperationsFilters, PathCommandOptions,
    RefsFilters, SearchFilters, StringsFilters, VarsFilters,
};
use help_theme::try_themed_help;

const DEFAULT_RAYON_STACK_BYTES: usize = 64 * 1024 * 1024;

// CLI-wide stdout counter + counted print macros — defined up top so
// `cli_println!` / `cli_print!` are visible everywhere below (macro_rules
// is lexically scoped). Stderr (progress bars, errors, footer) bypasses
// the counter; only command-produced output reaches the footer's tally.
pub(crate) mod out_count {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static BYTES: AtomicUsize = AtomicUsize::new(0);
    static LINES: AtomicUsize = AtomicUsize::new(0);

    /// Precise counter invoked by `cli_print!` / `cli_println!`.
    /// Strips ANSI CSI / OSC escape sequences before tallying so the
    /// footer's `bytes` + `~tokens` reflect the *visible* output an
    /// LLM or `wc -c | sed 's/\x1b\[[0-9;]*m//g'` would see — not the
    /// raw stream with color codes. A styled line can be ~4× larger
    /// than its visible content, which badly inflates the heuristic
    /// `bytes / 4` token estimate used downstream.
    ///
    /// We count real embedded newlines + the optional terminator
    /// added by the `_println` variant so the final "N lines" number
    /// matches what the user visually sees. Newlines don't appear
    /// inside ANSI CSI sequences, so line counting stays correct
    /// on the raw buffer.
    pub(crate) fn add_counting(s: &str, trailing_newline: bool) {
        let visible_bytes = visible_byte_len(s);
        BYTES.fetch_add(visible_bytes, Ordering::Relaxed);
        #[allow(clippy::naive_bytecount)] // small token spans; bytecount crate not worth the dep
        let inner = s.as_bytes().iter().filter(|&&b| b == b'\n').count();
        LINES.fetch_add(inner + usize::from(trailing_newline), Ordering::Relaxed);
    }

    /// Total visible (ANSI-stripped) bytes emitted to stdout this run.
    /// During paged renders the page-cache buffer wins so the footer
    /// reports the size of the captured page rather than the full
    /// stream.
    pub(crate) fn bytes() -> usize {
        if let Some(bytes) = crate::page_cache::captured_bytes() {
            return bytes;
        }
        BYTES.load(Ordering::Relaxed)
    }

    /// Total newline-terminated lines emitted to stdout this run.
    pub(crate) fn lines() -> usize {
        LINES.load(Ordering::Relaxed)
    }

    /// Count the bytes of `s` that would survive ANSI-escape stripping.
    /// Recognises the two families the CLI emits through `comfy-table`
    /// + `owo-colors` + `syntect`:
    ///
    /// - **CSI**: `ESC [` … terminator in `@`..`~` (`0x40`..`0x7E`).
    ///   Covers SGR color/style (`\x1b[38;2;R;G;Bm`), cursor moves,
    ///   erase-in-line, etc.
    /// - **OSC**: `ESC ]` … `BEL` or `ESC \`. Covers terminal-title
    ///   and hyperlink sequences (`\x1b]8;;url\x1b\\`).
    ///
    /// Plus a few C0 single-byte controls we want to ignore (`\r`,
    /// bare `ESC`). Non-ANSI text is counted verbatim (including
    /// multi-byte UTF-8, which matches what `wc -c` reports).
    fn visible_byte_len(s: &str) -> usize {
        let bytes = s.as_bytes();
        let mut byte_index = 0;
        let mut visible = 0usize;
        while byte_index < bytes.len() {
            let byte = bytes[byte_index];
            if byte == 0x1b && byte_index + 1 < bytes.len() {
                match bytes[byte_index + 1] {
                    b'[' => {
                        // CSI: skip until a byte in 0x40..=0x7E.
                        byte_index += 2;
                        while byte_index < bytes.len() && !(0x40..=0x7E).contains(&bytes[byte_index]) {
                            byte_index += 1;
                        }
                        if byte_index < bytes.len() {
                            byte_index += 1;
                        }
                        continue;
                    }
                    b']' => {
                        // OSC: terminated by BEL (0x07) or ST (ESC \).
                        byte_index += 2;
                        while byte_index < bytes.len() {
                            if bytes[byte_index] == 0x07 {
                                byte_index += 1;
                                break;
                            }
                            if bytes[byte_index] == 0x1b
                                && byte_index + 1 < bytes.len()
                                && bytes[byte_index + 1] == b'\\'
                            {
                                byte_index += 2;
                                break;
                            }
                            byte_index += 1;
                        }
                        continue;
                    }
                    _ => {
                        // Bare ESC followed by a single byte (charset
                        // select, two-byte sequences). Skip both.
                        byte_index += 2;
                        continue;
                    }
                }
            }
            if byte == b'\r' {
                byte_index += 1;
                continue;
            }
            visible += 1;
            byte_index += 1;
        }
        visible
    }

    #[cfg(test)]
    #[path = "tests.rs"]
    mod tests;
}

/// Like `println!` but bumps the global CLI output tally so the
/// end-of-command footer can report "N lines · M bytes · ~K tokens".
///
/// Writes directly to a locked stdout handle rather than delegating
/// to `println!` — a `println!`-wrapping version would double-expand
/// through `format_args!` and blow past Rust's macro recursion limit
/// on deeply-nested call sites.
#[macro_export]
macro_rules! cli_println {
    () => {{
        if $crate::page_cache::write("\n") {
        } else if $crate::output::write_line("") {
        } else {
            use std::io::Write as _;
            let mut h = std::io::stdout().lock();
            let _ = h.write_all(b"\n");
            $crate::out_count::add_counting("", true);
        }
    }};
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let s: String = std::fmt::format(std::format_args!($($arg)*));
        if $crate::page_cache::write(&format!("{s}\n")) {
        } else if $crate::output::write_line(&s) {
        } else {
            let mut h = std::io::stdout().lock();
            let _ = h.write_all(s.as_bytes());
            let _ = h.write_all(b"\n");
            $crate::out_count::add_counting(&s, true);
        }
    }};
}

/// Like `print!` but bumps the global CLI output tally (no
/// trailing newline). Same direct-write shape as [`cli_println!`].
#[macro_export]
macro_rules! cli_print {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let s: String = std::fmt::format(std::format_args!($($arg)*));
        if $crate::page_cache::write(&s) {
        } else if $crate::output::write_str(&s) {
        } else {
            let mut h = std::io::stdout().lock();
            let _ = h.write_all(s.as_bytes());
            $crate::out_count::add_counting(&s, false);
        }
    }};
}

pub(crate) static UI_CELL: std::sync::OnceLock<Ui> = std::sync::OnceLock::new();

/// Global `--no-cache` toggle. Set once at startup from the CLI flag or
/// `BONSAI_NO_CACHE` env var; read by the inspect `ChainCache`
/// constructor. Defaults to `false` (caching on).
pub(crate) static NO_CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Optional process-wide CLI parse timeout override in milliseconds.
/// `None` lets the parser use `BONSAI_PARSE_TIMEOUT_MS` or its default.
pub(crate) static PARSE_TIMEOUT_MS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();

/// Read `--theme` / `BONSAI_THEME` from argv + env *before* clap parses, so
/// clap's own help renderer can use the chosen palette. Falls back to
/// `moss` (the bonsai-ninja house theme) when no theme is requested
/// or the name is unknown.
///
/// Parsing is best-effort: we walk argv looking for `--theme X`,
/// `--theme=X`, or an environment variable. We don't validate any other
/// flags — that's clap's job on the real pass.
pub(crate) fn resolve_theme_early() -> Theme {
    let args: Vec<String> = std::env::args().collect();
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--theme" {
            if let Some(v) = iter.next() {
                if let Some(t) = Theme::parse(v) {
                    return t;
                }
            }
        } else if let Some(v) = arg.strip_prefix("--theme=") {
            if let Some(t) = Theme::parse(v) {
                return t;
            }
        }
    }
    std::env::var("BONSAI_THEME")
        .ok()
        .as_deref()
        .and_then(Theme::parse)
        .unwrap_or(Theme::Moss)
}

/// Clap styles used by `--help` rendering. Wires the active theme into
/// clap's header / usage / literal / placeholder slots so the help menu
/// matches the rest of the CLI's chrome.
pub(crate) fn clap_help_styles() -> clap::builder::styling::Styles {
    resolve_theme_early().clap_styles()
}

/// Borrow the process-wide [`Ui`] renderer. Initialised once from
/// `main()` with the resolved theme + `--no-color` choice; every
/// `cmd_*` handler calls this to get a themed-output handle without
/// threading one through every signature. Falls back to a
/// `Moss` default if called before `main()` initialised the cell
/// (shouldn't happen under normal CLI invocation).
pub(crate) fn ui() -> &'static Ui {
    UI_CELL.get_or_init(|| Ui::new(false, Theme::Moss))
}

fn main() -> Result<()> {
    // Run the whole CLI on a worker thread with a large stack. The
    // main thread's default 8 MB stack overflows (SIGABRT, unrecoverable
    // in Rust) on deeply-nested source — the recursive tree walk in
    // decl extraction / lowering descends one frame per nesting level,
    // so ~1300 nested blocks abort the process. Parse/analysis rayon
    // workers already run with a large stack for the same reason; the
    // single-file / serial phases run here on `main`, so give this the
    // same headroom. Errors and exit codes are unchanged: the worker's
    // `Result` is returned verbatim (std's `Termination` renders it),
    // and a worker panic keeps the standard 101 exit after its message.
    let worker = std::thread::Builder::new()
        .name("bonsai-main".to_string())
        .stack_size(configured_main_stack_bytes())
        .spawn(real_main)
        .expect("spawn bonsai worker thread");
    match worker.join() {
        Ok(result) => result,
        Err(_) => std::process::exit(101),
    }
}

fn real_main() -> Result<()> {
    install_global_rayon_pool();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "error".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    // Intercept `--help` / `-h` before clap parses so we can render
    // fully themed help output. Clap's derive-generated help only
    // colors chrome (Usage, section headings, flag literals); flag
    // descriptions come from `///` doc comments and have no style
    // slot. We render clap's help to a buffer and post-process it
    // to colorize description body text in the active palette.
    if let Some(ec) = try_themed_help() {
        std::process::exit(ec);
    }

    let cli = Cli::parse();
    let theme = cli
        .theme
        .as_deref()
        .or(option_env!("BONSAI_THEME"))
        .and_then(Theme::parse)
        .or_else(|| {
            std::env::var("BONSAI_THEME")
                .ok()
                .as_deref()
                .and_then(Theme::parse)
        })
        .unwrap_or(Theme::Moss);
    let _ = UI_CELL.set(Ui::new(cli.no_color, theme));
    let no_cache_env = std::env::var("BONSAI_NO_CACHE")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
    let _ = NO_CACHE.set(cli.no_cache || no_cache_env);
    let _ = PARSE_TIMEOUT_MS.set(cli.parse_timeout_ms);
    // Mirror `--debug <categories>` into `BONSAI_DEBUG` so the
    // diagnostics::debug filter (read on first call) sees the
    // categories the user enabled. CLI flag takes precedence over
    // any pre-set env value — explicit beats inherited.
    if let Some(categories) = cli.debug.as_deref().filter(|c| !c.is_empty()) {
        std::env::set_var("BONSAI_DEBUG", categories);
    }
    // Progress visibility is independent from color. `--no-color`
    // keeps progress visible in interactive terminals, but renders it
    // without ANSI color; `--no-progress` / `NO_PROGRESS` hide it.
    progress::set_no_color(cli.no_color);
    progress::set_no_progress(cli.no_progress);
    // Secondary output filters (`--contains` / `--not-contains`) are
    // global flags applied at render time. They're part of the
    // normalized argv, so the rendered-page cache key already varies by
    // filter (a filtered run never replays an unfiltered run's pages);
    // the expensive taint *analysis* payload is keyed separately so it
    // is reused across filter changes.
    filter::init(&cli.contains, &cli.not_contains);
    let output_path = command_output_path(&cli.command).map(std::path::Path::to_path_buf);
    output::init(output_path.as_deref())?;
    if let Some(workspace) = command_workspace_for_page_cache(&cli.command) {
        if page_cache::replay_if_hit(workspace)? {
            output::finish()?;
            return Ok(());
        }
    }
    let result = match cli.command {
        Cmd::Index {
            workspace,
            watch,
            interval_ms,
            prewarm_dataflow,
            semantic,
            structural_only,
        } => cmd_index(
            &workspace,
            IndexCommandOptions {
                watch,
                interval_ms,
                prewarm_dataflow,
                semantic,
                structural_only,
            },
        ),
        Cmd::Context { workspace, .. } => cmd_context(&workspace),
        Cmd::Trace {
            workspace,
            symbol,
            function,
            from,
            to,
            context,
            page,
            all,
            max_depth,
            max_steps,
            max_branch_fanout,
            max_loop_iters,
            format,
            output: _,
        } => {
            let fn_arg = function.or(symbol);
            let paging = paging_from_cli_output(context.as_deref(), page.as_deref(), all, format)?;
            let trace_opts = bonsai_sdk::CrossModuleOptions {
                max_depth,
                max_steps,
                max_branch_fanout,
                max_loop_iters,
            };
            cmd_trace(&workspace, fn_arg, from, to, paging, format, trace_opts)
        }
        Cmd::Path {
            workspace,
            from,
            to,
            regex,
            max_paths,
            max_depth,
            max_probes,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_path(
            &workspace,
            PathCommandOptions {
                from: &from,
                to: &to,
                regex,
                max_paths,
                max_depth,
                max_probes,
                paging_cfg: paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
                format,
            },
        ),
        Cmd::Slice {
            workspace,
            symbol,
            line,
            file,
            max_steps,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_slice(
            &workspace,
            &symbol,
            line,
            file.as_deref(),
            max_steps,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            format,
        ),
        Cmd::Show {
            workspace,
            id,
            query,
            in_file,
            taint_source,
            taint_seeds,
            taint_sanitizers,
            taint_sink,
            taint_budget,
            taint_intra_worklist_cap,
            compact,
            context,
            page,
            all,
            format,
            rules_dir,
            output: _,
        } => commands::show::cmd_show(commands::show::ShowArgs {
            workspace: &workspace,
            id: &id,
            query: query.as_deref(),
            in_file: in_file.as_deref(),
            taint_source: taint_source.as_deref(),
            taint_seeds: &taint_seeds,
            taint_sanitizers: &taint_sanitizers,
            taint_sink: taint_sink.as_deref(),
            taint_budget,
            taint_intra_worklist_cap,
            compact,
            context: context.as_deref(),
            page: page.as_deref(),
            all,
            format,
            rules_dir: rules_dir.as_deref(),
        }),
        Cmd::Diagnostics { workspace } => cmd_diagnostics(&workspace),
        Cmd::DumpHir {
            workspace,
            symbol_pos,
            symbol,
        } => {
            let sym = resolve_symbol_arg(symbol_pos, symbol, "symbol")?;
            cmd_dump_hir(&workspace, &sym)
        }
        Cmd::DumpCfg {
            workspace,
            symbol_pos,
            symbol,
        } => {
            let sym = resolve_symbol_arg(symbol_pos, symbol, "symbol")?;
            cmd_dump_cfg(&workspace, &sym)
        }
        Cmd::DumpCallgraph {
            workspace,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_dump_callgraph(
            &workspace,
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            format,
        ),
        Cmd::DumpEdges {
            workspace,
            from,
            to,
            precision,
            compact,
            edge,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_dump_edges(
            &workspace,
            from.as_deref(),
            to.as_deref(),
            precision,
            compact,
            edge.as_deref(),
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            format,
        ),
        Cmd::DumpResolution {
            workspace,
            file,
            unresolved_only,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_dump_resolution(
            &workspace,
            file.as_deref(),
            unresolved_only,
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            format,
        ),
        Cmd::DumpAst {
            workspace,
            symbol_pos,
            file,
            function,
            compact,
            max_depth,
            node,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => {
            // --function takes precedence over the positional symbol.
            let function_scope = function.or(symbol_pos);
            let paging = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_dump_ast(
                &workspace,
                file.as_deref(),
                function_scope.as_deref(),
                compact,
                max_depth,
                node.as_deref(),
                limit,
                paging,
                format,
            )
        }
        Cmd::DumpResolve {
            workspace,
            name_pos,
            name,
            in_file,
            compact,
            candidate,
            format,
            output: _,
        } => {
            // --name takes precedence over the positional name.
            let query_name = name.or(name_pos).ok_or_else(|| {
                anyhow::anyhow!("dump-resolve needs a name to resolve (positional arg or --name)")
            })?;
            cmd_dump_resolve(
                &workspace,
                &query_name,
                in_file.as_deref(),
                compact,
                candidate.as_deref(),
                format,
            )
        }
        Cmd::DumpTaint {
            workspace,
            source,
            seeds,
            sanitizers,
            sink,
            budget,
            intra_worklist_cap,
            compact,
            taint,
            context,
            page,
            all,
            format,
            output: _,
        } => {
            let paging = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_dump_taint(
                &workspace,
                &source,
                &seeds,
                &sanitizers,
                sink.as_deref(),
                budget,
                intra_worklist_cap,
                compact,
                taint.as_deref(),
                paging,
                format,
            )
        }

        Cmd::Defs {
            workspace,
            kind,
            file,
            name,
            has_callee,
            has_decorator,
            has_param,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_defs(
            &workspace,
            DefsFilters {
                kind: kind.as_deref(),
                file: file.as_deref(),
                name: name.as_deref(),
                has_callee: has_callee.as_deref(),
                has_decorator: has_decorator.as_deref(),
                has_param: has_param.as_deref(),
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            !no_flows,
            format,
        ),
        Cmd::EntryPoints {
            workspace,
            kind,
            file,
            name,
            regex,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_entrypoints(
            &workspace,
            EntryPointsFilters {
                kind: kind.as_deref(),
                file: file.as_deref(),
                name: name.as_deref(),
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            format,
        ),
        Cmd::Calls {
            workspace,
            callee,
            file,
            caller,
            call_kind,
            regex,
            limit,
            context,
            page,
            all,
            no_flows,
            format,
            output: _,
        } => cmd_calls(
            &workspace,
            CallsFilters {
                callee: callee.as_deref(),
                file: file.as_deref(),
                caller: caller.as_deref(),
                call_kind: call_kind.as_deref(),
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            !no_flows,
            format,
        ),
        Cmd::Imports {
            workspace,
            file,
            module,
            alias,
            wildcard,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_imports(
            &workspace,
            ImportsFilters {
                file: file.as_deref(),
                module: module.as_deref(),
                alias: alias.as_deref(),
                wildcard,
                regex,
                resolve_workspace_bindings: false,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            !no_flows,
            format,
        ),
        Cmd::Vars {
            workspace,
            name,
            file,
            in_fn,
            source,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_vars(
            &workspace,
            VarsFilters {
                name: name.as_deref(),
                file: file.as_deref(),
                in_fn: in_fn.as_deref(),
                source: source.as_deref(),
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            !no_flows,
            format,
        ),
        Cmd::Strings {
            workspace,
            category,
            contains,
            file,
            in_fn,
            min_len,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_strings(
            &workspace,
            StringsFilters {
                category: category.as_deref(),
                contains: contains.as_deref(),
                file: file.as_deref(),
                in_fn: in_fn.as_deref(),
                min_len,
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            !no_flows,
            format,
        ),
        Cmd::Comments {
            workspace,
            kind,
            contains,
            file,
            in_fn,
            min_len,
            regex,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_comments(
            &workspace,
            CommentsFilters {
                kind: kind.as_deref(),
                contains: contains.as_deref(),
                file: file.as_deref(),
                in_fn: in_fn.as_deref(),
                min_len,
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            format,
        ),
        Cmd::Args {
            workspace,
            callee,
            file,
            in_fn,
            value,
            position,
            keyword,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_args(
            &workspace,
            ArgsFilters {
                callee: callee.as_deref(),
                file: file.as_deref(),
                in_fn: in_fn.as_deref(),
                value: value.as_deref(),
                position,
                keyword: keyword.as_deref(),
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            !no_flows,
            format,
        ),
        Cmd::Operations {
            workspace,
            kind,
            name,
            file,
            in_fn,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_operations(
            &workspace,
            OperationsFilters {
                kind: kind.as_deref(),
                name: name.as_deref(),
                file: file.as_deref(),
                in_fn: in_fn.as_deref(),
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            !no_flows,
            format,
        ),
        Cmd::Classes {
            workspace,
            name,
            file,
            kind,
            has_method,
            min_methods,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => cmd_classes(
            &workspace,
            ClassesFilters {
                name: name.as_deref(),
                file: file.as_deref(),
                kind: kind.as_deref(),
                has_method: has_method.as_deref(),
                min_methods,
                regex,
            },
            limit,
            paging_from_cli(context.as_deref(), page.as_deref(), all, format)?,
            !no_flows,
            format,
        ),
        Cmd::Refs {
            workspace,
            symbol_pos,
            symbol,
            kind,
            file,
            in_fn,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => {
            let sym = resolve_symbol_arg(symbol_pos, symbol, "symbol")?;
            let paging = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_refs(
                &workspace,
                &sym,
                RefsFilters {
                    kind: kind.as_deref(),
                    file: file.as_deref(),
                    in_fn: in_fn.as_deref(),
                    regex,
                },
                limit,
                paging,
                !no_flows,
                format,
            )
        }
        Cmd::Search {
            workspace,
            query_pos,
            query,
            kind,
            file,
            regex,
            limit,
            no_flows,
            context,
            page,
            all,
            format,
            output: _,
        } => {
            let q = resolve_symbol_arg(query_pos, query, "query")?;
            let paging = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_search(
                &workspace,
                &q,
                SearchFilters {
                    kind: kind.as_deref(),
                    file: file.as_deref(),
                    regex,
                },
                limit,
                paging,
                !no_flows,
                format,
            )
        }
        Cmd::Inspect {
            workspace,
            symbol_pos,
            query,
            symbol,
            regex,
            kind,
            from,
            from_kind,
            to,
            to_kind,
            file,
            in_fn,
            max_flows,
            max_entry_probes,
            max_hits,
            all,
            compact,
            flow,
            view,
            group,
            graph_flow,
            taint_flow,
            syntax_only,
            context,
            page,
            format,
            output: _,
        } => {
            // Precedence: positional → --query → --symbol (legacy alias).
            // Query is OPTIONAL: when omitted, `--from` / `--to` /
            // `--file` / `--in-fn` / `--kind` can act as standalone
            // filters that enumerate every decl + hit and narrow from
            // there. At least one signal must be present. `--flow
            // <id>` alone also satisfies the "some signal" rule — a
            // flow id pins a specific chain independently of the
            // query that originally produced it.
            let q = symbol_pos.or(query).or(symbol);
            let filters = InspectFilters {
                from: from.as_deref(),
                from_kind,
                to: to.as_deref(),
                to_kind,
                file: file.as_deref(),
                in_fn: in_fn.as_deref(),
            };
            if q.is_none()
                && filters.from.is_none()
                && filters.to.is_none()
                && filters.file.is_none()
                && filters.in_fn.is_none()
                && kind.is_empty()
                && flow.is_none()
                && group.is_none()
                && !taint_flow
            {
                anyhow::bail!(
                    "inspect needs a query, a filter (--from / --to / --file / \
                     --in-fn / --kind), --flow <flow_id>, --group <group_id>, \
                     or --taint-flow"
                );
            }
            // `--all` lifts every cap. The chain enumerator uses
            // saturating math internally, so `usize::MAX` is the
            // explicit uncapped value here rather than a large finite
            // stand-in.
            let (mf, mp, mh) = if all {
                (usize::MAX, usize::MAX, usize::MAX)
            } else {
                (max_flows, max_entry_probes, max_hits)
            };
            // `--flow <id>` on its own should still surface something
            // even when no `--query` / filters are set: enumerate every
            // decl + hit, then the flow-id filter in `cmd_inspect`
            // drops everything except the one matching flow.
            let render = InspectRenderOptions {
                compact,
                flow_id_filter: flow,
                view,
                group_id_filter: group,
                structural_drilldown: false,
            };
            let paging = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            let taint_flow_explicit = taint_flow;
            let taint_flow = taint_flow || !syntax_only;
            cmd_inspect(
                &workspace,
                InspectCommandOptions {
                    pattern: q.as_deref(),
                    is_regex: regex,
                    kind_filter: &kind,
                    filters,
                    max_flows: mf,
                    max_entry_probes: mp,
                    max_hits: mh,
                    render,
                    graph_flow,
                    taint_flow,
                    taint_flow_explicit,
                    paging_cfg: paging,
                    format,
                },
            )
        }
        Cmd::Export {
            workspace,
            full_propagations,
            complete_chains,
            all,
            format,
            output: _,
        } => cmd_export(&workspace, full_propagations, complete_chains || all, all, format),
        Cmd::Cache { action } => cmd_cache(action),
        Cmd::Security { workspace, action } => commands::security::cmd_security(&workspace, action),
        Cmd::Tree {
            workspace,
            max_depth,
            file,
            exclude_file,
            severity,
            limit,
            compact,
            context,
            page,
            all,
            format,
            rules_dir,
            output: _,
        } => commands::tree::cmd_tree(commands::tree::TreeArgs {
            workspace: &workspace,
            max_depth,
            file: file.as_deref(),
            exclude_file: &exclude_file,
            severity: severity.as_deref(),
            limit,
            compact,
            context: context.as_deref(),
            page: page.as_deref(),
            all,
            format: &format,
            rules_dir: rules_dir.as_deref(),
        }),
        Cmd::ReadFile {
            workspace,
            path,
            symbol,
            lines,
            from,
            to,
            max_inlined_bodies,
            compact,
            context,
            page,
            all,
            format,
            rules_dir,
            output: _,
        } => commands::read_file::cmd_read_file(commands::read_file::ReadFileArgs {
            workspace: &workspace,
            path: path.as_deref(),
            symbol: symbol.as_deref(),
            lines: lines.as_deref(),
            from: from.as_deref(),
            to: to.as_deref(),
            max_inlined_bodies,
            compact,
            context: context.as_deref(),
            page: page.as_deref(),
            all,
            format: &format,
            rules_dir: rules_dir.as_deref(),
        }),
    };
    let output_result = output::finish();
    result?;
    output_result?;
    Ok(())
}

fn install_global_rayon_pool() {
    let _ = rayon::ThreadPoolBuilder::new()
        .thread_name(|idx| format!("bonsai-worker-{idx}"))
        .stack_size(configured_rayon_stack_bytes())
        .build_global();
}

fn configured_rayon_stack_bytes() -> usize {
    std::env::var("BONSAI_RAYON_STACK_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 1024 * 1024)
        .unwrap_or(DEFAULT_RAYON_STACK_BYTES)
}

/// Stack size for the worker thread that runs the whole CLI. Larger than
/// the default 8 MB main-thread stack (and the rayon default) so deeply
/// nested source — where the recursive tree walk descends one frame per
/// nesting level — cannot overflow the stack on realistic or adversarial
/// input. Reserved virtual space, committed lazily, so the cost is ~0 for
/// normal runs. Override with `BONSAI_MAIN_STACK_BYTES`.
fn configured_main_stack_bytes() -> usize {
    const DEFAULT_MAIN_STACK_BYTES: usize = 512 * 1024 * 1024;
    std::env::var("BONSAI_MAIN_STACK_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 8 * 1024 * 1024)
        .unwrap_or(DEFAULT_MAIN_STACK_BYTES)
}

fn command_workspace_for_page_cache(cmd: &Cmd) -> Option<&std::path::Path> {
    match cmd {
        Cmd::Index { workspace, .. }
        | Cmd::Context { workspace, .. }
        | Cmd::Trace { workspace, .. }
        | Cmd::Path { workspace, .. }
        | Cmd::Slice { workspace, .. }
        | Cmd::Show { workspace, .. }
        | Cmd::Diagnostics { workspace }
        | Cmd::DumpHir { workspace, .. }
        | Cmd::DumpCfg { workspace, .. }
        | Cmd::DumpCallgraph { workspace, .. }
        | Cmd::DumpEdges { workspace, .. }
        | Cmd::DumpResolution { workspace, .. }
        | Cmd::DumpAst { workspace, .. }
        | Cmd::DumpResolve { workspace, .. }
        | Cmd::DumpTaint { workspace, .. }
        | Cmd::Defs { workspace, .. }
        | Cmd::EntryPoints { workspace, .. }
        | Cmd::Calls { workspace, .. }
        | Cmd::Imports { workspace, .. }
        | Cmd::Vars { workspace, .. }
        | Cmd::Strings { workspace, .. }
        | Cmd::Comments { workspace, .. }
        | Cmd::Args { workspace, .. }
        | Cmd::Operations { workspace, .. }
        | Cmd::Classes { workspace, .. }
        | Cmd::Refs { workspace, .. }
        | Cmd::Search { workspace, .. }
        | Cmd::Inspect { workspace, .. }
        | Cmd::Export { workspace, .. }
        | Cmd::Security { workspace, .. }
        | Cmd::Tree { workspace, .. }
        | Cmd::ReadFile { workspace, .. } => Some(workspace.as_path()),
        Cmd::Cache { .. } => None,
    }
}

fn command_output_path(cmd: &Cmd) -> Option<&std::path::Path> {
    match cmd {
        Cmd::Trace { output, .. }
        | Cmd::Path { output, .. }
        | Cmd::Slice { output, .. }
        | Cmd::Show { output, .. }
        | Cmd::DumpCallgraph { output, .. }
        | Cmd::DumpEdges { output, .. }
        | Cmd::DumpResolution { output, .. }
        | Cmd::DumpAst { output, .. }
        | Cmd::DumpResolve { output, .. }
        | Cmd::DumpTaint { output, .. }
        | Cmd::Defs { output, .. }
        | Cmd::EntryPoints { output, .. }
        | Cmd::Calls { output, .. }
        | Cmd::Imports { output, .. }
        | Cmd::Vars { output, .. }
        | Cmd::Strings { output, .. }
        | Cmd::Comments { output, .. }
        | Cmd::Args { output, .. }
        | Cmd::Operations { output, .. }
        | Cmd::Classes { output, .. }
        | Cmd::Refs { output, .. }
        | Cmd::Search { output, .. }
        | Cmd::Inspect { output, .. }
        | Cmd::Export { output, .. }
        | Cmd::Context { output, .. }
        | Cmd::Tree { output, .. }
        | Cmd::ReadFile { output, .. } => output.output_path.as_deref(),
        Cmd::Security { action, .. } => security_action_output_path(action),
        Cmd::Cache {
            action: CacheAction::Stats { output, .. },
        } => output.output_path.as_deref(),
        Cmd::Index { .. }
        | Cmd::Diagnostics { .. }
        | Cmd::DumpHir { .. }
        | Cmd::DumpCfg { .. }
        | Cmd::Cache { .. } => None,
    }
}

fn security_action_output_path(action: &SecurityAction) -> Option<&std::path::Path> {
    match action {
        SecurityAction::Sources { output, .. }
        | SecurityAction::Sinks { output, .. }
        | SecurityAction::Sanitizers { output, .. }
        | SecurityAction::Deps { output, .. }
        | SecurityAction::TaintAnalysis { output, .. }
        | SecurityAction::SourceAnalysis { output, .. }
        | SecurityAction::Pack { output, .. } => output.output_path.as_deref(),
    }
}
