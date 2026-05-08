//! Clap CLI surface: top-level [`Cli`], every subcommand variant in
//! [`Cmd`], and the `ValueEnum`-backed format / filter types used by
//! multiple subcommands.
//!
//! This module is pure-declarative: no command logic lives here. Each
//! variant's handler (`cmd_*`) dispatches from `main.rs` into one of
//! the `commands/*` modules.
//!
//! The default-value constants [`BROWSE_TEXT_LIMIT_DEFAULT`] and
//! [`DUMP_AST_FILE_LIMIT_DEFAULT`] live here because clap's
//! `#[arg(default_value_t = ...)]` must be able to resolve them at
//! attribute-expansion time.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::clap_help_styles;
use crate::help_theme::{
    themed_after_help, themed_cli_long_about, themed_help_template, themed_subcommand_after_help,
    themed_subcommand_long_about,
};

/// Default row cap for every browse command's text renderer. Chosen
/// so the footer's `~estimated tokens` stays under the 10K-token
/// shoulder of typical LLM context windows even on monster repos
/// (`calls` on Redis produces ~300K rows / ~11M tokens uncapped).
/// Users who want everything either pass `--limit 0` or pipe
/// `--format json`, both of which skip the cap.
pub(crate) const BROWSE_TEXT_LIMIT_DEFAULT: usize = 200;

/// Dump-AST-specific file cap. Much smaller than the general
/// browse default because a single real-world source file emits
/// tens of thousands of AST nodes — even 10 files is tens of
/// thousands of lines of output. Users who really want the full
/// workspace AST pass `--limit 0`.
pub(crate) const DUMP_AST_FILE_LIMIT_DEFAULT: usize = 10;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    Json,
    Text,
    Dot,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum BrowseFormat {
    Json,
    Text,
    /// SARIF 2.1.0. Only meaningful for `security taint-analysis` /
    /// `security source-analysis`; non-finding-bearing browse
    /// commands silently fall back to JSON.
    Sarif,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ExportFormat {
    /// Existing complete JSON document.
    Json,
    /// NetworkX node-link JSON (`nx.node_link_graph(..., edges="links")`).
    Networkx,
    /// GraphML directed property graph.
    Graphml,
    /// Neo4j-compatible Cypher `MERGE` script.
    Cypher,
}

/// How `inspect` shapes its flow output. `trace` is the historical
/// per-flow render (one FLOW N section per chain). `grouped` clusters
/// flows that share a call-edge tail and renders the shared tail
/// once. `auto` picks based on flow count — small result sets stay
/// in trace (detail is cheap), large sets flip to grouped (noise
/// reduction pays off).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum InspectView {
    /// One FLOW N block per chain. The default.
    Trace,
    /// Cluster flows by longest-shared-suffix into GROUP blocks.
    Grouped,
    /// `trace` when ≤ [`GROUPED_VIEW_AUTO_THRESHOLD`] total flows,
    /// `grouped` otherwise.
    Auto,
}

/// Auto-switch threshold: the total number of rendered flows at or
/// below which `--view auto` stays in `trace` mode. Above it, flips
/// to `grouped`. Chosen because:
/// - a 3–5 flow set reads fine as a flat list,
/// - ≥10 flows on the same sink is where the repeated tail becomes
///   real visual noise,
/// - and Redis's biggest inspect results (40–344 flows on
///   `--query system`) are exactly where grouping buys the most
///   readability.
pub(crate) const GROUPED_VIEW_AUTO_THRESHOLD: usize = 10;

/// Browse-fact kinds the `--from-kind` / `--to-kind` flags accept.
/// Mirrors the taint fact kind vocabulary with clap-friendly value
/// spellings — callers type `--from-kind read`, `--from-kind call`,
/// etc. to narrow match space to one browse-fact surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum FactKindFilter {
    Decl,
    Call,
    Read,
    Write,
    Arg,
    #[value(name = "string")]
    StringLit,
    Import,
    Class,
}

impl FactKindFilter {
    /// Map the clap-facing CLI variant to the SDK-level
    /// [`bonsai_sdk::FactKindFilter`]. Same shape, but the SDK
    /// type stays free of clap so the engine crate doesn't pull in
    /// a CLI dependency.
    pub(crate) fn to_sdk(self) -> bonsai_sdk::FactKindFilter {
        match self {
            Self::Decl => bonsai_sdk::FactKindFilter::Decl,
            Self::Call => bonsai_sdk::FactKindFilter::Call,
            Self::Read => bonsai_sdk::FactKindFilter::Read,
            Self::Write => bonsai_sdk::FactKindFilter::Write,
            Self::Arg => bonsai_sdk::FactKindFilter::Arg,
            Self::StringLit => bonsai_sdk::FactKindFilter::StringLit,
            Self::Import => bonsai_sdk::FactKindFilter::Import,
            Self::Class => bonsai_sdk::FactKindFilter::Class,
        }
    }
}

/// CLI-surfaced precision classes. Mirrors `bonsai_common::Precision`
/// with a hyphenated spelling clap will accept on the command line
/// (`--precision over-approximate`). Used by `dump-edges --precision`
/// and `security taint-analysis --precision`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum PrecisionFilter {
    /// `Precision::Exact` — structural facts; no approximation.
    Exact,
    /// `Precision::Narrowed` — single-candidate resolved call.
    Narrowed,
    /// `Precision::OverApproximate` — multi-candidate / Virtual edges.
    OverApproximate,
    /// `Precision::Unknown` — opaque; resolver has no guarantee.
    Unknown,
}

// `PrecisionFilter::matches` lived here previously. Filter logic
// against `bonsai_common::Precision` is now in
// `bonsai_sdk::PrecisionClass::matches` — the CLI converts at
// the cmd_dump_edges call site.

#[derive(Parser, Debug)]
#[command(
    name = "bonsai-ninja",
    version = env!("CARGO_PKG_VERSION"),
    about = "bonsai-ninja — multi-language static execution flow analyzer",
    long_about = themed_cli_long_about(),
    after_help = themed_after_help(),
    after_long_help = themed_after_help(),
    // Drop clap's auto `Commands:` block — we render our own grouped,
    // themed list in `after_help` so both don't appear. The template is
    // built at runtime so the `Options:` heading picks up the user's
    // theme color, matching clap's own `Usage:` / group headings.
    help_template = themed_help_template(),
    disable_help_subcommand = true,
    styles = clap_help_styles(),
)]
pub(crate) struct Cli {
    /// Disable colored / styled output. Also respects `NO_COLOR` env and
    /// auto-disables when stdout isn't a TTY.
    #[arg(long, global = true)]
    pub(crate) no_color: bool,

    /// Color theme preset. Defaults to `moss` (the bonsai-ninja house
    /// theme — a dark-forest palette: pine-ink borders, misted-pine
    /// headers, evergreen body, spruce-teal accent; deep greens and
    /// slate, no warm bark tones). Can also be set via `BONSAI_THEME`.
    /// Choices: `moss` (default, aliases: `bonsai`, `forest`),
    /// `earthy-dark`, `dracula`, `retro-amber`.
    #[arg(long, global = true)]
    pub(crate) theme: Option<String>,

    /// Disable the in-process chain / downstream / reachable-names caches
    /// used by `inspect` and `export`. Results are identical — cached and
    /// uncached paths return the same flows — but every lookup recomputes
    /// from scratch. Use for benchmarking the cold path or as a safety
    /// hatch if you suspect stale state. Also respects `BONSAI_NO_CACHE`.
    #[arg(long, global = true)]
    pub(crate) no_cache: bool,

    /// Disable progress bars for long-running commands. Also respects
    /// `NO_PROGRESS` / `NO_COLOR` env vars and auto-disables when
    /// stderr isn't a TTY (so pipes / CI / `--format json` scripts
    /// stay clean by default).
    #[arg(long, global = true)]
    pub(crate) no_progress: bool,

    /// Per-file tree-sitter parse timeout in milliseconds. Defaults
    /// to 30000 ms; `0` disables the timeout guard. Also respects
    /// `BONSAI_PARSE_TIMEOUT_MS`.
    #[arg(long = "parse-timeout", global = true, value_name = "MS")]
    pub(crate) parse_timeout_ms: Option<u64>,

    #[command(subcommand)]
    pub(crate) command: Cmd,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Cmd {
    /// Ingest a workspace and print stats.
    #[command(
        display_order = 10,
        long_about = themed_subcommand_long_about("Ingest every supported source file under <WORKSPACE> and print \
                      a summary (file count, decls, refs, module count) as \
                      JSON.\n\
                      \n\
                      Builds the parsed/indexed workspace and eagerly warms \
                      the persisted dataflow sidecar (`.bonsai/dataflow.v2.bin`) \
                      for missing or changed function facts. Later browse, \
                      inspect, trace, security, export, and debug commands \
                      load that sidecar and compute only misses lazily.\n\
                      \n\
                      Pass `--watch` to keep the process alive as a workflow \
                      tool: bonsai polls the source tree, hot-reloads saved \
                      changes into the live workspace, prewarms only missing \
                      or invalidated dataflow facts, and rewrites the sidecar."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Sanity-check a workspace\n  \
                      $ bonsai-ninja index ./src\n  \
                      \n  \
                      # Keep the index warm while editing\n  \
                      $ bonsai-ninja index ./src --watch\n  \
                      \n  \
                      # Force a fresh taint sidecar before measuring\n  \
                      $ bonsai-ninja cache clear ./src --dataflow-only\n  \
                      $ bonsai-ninja index ./src")
    )]
    Index {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Keep running and refresh the live index when files change on disk.
        #[arg(long)]
        watch: bool,
        /// Poll interval for `--watch`, in milliseconds.
        #[arg(long = "interval-ms", default_value_t = 750)]
        interval_ms: u64,
    },

    /// Cross-module execution trace from a function (headline feature).
    #[command(
        display_order = 2,
        long_about = themed_subcommand_long_about("Expand a function's call tree across the whole workspace and \
                      emit a structured trace of every step (Call / Branch / Loop / \
                      Return / Throw / Try / ...). Follows qualified calls through \
                      classes, modules, and imports, backed by the same indexed \
                      dataflow sidecar that inspect and security query.\n\
                      \n\
                      Use `--from X --to Y` to restrict to flows that go from X to Y."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Trace every flow that starts at handle_request\n  \
                      $ bonsai-ninja trace ./src handle_request\n  \
                      \n  \
                      # Only flows that reach os.system starting from handle_request\n  \
                      $ bonsai-ninja trace ./src --from handle_request --to os.system\n  \
                      \n  \
                      # Graphviz output\n  \
                      $ bonsai-ninja trace ./src handle_request --format dot | dot -Tpng > flow.png")
    )]
    Trace {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Positional symbol to trace (alternative to `--function`).
        symbol: Option<String>,
        /// Function name to trace. Takes precedence over the positional
        /// symbol when both are set.
        #[arg(long)]
        function: Option<String>,
        /// Restrict to flows that start at (or pass through) a name
        /// containing this substring. Pairs with `--to` to bracket a
        /// specific entry → sink window.
        #[arg(long)]
        from: Option<String>,
        /// Restrict to flows that reach a name containing this
        /// substring. Requires `--from`.
        #[arg(long, requires = "from")]
        to: Option<String>,
        /// Token-budget ceiling for text output. Long traces page at
        /// rendered-line boundaries so large paths stay within budget.
        /// Shorthand `4k` / `32k`. `0` / `all` / `uncapped`
        /// disables. Default 32k.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based (`--page 2`), cursor
        /// (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit the full trace with no context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Maximum cross-module call depth to expand.
        #[arg(long, default_value_t = 12)]
        max_depth: u16,
        /// Maximum trace steps to emit before truncating.
        #[arg(long, default_value_t = 8192)]
        max_steps: u32,
        /// Maximum branch fanout used to derive the path budget.
        #[arg(long, default_value_t = 4)]
        max_branch_fanout: u16,
        /// Maximum loop iterations represented in trace metadata.
        #[arg(long, default_value_t = 1)]
        max_loop_iters: u16,
        /// Output shape — `text` for the rendered trace, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Workspace-wide diagnostics.
    #[command(
        display_order = 11,
        long_about = themed_subcommand_long_about("Run every language adapter's diagnostic pass across the \
                      workspace and print the aggregated results. Flags \
                      adapter-level extraction issues (unsupported \
                      construct per language, tree-sitter parse errors, \
                      unresolved imports) before they silently degrade \
                      inspect / taint output. Exits 0 even when \
                      warnings are present — CI pipelines can still gate \
                      on specific lines."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Run every adapter's diagnostic pass\n  \
                      $ bonsai-ninja diagnostics ./src\n  \
                      \n  \
                      # Grep for unsupported-construct warnings\n  \
                      $ bonsai-ninja diagnostics ./src | grep -i unsupported")
    )]
    Diagnostics {
        /// Workspace root to analyze.
        workspace: PathBuf,
    },

    /// Dump the HIR of a single function.
    #[command(
        display_order = 30,
        long_about = themed_subcommand_long_about("Emit the HIR (flow-event tree — Call / Branch / Loop / Return \
                      / Throw / Try / …) for one function as JSON. The \
                      layer directly above the tree-sitter AST; what \
                      `inspect` and `trace` walk to produce flow chains.\n\
                      \n\
                      Use to verify an adapter actually extracts a construct \
                      before chasing a missing chain further down the \
                      pipeline — when HIR is empty, every downstream layer \
                      (CFG, call graph, taint) will also be missing it.\n\
                      \n\
                      Output is JSON-only — the HIR shape is structural, \
                      not tabular, so a rendered text view wouldn't add \
                      information. Pipe through `jq` to drill down."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Positional symbol\n  \
                      $ bonsai-ninja dump-hir ./src handle_request\n  \
                      \n  \
                      # Equivalent, via --symbol\n  \
                      $ bonsai-ninja dump-hir ./src --symbol run_admin_command\n  \
                      \n  \
                      # Just the call events inside a function\n  \
                      $ bonsai-ninja dump-hir ./src handle_request | jq '.flow_events[] | select(.Call)'")
    )]
    DumpHir {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Positional symbol to dump (alternative to `--symbol`).
        symbol_pos: Option<String>,
        /// Function name to dump. The positional symbol takes
        /// precedence when both are set.
        #[arg(long)]
        symbol: Option<String>,
    },

    /// Dump the CFG of a single function.
    #[command(
        display_order = 31,
        long_about = themed_subcommand_long_about("Emit the CFG (basic blocks + edges) derived from a function's \
                      HIR as JSON. The intraprocedural view taint analysis \
                      walks — every branch, loop, and join point is \
                      materialised as explicit nodes.\n\
                      \n\
                      Read alongside `dump-hir` when a taint pass disagrees \
                      with your expectation: HIR tells you what events the \
                      adapter extracted, CFG tells you how they were \
                      linearized into blocks.\n\
                      \n\
                      Output is JSON-only — the CFG shape is structural, \
                      not tabular. Pipe through `jq` to inspect specific \
                      blocks / terminators."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Positional symbol\n  \
                      $ bonsai-ninja dump-cfg ./src handle_request\n  \
                      \n  \
                      # Equivalent, via --symbol\n  \
                      $ bonsai-ninja dump-cfg ./src --symbol run_admin_command\n  \
                      \n  \
                      # Just block terminators\n  \
                      $ bonsai-ninja dump-cfg ./src handle_request | jq '.blocks[] | {id, terminator}'")
    )]
    DumpCfg {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Positional symbol to dump (alternative to `--symbol`).
        symbol_pos: Option<String>,
        /// Function name to dump. The positional symbol takes
        /// precedence when both are set.
        #[arg(long)]
        symbol: Option<String>,
    },

    /// Dump the callgraph (functions + reachable counts).
    #[command(
        display_order = 32,
        long_about = themed_subcommand_long_about("Emit every function with its inbound caller count and \
                      outbound reachable-callee count, sorted \
                      hottest-first. The fastest way to find the hubs \
                      of a codebase — high-fanin functions are the \
                      chokepoints reviewers should audit first; \
                      high-fanout functions are dispatch / orchestration \
                      layers. `--format json` emits one row per function \
                      so downstream tools can post-process."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Hub functions sorted by reachable-callee count\n  \
                      $ bonsai-ninja dump-callgraph ./src\n  \
                      \n  \
                      # Top 10 hubs as JSON\n  \
                      $ bonsai-ninja dump-callgraph ./src --format json | jq '.[0:10]'")
    )]
    DumpCallgraph {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Max rows in the text rendering (`0` = uncapped). JSON
        /// output is always uncapped so scripts keep the full graph.
        /// Legacy cap — prefer `--context` for token-budget paging.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Token-budget ceiling for text output. Shorthand `4k` etc.
        #[arg(long)]
        context: Option<String>,
        /// Page to render (1-based number, `P:xxxxxxxx`, or `next`).
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Dump every resolved call edge with `EdgeKind` + `Precision`.
    #[command(
        display_order = 33,
        long_about = themed_subcommand_long_about("One record per resolved call edge: caller, callee, call-site \
                      location, `EdgeKind` (Direct / Virtual), `Precision` \
                      (Exact / Narrowed / OverApproximate / Unknown). The \
                      place to look when `inspect` shows `[precision: \
                      over-approximate]` and you want to know exactly which \
                      edge dragged the chain's precision down.\n\
                      \n\
                      Every edge carries a stable `edge_id` (`E:` + 8 hex) \
                      — a FNV-1a content hash over (caller, callee, call \
                      site) that survives renames / cache state / render \
                      mode. `--edge E:xxxxxxxx` re-renders just that one \
                      edge; scripts can cite an id across runs."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every edge, full detail\n  \
                      $ bonsai-ninja dump-edges ./src\n  \
                      \n  \
                      # Only over-approximate edges (the weak-evidence ones)\n  \
                      $ bonsai-ninja dump-edges ./src --precision over-approximate\n  \
                      \n  \
                      # Edges into a specific callee (every caller of os.system)\n  \
                      $ bonsai-ninja dump-edges ./src --to os.system\n  \
                      \n  \
                      # Compact: one line per edge, ideal for piping\n  \
                      $ bonsai-ninja dump-edges ./src --compact\n  \
                      \n  \
                      # Drill into one edge by its stable id\n  \
                      $ bonsai-ninja dump-edges ./src --edge E:aabbccdd")
    )]
    DumpEdges {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Only keep edges whose caller name contains this substring.
        /// Analogous to `inspect --from`.
        #[arg(long)]
        from: Option<String>,
        /// Only keep edges whose callee name contains this substring.
        /// Analogous to `inspect --to`.
        #[arg(long)]
        to: Option<String>,
        /// Only keep edges at the given precision class.
        #[arg(long, value_enum)]
        precision: Option<PrecisionFilter>,
        /// Drop per-edge detail lines and emit one compact line per
        /// edge (`E:id  kind  precision  caller → callee  (file:line)`).
        /// Same data, shorter render — mirrors `inspect --compact`.
        #[arg(long, default_value_t = false)]
        compact: bool,
        /// Re-render only the edge whose stable content-hash id
        /// matches (`E:` + 8 hex). Complementary to `inspect --flow`
        /// — one level down: pins a single call edge, not a chain.
        #[arg(long)]
        edge: Option<String>,
        /// Max edges in the text rendering (`0` = uncapped). JSON
        /// output is always uncapped. Redis emits ~300 k edges
        /// without a cap — keep the common interactive run
        /// readable. Legacy cap — prefer `--context`.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Token-budget ceiling for text output. Shorthand `4k` etc.
        #[arg(long)]
        context: Option<String>,
        /// Page to render (1-based number, `P:xxxxxxxx`, or `next`).
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Dump the tree-sitter parse tree per file or per function.
    #[command(
        display_order = 34,
        long_about = themed_subcommand_long_about("Emit the tree-sitter parse tree for the workspace, one file \
                      at a time (or one function with `--function`). The ground-truth \
                      view of what the grammar actually extracted — the first place \
                      to look when `dump-hir` / `inspect` don't surface a function \
                      you expected, or when a language adapter silently misses a \
                      construct (DSL callbacks, lambdas hidden in a closure, etc.).\n\
                      \n\
                      Every node carries a stable `node_id` (`N:` + 8 hex) — a \
                      FNV-1a content hash over (file, byte range, node kind) that \
                      survives parse-cache rebuilds. `--node N:xxxxxxxx` re-renders \
                      just the one node and its subtree, so scripts can cite \
                      specific nodes across runs.\n\
                      \n\
                      Only named nodes are shown by default (matching the default \
                      tree-sitter CLI convention); anonymous tokens (`def`, `{`, \
                      `,` …) are omitted for signal density."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every file's parse tree, full detail\n  \
                      $ bonsai-ninja dump-ast ./src\n  \
                      \n  \
                      # One file\n  \
                      $ bonsai-ninja dump-ast ./src --file gateway.py\n  \
                      \n  \
                      # One function's subtree\n  \
                      $ bonsai-ninja dump-ast ./src --function handle_request\n  \
                      \n  \
                      # Kinds-only compact render, ideal for piping\n  \
                      $ bonsai-ninja dump-ast ./src --compact\n  \
                      \n  \
                      # Drill into one node by its stable id\n  \
                      $ bonsai-ninja dump-ast ./src --node N:aabbccdd")
    )]
    DumpAst {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Positional symbol (alternative to `--function`).
        symbol_pos: Option<String>,
        /// Filter to files whose path contains this substring.
        #[arg(long)]
        file: Option<String>,
        /// Scope to a single function's subtree (decl name). Takes
        /// precedence over `--file` when both are set.
        #[arg(long)]
        function: Option<String>,
        /// Kinds-only compact render (drop source text snippets and
        /// anonymous tokens). Same structure, shorter output.
        #[arg(long, default_value_t = false)]
        compact: bool,
        /// Max tree depth. Unlimited by default. Useful on dense
        /// grammars (e.g. deeply-nested expression statements).
        #[arg(long)]
        max_depth: Option<usize>,
        /// Drill down to one node by its stable content-hash id
        /// (`N:` + 8 hex). Prints that node and its subtree.
        #[arg(long)]
        node: Option<String>,
        /// Max files in the text rendering (`0` = uncapped). A
        /// single real-world source file can emit tens of
        /// thousands of AST nodes, so the default cap is
        /// deliberately small — dump-ast is a targeted debug tool
        /// (scope with `--file` / `--function` / `--node`), not a
        /// bulk listing. JSON output is always uncapped. Legacy
        /// cap — prefer `--context`.
        #[arg(long, default_value_t = DUMP_AST_FILE_LIMIT_DEFAULT)]
        limit: usize,
        /// Token-budget ceiling for text output. Shorthand `4k` etc.
        #[arg(long)]
        context: Option<String>,
        /// Page to render (1-based number, `P:xxxxxxxx`, or `next`).
        #[arg(long)]
        page: Option<String>,
        /// Emit every AST line with no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Trace the name resolver stage-by-stage.
    #[command(
        display_order = 35,
        long_about = themed_subcommand_long_about("Feed a name token through the resolver and emit every \
                      stage's input and output: `short_callee` qualification \
                      trim, per-file import alias rewrite, \
                      `collect_callable_targets` primary lookup, literal-name \
                      fallback. Use to *verify* the resolver is sound — not \
                      just to observe its output (that's `dump-edges`) but to \
                      confirm it considered the inputs you expected, applied \
                      the aliases you expected, and rejected the names it \
                      should have rejected.\n\
                      \n\
                      Every candidate carries a stable `candidate_id` (`R:` + \
                      8 hex) — a FNV-1a content hash over (query, file context, \
                      candidate decl location) that survives cache / render \
                      changes. Scripts can pin a specific resolution decision \
                      across runs for regression testing.\n\
                      \n\
                      Zero candidates is a *valid* outcome (the name escapes \
                      the workspace — external, FFI, dynamic). The command \
                      still exits non-zero with did-you-mean suggestions so \
                      scripts can detect surprise failures."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Trace a single name (global lookup, no file context)\n  \
                      $ bonsai-ninja dump-resolve ./src run_admin_command\n  \
                      \n  \
                      # With a file context so the alias map is applied\n  \
                      $ bonsai-ninja dump-resolve ./src z --in-file gateway.py\n  \
                      \n  \
                      # Compact — one line per candidate\n  \
                      $ bonsai-ninja dump-resolve ./src execute --compact\n  \
                      \n  \
                      # Drill into one candidate by its stable id\n  \
                      $ bonsai-ninja dump-resolve ./src execute --candidate R:aabbccdd")
    )]
    DumpResolve {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Positional name to resolve (alternative to `--name`).
        name_pos: Option<String>,
        /// Name to resolve.
        #[arg(long)]
        name: Option<String>,
        /// Apply the alias map of the file whose path contains this
        /// substring. When omitted the lookup runs in "global" mode
        /// (no alias rewrite) — matching how a dynamic `getattr(...)`
        /// or top-level reference would resolve.
        #[arg(long = "in-file")]
        in_file: Option<String>,
        /// Drop per-stage detail and emit one line per candidate
        /// (`R:id  name  location`). Same data, shorter render —
        /// mirrors `inspect --compact`.
        #[arg(long, default_value_t = false)]
        compact: bool,
        /// Re-render only the candidate whose stable content-hash id
        /// matches (`R:` + 8 hex). Errors if the id isn't present in
        /// the candidate set.
        #[arg(long)]
        candidate: Option<String>,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Run the interprocedural taint pass from an entry function and
    /// dump every resulting cross-function propagation.
    #[command(
        display_order = 36,
        long_about = themed_subcommand_long_about("Run the full taint pipeline (intraprocedural CFG + \
                      interprocedural call-graph propagation) for the requested \
                      `--source`. Provide `--seed` to override entry taint, or \
                      omit it to infer source parameters and local assignment targets. \
                      Emits one record per cross-function propagation: which \
                      tainted arg at which call site taints which parameter in \
                      which callee. Use this to verify taint behavior on any \
                      fixture; inspect, trace, and security read the same indexed \
                      taint facts when they render higher-level reports.\n\
                      \n\
                      Every propagation carries a stable `taint_id` (`T:` + 8 \
                      hex) derived from (caller, callee, call site, tainted \
                      params). Stable across runs; drill into a single record \
                      with `--taint T:id`. Sanitizer names are accepted for \
                      compatibility but do not change propagation.\n\
                      \n\
                      Every taint edge threads through `bonsai_resolve`'s \
                      alias-aware call resolution — cross-module imports, \
                      `from x import y as z` rewrites, and virtual / over-\
                      approximate edges all flow taint with their precision \
                      carried forward."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Start from update_user with `action` seeded as tainted\n  \
                      $ bonsai-ninja dump-taint ./src --source update_user --seed action\n  \
                      \n  \
                      # Let the command infer entry seeds for a handler\n  \
                      $ bonsai-ninja dump-taint ./src --source handle_request\n  \
                      \n  \
                      # Seed multiple names; pick up cross-module flows\n  \
                      $ bonsai-ninja dump-taint ./src --source update_user --seed token --seed action\n  \
                      \n  \
                      # Pass sanitizer names for compatibility; propagation is unchanged\n  \
                      $ bonsai-ninja dump-taint ./src --source update_user --seed action --sanitizer shlex_quote\n  \
                      \n  \
                      # Filter to propagations landing in a specific sink\n  \
                      $ bonsai-ninja dump-taint ./src --source update_user --seed action --sink run_admin_command\n  \
                      \n  \
                      # Compact one-line-per-propagation output\n  \
                      $ bonsai-ninja dump-taint ./src --source update_user --seed action --compact")
    )]
    DumpTaint {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Entry function whose scope is initially tainted. Accepts
        /// a bare name (`update_user`), a file-qualified name
        /// (`src/handlers.py:update_user`), or a fully qualified form
        /// (`src/handlers.py:42:update_user`) for disambiguating when
        /// several decls in the workspace share the same name.
        #[arg(long)]
        source: String,
        /// Seed identifier names (repeatable). Each is treated as
        /// tainted on entry to `--source`. When omitted, every
        /// parameter and local assignment target of `--source` is
        /// seeded so param-less handlers and request-derived locals
        /// can still be inspected.
        #[arg(long = "seed")]
        seeds: Vec<String>,
        /// Compatibility sanitizer callee names (repeatable). They
        /// are accepted but do not change taint propagation.
        #[arg(long = "sanitizer")]
        sanitizers: Vec<String>,
        /// Filter emitted propagations to those whose callee name
        /// contains this substring. Doesn't change the analysis —
        /// taint still runs globally; only the render is narrowed.
        #[arg(long)]
        sink: Option<String>,
        /// Override the interprocedural pass's `(FuncId, seed)`
        /// chunk size. Default 512. This affects how often the
        /// resumable worklist yields, not whether complete flows are
        /// explored.
        #[arg(long)]
        budget: Option<u32>,
        /// Override the intraprocedural CFG worklist iteration cap per
        /// function. Default derives from CFG size.
        #[arg(long = "intra-worklist-cap")]
        intra_worklist_cap: Option<u32>,
        /// One-line-per-propagation render (the headline table).
        #[arg(long, default_value_t = false)]
        compact: bool,
        /// Drill down to one propagation by its stable content-hash
        /// id (`T:` + 8 hex).
        #[arg(long)]
        taint: Option<String>,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    // --- Browse & inspect --------------------------------------------------
    /// Browse indexed definitions (functions, methods, classes, structs, ...).
    #[command(
        display_order = 20,
        long_about = themed_subcommand_long_about("List every definition found in the workspace. Columns: \
                      name, kind, location, signature, callees (top 3 \
                      outgoing), flows (`F:<16-hex>` ids whose chain reaches \
                      the decl — paste into `inspect --flow` to expand).\n\
                      \n\
                      Supports filters by kind (`function`, `class`, \
                      `method`, …), file-path substring, name substring / \
                      regex, has-callee / has-decorator / has-param \
                      narrowers for decl-shape queries. `--no-flows` \
                      suppresses the `flows` column on very large \
                      workspaces where chain enumeration adds noticeable \
                      time."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every decl in the workspace\n  \
                      $ bonsai-ninja defs ./src\n  \
                      \n  \
                      # Only methods in auth_service.py matching `run_`\n  \
                      $ bonsai-ninja defs ./src --kind method --file auth_service --name run_\n  \
                      \n  \
                      # Decls that call a specific sink\n  \
                      $ bonsai-ninja defs ./src --has-callee os.system\n  \
                      \n  \
                      # Regex name match + JSON for tooling\n  \
                      $ bonsai-ninja defs ./src --regex --name '^handle_.*' --format json\n\n\
                      SAMPLE OUTPUT\n\n  \
                      name               kind      location                           signature                        callees\n  \
                      ─────────────────────────────────────────────────────────────────────────────────────────────────────────\n  \
                      verify_token       function  python/micro/auth_service.py:5:5   verify_token(token)              sqlite3.connect → conn.cursor → cursor.execute (+2)\n  \
                      run_admin_command  function  python/micro/auth_service.py:17:5  run_admin_command(user_id, cmd)  os.system")
    )]
    Defs {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Substring match on the decl kind (`function`, `method`, `class`, …).
        #[arg(long)]
        kind: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Substring match on the decl's short name.
        #[arg(long)]
        name: Option<String>,
        /// Only keep decls whose outgoing calls include this substring.
        #[arg(long = "has-callee")]
        has_callee: Option<String>,
        /// Only keep decls decorated with this name (or substring).
        #[arg(long = "has-decorator")]
        has_decorator: Option<String>,
        /// Substring match on any parameter name.
        #[arg(long = "has-param")]
        has_param: Option<String>,
        /// Interpret `--name` as a regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped so scripts keep the full result set.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Suppress the `flows` column. The column is ON by default
        /// and lists the taint-flow IDs (`F:<16-hex>`) whose
        /// upstream call chains reach the row's enclosing function;
        /// paste any ID into `inspect --flow F:<16-hex>` to expand
        /// the chain. Pass `--no-flows` on very large workspaces
        /// where chain enumeration adds a few seconds you don't
        /// want to pay.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Token-budget ceiling for text output. Shorthand: `4k`
        /// `32k` `128k` `1m`. `0` / `all` / `uncapped` disables.
        /// Defaults to `BONSAI_CONTEXT` or `32k`. JSON stays
        /// uncapped unless explicitly set.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Browse indexed call sites by callee / file / line.
    #[command(
        display_order = 21,
        long_about = themed_subcommand_long_about("Every call site in the workspace, with the caller function, \
                      location, and a syntax-highlighted source-line \
                      snippet. The `flows` column (on by default) \
                      lists every `F:<16-hex>` whose upstream chain \
                      reaches the call's enclosing function — paste \
                      any id into `inspect --flow F:<16-hex>` to \
                      expand. `--callee` accepts a substring or regex \
                      (`--regex`) and is the fastest way to find every \
                      invocation of a sensitive function."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Everywhere os.system is called\n  \
                      $ bonsai-ninja calls ./src --callee os.system\n  \
                      \n  \
                      # All calls in a specific file\n  \
                      $ bonsai-ninja calls ./src --file gateway.py\n\n\
                      SAMPLE OUTPUT\n\n  \
                      callee       caller             location                           code\n  \
                      ───────────────────────────────────────────────────────────────────────────────────────────────\n  \
                      os.system    run_admin_command  python/micro/auth_service.py:19:9  os.system(\"notify-admin \" + cmd)")
    )]
    Calls {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Substring match on the callee name.
        #[arg(long)]
        callee: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Substring match on the enclosing (caller) function.
        #[arg(long)]
        caller: Option<String>,
        /// Only calls of this kind (`function`, `method`, `constructor`, `macro`, `indirect`).
        #[arg(long = "call-kind")]
        call_kind: Option<String>,
        /// Interpret `--callee` as a regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped. Legacy cap — prefer `--context` for
        /// token-budget-aware paging.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Token-budget ceiling for text output. Accepts integers
        /// (`32768`) or shorthand (`4k / 8k / 16k / 32k / 64k /
        /// 128k / 256k / 1m`). Overrides `--limit` when both are
        /// set. `0` / `all` / `uncapped` disable the cap. Defaults
        /// to `BONSAI_CONTEXT` env or `32k` for text. Programmatic
        /// formats (JSON) stay uncapped unless `--context` is
        /// explicitly passed.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx` from a previous footer), or
        /// `next` to advance from the last invocation in this
        /// shell session. Defaults to page 1.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row with no paging or context cap. Short for
        /// `--context 0`.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Suppress the `flows` column. The column is ON by default
        /// and lists the taint-flow IDs (`F:<16-hex>`) whose
        /// upstream call chains reach the row's enclosing function;
        /// paste any ID into `inspect --flow F:<16-hex>` to expand
        /// the chain. Pass `--no-flows` on very large workspaces
        /// where chain enumeration adds a few seconds you don't
        /// want to pay.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Review imports and using statements.
    #[command(
        display_order = 22,
        long_about = themed_subcommand_long_about("Every import / use / include statement in the workspace. \
                      Columns: module, symbol (`from x import y` → `y`), \
                      alias (`as X`), kind (named / wildcard), location, \
                      source-line snippet, and the `flows` column listing \
                      every `F:<16-hex>` whose chain reaches a function \
                      brought into scope by the import.\n\
                      \n\
                      Supported forms: Python `import x [as y]`, `from x \
                      import y [as z]`, `from . import x`, `from x import \
                      *`; JS/TS `import x from`, `import * as x from`, \
                      `import { a as b } from`; Go `import alias \"path\"`, \
                      `import . \"path\"`; Rust `use x::y [as z]`, `use \
                      x::{a, b}`, `use x::*`; Scala `import x.{a => b}`; \
                      PHP `use X [as Y]`; C/C++ `#include`, `using \
                      namespace`; Obj-C `#import \"X.h\"`; Elixir `alias \
                      MyApp.X`; Ruby `require`, `require_relative`; Perl \
                      `use X`; Dart `import 'x.dart'`.\n\
                      \n\
                      Flow-id resolution for whole-module includes (C/C++ \
                      `#include`, Obj-C `#import`, Elixir `alias`, Ruby \
                      `require_relative`) looks up the module path in the \
                      workspace and pulls declared function names from the \
                      resolved file — plus the sibling `.c`/`.cpp`/`.m` \
                      file when the header has only prototypes, and the \
                      snake_case form (`MyApp.AuthService` → \
                      `auth_service.ex`) for ecosystems whose file \
                      convention differs from the module name."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every import in the workspace\n  \
                      $ bonsai-ninja imports ./src\n  \
                      \n  \
                      # Imports in a specific file\n  \
                      $ bonsai-ninja imports ./src --file auth_service.py\n  \
                      \n  \
                      # Wildcard imports only (hotspots for unintended reexports)\n  \
                      $ bonsai-ninja imports ./src --wildcard\n  \
                      \n  \
                      # JSON for tooling\n  \
                      $ bonsai-ninja imports ./src --format json")
    )]
    Imports {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Substring match on the module name.
        #[arg(long)]
        module: Option<String>,
        /// Substring match on the alias (`as X`).
        #[arg(long)]
        alias: Option<String>,
        /// Only wildcard imports (`*`, `.*`, `::*`, `._`).
        #[arg(long, default_value_t = false)]
        wildcard: bool,
        /// Interpret `--module` as a regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Suppress the `flows` column. The column is ON by default
        /// and lists the taint-flow IDs (`F:<16-hex>`) whose
        /// upstream call chains reach the row's enclosing function;
        /// paste any ID into `inspect --flow F:<16-hex>` to expand
        /// the chain. Pass `--no-flows` on very large workspaces
        /// where chain enumeration adds a few seconds you don't
        /// want to pay.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Token-budget ceiling for text output. Shorthand: `4k`
        /// `32k` `128k` `1m`. `0` / `all` / `uncapped` disables.
        /// Defaults to `BONSAI_CONTEXT` or `32k`. JSON stays
        /// uncapped unless explicitly set.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Inspect variables (assignments observed in flow events) with locations.
    #[command(
        display_order = 23,
        long_about = themed_subcommand_long_about("Every assignment captured from a function's flow. Columns: \
                      `var`, enclosing `fn`, `source` (bare-identifier \
                      RHS when the adapter could extract one — `None` \
                      for compound expressions), location, syntax- \
                      highlighted source-line snippet.\n\
                      \n\
                      The companion to `calls`: where `calls` lists \
                      call sites, `vars` lists binding sites. Use \
                      `--name` to scope to a specific identifier, \
                      `--in-fn` for a function, `--file` for a path."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Where does `token` get assigned?\n  \
                      $ bonsai-ninja vars ./src --name token\n  \
                      \n  \
                      # All assignments in a file\n  \
                      $ bonsai-ninja vars ./src --file gateway.py\n  \
                      \n  \
                      # Every assignment inside handle_request\n  \
                      $ bonsai-ninja vars ./src --in-fn handle_request")
    )]
    Vars {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Substring match on the variable name (assignment target).
        #[arg(long)]
        name: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Only assignments inside a function whose name contains this substring.
        #[arg(long = "in-fn")]
        in_fn: Option<String>,
        /// Only assignments whose RHS is a bare identifier matching this substring.
        #[arg(long)]
        source: Option<String>,
        /// Interpret `--name` as a regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Suppress the `flows` column. The column is ON by default
        /// and lists the taint-flow IDs (`F:<16-hex>`) whose
        /// upstream call chains reach the row's enclosing function;
        /// paste any ID into `inspect --flow F:<16-hex>` to expand
        /// the chain. Pass `--no-flows` on very large workspaces
        /// where chain enumeration adds a few seconds you don't
        /// want to pay.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Token-budget ceiling for text output. Shorthand: `4k`
        /// `32k` `128k` `1m`. `0` / `all` / `uncapped` disables.
        /// Defaults to `BONSAI_CONTEXT` or `32k`. JSON stays
        /// uncapped unless explicitly set.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Find string / char literals and classify them.
    #[command(
        display_order = 24,
        long_about = themed_subcommand_long_about("Every string literal in the workspace with an auto-classified \
                      category (`sql`, `url`, `shell`, `regex`, `generic`). Useful \
                      for auditing hard-coded sinks / sources."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every SQL-looking string\n  \
                      $ bonsai-ninja strings ./src --category sql\n  \
                      \n  \
                      # Any string mentioning an internal host\n  \
                      $ bonsai-ninja strings ./src --contains internal.corp")
    )]
    Strings {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Category filter (`sql`, `url`, `shell`, `regex`, `path`, `generic`).
        #[arg(long)]
        category: Option<String>,
        /// Substring match on the literal's text.
        #[arg(long)]
        contains: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Only strings inside a function whose name contains this substring.
        #[arg(long = "in-fn")]
        in_fn: Option<String>,
        /// Minimum character length — filters out empty / trivial literals.
        #[arg(long = "min-len")]
        min_len: Option<usize>,
        /// Interpret `--contains` as a regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Suppress the `flows` column. The column is ON by default
        /// and lists the taint-flow IDs (`F:<16-hex>`) whose
        /// upstream call chains reach the row's enclosing function;
        /// paste any ID into `inspect --flow F:<16-hex>` to expand
        /// the chain. Pass `--no-flows` on very large workspaces
        /// where chain enumeration adds a few seconds you don't
        /// want to pay.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Token-budget ceiling for text output. Shorthand: `4k`
        /// `32k` `128k` `1m`. `0` / `all` / `uncapped` disables.
        /// Defaults to `BONSAI_CONTEXT` or `32k`. JSON stays
        /// uncapped unless explicitly set.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Every comment in the workspace with an auto-classified kind.
    #[command(
        display_order = 24,
        long_about = themed_subcommand_long_about("Every comment node across the workspace, classified into \
                      `todo` / `fixme` / `security` / `doc` / \
                      `disabled_code` / `generic` so reviewers can zero \
                      in on the attention-grabbing ones. Line comments, \
                      block comments, doc comments, shebangs, and \
                      Python docstrings all surface through the same \
                      table. Same paging / filter surface as `strings`."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every TODO / FIXME / SECURITY marker\n  \
                      $ bonsai-ninja comments ./src --kind todo\n  \
                      $ bonsai-ninja comments ./src --kind fixme\n  \
                      \n  \
                      # All doc comments for one module\n  \
                      $ bonsai-ninja comments ./src --kind doc --file auth_service\n  \
                      \n  \
                      # Commented-out code\n  \
                      $ bonsai-ninja comments ./src --kind disabled_code\n  \
                      \n  \
                      # Free-form substring search\n  \
                      $ bonsai-ninja comments ./src --contains 'CVE-' --regex")
    )]
    Comments {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Kind filter — `todo`, `fixme`, `security`, `doc`,
        /// `disabled_code`, `generic`. Substring match, so
        /// `--kind do` matches both `todo` and `doc`.
        #[arg(long)]
        kind: Option<String>,
        /// Substring match on the comment text.
        #[arg(long)]
        contains: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Only comments inside a function whose name contains
        /// this substring.
        #[arg(long = "in-fn")]
        in_fn: Option<String>,
        /// Minimum character length — filters out trivial markers.
        #[arg(long = "min-len")]
        min_len: Option<usize>,
        /// Interpret `--contains` as a regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Token-budget ceiling for text output. Shorthand: `4k`
        /// `32k` `128k` `1m`. `0` / `all` / `uncapped` disables.
        /// Defaults to `BONSAI_CONTEXT` or `32k`.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Inspect call arguments with callee name, position, and verbatim text.
    #[command(
        display_order = 25,
        long_about = themed_subcommand_long_about("Every call-site argument, positional or keyword, with the \
                      callee, the arg's position (or keyword name), and \
                      the verbatim source text. Lets you audit what's \
                      actually being handed to a sensitive callee — \
                      `--callee os.system` pairs naturally with \
                      `--value` / `--position` narrowers."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # What gets passed to os.system anywhere in the repo?\n  \
                      $ bonsai-ninja args ./src --callee os.system\n  \
                      \n  \
                      # First-position args only (the command string to system/exec)\n  \
                      $ bonsai-ninja args ./src --callee subprocess.run --position 0\n  \
                      \n  \
                      # Named-arg filter (Python keyword arg)\n  \
                      $ bonsai-ninja args ./src --callee connect --keyword host\n  \
                      \n  \
                      # Regex on the arg value\n  \
                      $ bonsai-ninja args ./src --value 'secret|token' --regex")
    )]
    Args {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Substring match on the callee name.
        #[arg(long)]
        callee: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Only calls inside an enclosing fn whose name contains this substring.
        #[arg(long = "in-fn")]
        in_fn: Option<String>,
        /// Substring match on the argument's verbatim text.
        #[arg(long)]
        value: Option<String>,
        /// Only arguments at this positional index (0-based).
        #[arg(long)]
        position: Option<usize>,
        /// Only keyword args whose name matches this substring.
        #[arg(long)]
        keyword: Option<String>,
        /// Interpret `--callee` / `--value` as regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Suppress the `flows` column. The column is ON by default
        /// and lists the taint-flow IDs (`F:<16-hex>`) whose
        /// upstream call chains reach the row's enclosing function;
        /// paste any ID into `inspect --flow F:<16-hex>` to expand
        /// the chain. Pass `--no-flows` on very large workspaces
        /// where chain enumeration adds a few seconds you don't
        /// want to pay.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Token-budget ceiling for text output. Shorthand: `4k`
        /// `32k` `128k` `1m`. `0` / `all` / `uncapped` disables.
        /// Defaults to `BONSAI_CONTEXT` or `32k`. JSON stays
        /// uncapped unless explicitly set.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Review classes / structs / interfaces with method counts.
    #[command(
        display_order = 26,
        long_about = themed_subcommand_long_about("Every class / struct / trait / interface / enum decl, with \
                      method count and (up to 8) method names per row. The \
                      `flows` column unions the flow-ids reaching every \
                      method the class declares, so a single row captures \
                      every chain that lands anywhere inside the class."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every class in the workspace\n  \
                      $ bonsai-ninja classes ./src\n  \
                      \n  \
                      # Classes whose name matches a pattern\n  \
                      $ bonsai-ninja classes ./src --name Service\n  \
                      \n  \
                      # Only structs / traits, with minimum method count\n  \
                      $ bonsai-ninja classes ./src --kind struct --min-methods 3")
    )]
    Classes {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Substring match on the class name.
        #[arg(long)]
        name: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Kind filter (`class`, `struct`, `trait`, `interface`, `enum`).
        #[arg(long)]
        kind: Option<String>,
        /// Only classes that declare a method whose name matches this substring.
        #[arg(long = "has-method")]
        has_method: Option<String>,
        /// Only classes with at least this many methods.
        #[arg(long = "min-methods")]
        min_methods: Option<usize>,
        /// Interpret `--name` as a regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Suppress the `flows` column. The column is ON by default
        /// and lists the taint-flow IDs (`F:<16-hex>`) whose
        /// upstream call chains reach the row's enclosing function;
        /// paste any ID into `inspect --flow F:<16-hex>` to expand
        /// the chain. Pass `--no-flows` on very large workspaces
        /// where chain enumeration adds a few seconds you don't
        /// want to pay.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Token-budget ceiling for text output. Shorthand: `4k`
        /// `32k` `128k` `1m`. `0` / `all` / `uncapped` disables.
        /// Defaults to `BONSAI_CONTEXT` or `32k`. JSON stays
        /// uncapped unless explicitly set.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Every indexed reference to a symbol.
    #[command(
        display_order = 27,
        long_about = themed_subcommand_long_about("Find every place a symbol is read, called, or referenced. \
                      Columns: symbol, kind, enclosing fn, location, code.\n\
                      \n\
                      A symbol is required — either as the positional \
                      argument or via `--symbol`. The `flows` column shows \
                      every `F:<16-hex>` whose upstream chain reaches the \
                      ref's enclosing function; paste into \
                      `inspect --flow F:<16-hex>` to expand the chain."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Positional symbol\n  \
                      $ bonsai-ninja refs ./src run_admin_command\n  \
                      \n  \
                      # Equivalent, via --symbol\n  \
                      $ bonsai-ninja refs ./src --symbol handle_request\n  \
                      \n  \
                      # Only call-site references\n  \
                      $ bonsai-ninja refs ./src verify_token --kind call\n  \
                      \n  \
                      # Regex across every symbol matching a pattern\n  \
                      $ bonsai-ninja refs ./src --regex 'handle_.*'")
    )]
    Refs {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Positional symbol (alternative to `--symbol`).
        symbol_pos: Option<String>,
        /// Symbol name whose refs to surface. The positional symbol
        /// takes precedence when both are set.
        #[arg(long)]
        symbol: Option<String>,
        /// Ref kind filter (`call`, `read`, `write`, `type`, `import`, `macro`, `decorator`, `other`).
        #[arg(long)]
        kind: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Only refs inside an enclosing fn whose name contains this substring.
        #[arg(long = "in-fn")]
        in_fn: Option<String>,
        /// Interpret the symbol as a regex instead of an exact/substring match.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Max rows in the text table (`0` = uncapped). JSON is
        /// always uncapped.
        #[arg(long, default_value_t = BROWSE_TEXT_LIMIT_DEFAULT)]
        limit: usize,
        /// Suppress the `flows` column. The column is ON by default
        /// and lists the taint-flow IDs (`F:<16-hex>`) whose
        /// upstream call chains reach the row's enclosing function;
        /// paste any ID into `inspect --flow F:<16-hex>` to expand
        /// the chain. Pass `--no-flows` on very large workspaces
        /// where chain enumeration adds a few seconds you don't
        /// want to pay.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Token-budget ceiling for text output. Shorthand: `4k`
        /// `32k` `128k` `1m`. `0` / `all` / `uncapped` disables.
        /// Defaults to `BONSAI_CONTEXT` or `32k`. JSON stays
        /// uncapped unless explicitly set.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number (`--page 3`), stable
        /// cursor (`--page P:xxxxxxxx`), or `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Fuzzy search across indexed browse facts.
    #[command(
        display_order = 28,
        long_about = themed_subcommand_long_about("Prefix-first fuzzy search over every indexed browse fact: \
                      decl names / qualified names, call sites, imports, \
                      assignment targets, strings, comments, args, and refs. \
                      Fast; good as a `grep` alternative that knows about \
                      structure.\n\
                      \n\
                      A query is required — either as the positional \
                      argument or via `--query`. Use `--regex` to treat the \
                      query as a regex; `--kind` to filter by fact kind; \
                      `--file` to scope to a path substring. The `flows` \
                      column (on by default) lists every `F:<16-hex>` that \
                      reaches each hit — paste into `inspect --flow` to \
                      expand the chain."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Positional query\n  \
                      $ bonsai-ninja search ./src run_admin\n  \
                      \n  \
                      # Equivalent, via --query\n  \
                      $ bonsai-ninja search ./src --query verify --limit 50\n  \
                      \n  \
                      # Regex query, methods only\n  \
                      $ bonsai-ninja search ./src --query 'handle_.*' --regex --kind method")
    )]
    Search {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Positional query (alternative to `--query`).
        query_pos: Option<String>,
        /// Search query. The positional query takes precedence when
        /// both are set.
        #[arg(long)]
        query: Option<String>,
        /// Fact-kind filter (`function`, `call`, `import`, `var`,
        /// `string`, `comment`, `arg`, `ref-read`, …).
        #[arg(long)]
        kind: Option<String>,
        /// Substring match on the file path.
        #[arg(long)]
        file: Option<String>,
        /// Interpret the query as a regex.
        #[arg(long, default_value_t = false)]
        regex: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Suppress the `flows` column. On by default; pass
        /// `--no-flows` when chain enumeration would slow things
        /// down on a very large workspace.
        #[arg(long = "no-flows", default_value_t = false)]
        no_flows: bool,
        /// Token-budget ceiling for text output. Shorthand `4k` etc.
        #[arg(long)]
        context: Option<String>,
        /// Page to render (1-based number, `P:xxxxxxxx`, or `next`).
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },
    /// Inspect a name / pattern across every fact with full cross-module
    /// flow chains — the tool's headline feature.
    #[command(
        display_order = 1,
        long_about = themed_subcommand_long_about("Inspect a name / pattern across every fact: decls \
                      (functions, methods, classes, structs), calls, imports, \
                      vars (assignments), strings, args, refs, decorators.\n\
                      \n\
                      For decl hits, emits every upstream cross-module flow \
                      from every entry point that reaches the match, with the \
                      source lines inlined and annotated (SOURCE → ... → \
                      MATCH). For non-decl hits (a specific call, string, \
                      assignment, decorator), surfaces the occurrence in its \
                      enclosing function with the chain(s) that reach it.\n\
                      \n\
                      Chains that share the same entry + sink but take \
                      different intermediate paths get letter-suffixed labels \
                      (FLOW 2a / FLOW 2b) so branch splits are visible.\n\
                      \n\
                      Every flow carries a stable `F:<16-hex>` id printed \
                      next to its header; use `--flow F:id` to re-render \
                      just that chain across runs. `--group G:id` pins a \
                      cluster of chains that share a tail. Architecturally \
                      `inspect` is the pattern-less query layer over the \
                      indexed taint graph `export` ships; `security taint-analysis` \
                      applies rulepack source / sink / sanitizer matches with \
                      exact source seeds."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every flow that reaches os.system\n  \
                      $ bonsai-ninja inspect ./src --query os.system\n  \
                      \n  \
                      # Regex query — every flow that reaches any exec call\n  \
                      $ bonsai-ninja inspect ./src --query '^(exec|system|popen)$' --regex\n  \
                      \n  \
                      # Inspect a specific decl (shows every entry → decl flow)\n  \
                      $ bonsai-ninja inspect ./src handle_request\n  \
                      \n  \
                      # Restrict to call-kind hits only\n  \
                      $ bonsai-ninja inspect ./src --query exec --kind call\n  \
                      \n  \
                      # Pin one flow by its stable id across runs\n  \
                      $ bonsai-ninja inspect ./src --query handle_request --flow F:0123456789abcdef\n  \
                      \n  \
                      # --from/--to window on any chain in the workspace\n  \
                      $ bonsai-ninja inspect ./src --from handle_request --to os.system\n  \
                      \n  \
                      # Grouped view bubbles shared tails into GROUP blocks\n  \
                      $ bonsai-ninja inspect ./src --query exec --view grouped\n  \
                      \n  \
                      # JSON output for CI / tooling\n  \
                      $ bonsai-ninja inspect ./src --query os.system --format json\n\n\
                      SAMPLE OUTPUT\n\n  \
                      inspect `os.system` — 0 decl hit(s), 1 other hit(s)\n  \
                      by kind: call=1\n  \
                      \n  \
                      ▸ hit call os.system (python/micro/auth_service.py:19:9)\n  \
                      \n  \
                      ══════════════════════════════════════════════════════════════════════\n  \
                      FLOW 1 os.system\n  \
                      handle_request → update_user → run_admin_command\n  \
                      ══════════════════════════════════════════════════════════════════════\n  \
                      \n  \
                      [module] python/micro/gateway.py\n  \
                      └─ [def] handle_request() :10\n  \
                          1  def handle_request():  # [FLOW 1 SOURCE: entry handle_request]\n  \
                                 token = request.args.get(\"token\")  # source: user input\n  \
                          2      result = update_user(token, action)  # [FLOW 1 -> update_user]\n  \
                      ...\n  \
                      [module] python/micro/auth_service.py\n  \
                      └─ [def] run_admin_command(user_id, cmd) :17\n  \
                          4      os.system(\"notify-admin \" + cmd)  # [FLOW 1 MATCH: call os.system]")
    )]
    Inspect {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Positional search query. Case-insensitive substring by default;
        /// pair with `--regex` to interpret as a regex.
        symbol_pos: Option<String>,
        /// Preferred query flag.
        #[arg(long)]
        query: Option<String>,
        /// Legacy alias for `--query`; kept for backward-compat.
        #[arg(long, hide = true)]
        symbol: Option<String>,
        /// Interpret the query as a regex instead of a fuzzy substring.
        #[arg(long, default_value_t = false)]
        regex: bool,
        /// Restrict matches to one fact kind. Repeat to include multiple.
        /// Kinds: decl, call, import, var, string, arg, ref, decorator.
        #[arg(long)]
        kind: Vec<String>,
        /// Fuzzy filter: only keep flows that pass through something
        /// matching this substring anywhere in the chain (any hop) or
        /// the hit text. `--from request` catches `handle_request`
        /// even as an intermediate hop.
        #[arg(long)]
        from: Option<String>,
        /// Narrow `--from` matching to a single browse-fact kind —
        /// e.g. `--from-kind read` only matches `--from X` when `X`
        /// appears as a read reference, not a call-site name or an
        /// import. Precise compilation surface for security rules.
        #[arg(long = "from-kind", value_enum)]
        from_kind: Option<FactKindFilter>,
        /// Fuzzy filter: only keep flows that reach something matching
        /// this substring anywhere in the chain or the hit text.
        /// `--to os.system` keeps the `os.system` call-hit even though
        /// the chain itself ends at `run_admin_command` (the enclosing
        /// function).
        #[arg(long)]
        to: Option<String>,
        /// Narrow `--to` matching to a single browse-fact kind —
        /// mirror of `--from-kind`.
        #[arg(long = "to-kind", value_enum)]
        to_kind: Option<FactKindFilter>,
        /// Only keep hits whose file path contains this substring.
        #[arg(long)]
        file: Option<String>,
        /// Only keep non-decl hits whose enclosing function matches
        /// this substring. (`update_user` / `verify_token` / …)
        #[arg(long = "in-fn")]
        in_fn: Option<String>,
        /// Max number of flows to show per decl hit. Defaults are
        /// tuned to surface most chains while keeping queries fast on
        /// huge workspaces. When a cap kicks in the output explicitly
        /// reports `[truncated by max-flows cap]` — silent data loss
        /// is impossible. Use `--all` for guaranteed exhaustive
        /// enumeration.
        #[arg(long, default_value_t = 50)]
        max_flows: usize,
        /// DFS probe budget for chain enumeration. Default lets
        /// realistic call graphs (Redis, lodash, kotlinx.coroutines)
        /// finish; the truncation warning fires when it doesn't.
        #[arg(long, default_value_t = 500)]
        max_entry_probes: usize,
        /// Max number of non-decl hits (calls / strings / args /
        /// imports / refs) to list. Defaults to 200 — high enough to
        /// avoid silent miss for most queries, with the truncation
        /// banner surfacing the rest.
        #[arg(long, default_value_t = 200)]
        max_hits: usize,
        /// Show every flow / hit unconditionally — equivalent to
        /// `--max-flows usize::MAX --max-entry-probes usize::MAX
        /// --max-hits usize::MAX`. Use when you need certainty that
        /// no path is dropped (slow on dense call graphs like
        /// kotlinx.coroutines).
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Render flows without inlined source bodies. The chain
        /// display line, `FLOW N` header (with `flow_id` + precision
        /// tag), and a compact step list stay — the multi-line
        /// function blocks are dropped. Useful for surveying large
        /// result sets, piping to LLMs, and any case where you need
        /// the structural evidence but not the full transcript.
        /// `--format json` is unaffected (JSON already carries the
        /// same steps + location data).
        #[arg(long, default_value_t = false)]
        compact: bool,
        /// Re-render only the flow whose stable content-hash id
        /// matches (format `F:` + 16 hex, as shown next to each
        /// `FLOW N` header). Lets tools / scripts cite a single
        /// flow across runs without reproducing the full query
        /// plus `--from` / `--to` shape.
        #[arg(long)]
        flow: Option<String>,
        /// Output shape: `trace` (one block per flow, the default),
        /// `grouped` (cluster flows by shared tail into GROUP blocks
        /// with per-member prefixes), or `auto` (trace when the
        /// result set is small, grouped once it gets noisy).
        #[arg(long, value_enum, default_value_t = InspectView::Trace)]
        view: InspectView,
        /// Re-render only the flow group whose stable content-hash
        /// id matches (format `G:` + 16 hex, as shown next to each
        /// `GROUP N` header in grouped view). Complementary to
        /// `--flow <flow_id>` — one pins a single chain, the other
        /// pins a cluster of chains that share a tail.
        #[arg(long)]
        group: Option<String>,
        /// Token-budget ceiling for text output. Paging unit is
        /// one FLOW block (never mid-flow). Shorthand `4k`, `32k`,
        /// `128k`, `1m`; `0` / `all` / `uncapped` disables.
        /// Default 32k for text; JSON stays uncapped unless set.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `P:xxxxxxxx` cursor,
        /// or `next` to advance from this shell's last run.
        #[arg(long)]
        page: Option<String>,
        /// Output shape — `text` for the rendered table / tree, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },
    /// Export the complete analyzed workspace (index + taint graph).
    #[command(
        display_order = 12,
        long_about = themed_subcommand_long_about("Dump the full analyzed workspace as a single JSON document: \
                      every file's decls / refs / imports / strings / classes, \
                      the per-function flow-event tree, the resolved call-graph \
                      edge list, workspace-wide flow chains, and a complete \
                      `taint_graph` section that materializes the analyzer's \
                      engine state end-to-end.\n\
                      \n\
                      The `taint_graph` is the raw view both `inspect` and \
                      `security` query: per-function return-taint summaries, \
                      per-file alias maps, class field-taint (G3), \
                      reachability facts kinded by (decl / call / read / \
                      write / arg / string / import / class), per-parameter \
                      assign-chain expansion, per-parameter CFG dataflow, \
                      inferred entry-points, interprocedural propagation \
                      records, resolved FuncId chains per target, and \
                      stable `F:` / `G:` flow-id labels. Downstream tooling \
                      can reconstruct every finding without re-running the \
                      analyzer.\n\
                      \n\
                      Output defaults to compact JSON on stdout. `--format \
                      networkx` emits NetworkX node-link JSON; `--format \
                      graphml` emits a directed GraphML property graph; \
                      `--format cypher` emits a Neo4j-compatible MERGE script."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Full export to a file\n  \
                      $ bonsai-ninja export ./src > index.json\n  \
                      \n  \
                      # NetworkX node-link graph\n  \
                      $ bonsai-ninja export ./src --format networkx > graph.node_link.json\n  \
                      \n  \
                      # Generic graph database / graph-tooling import\n  \
                      $ bonsai-ninja export ./src --format graphml > graph.graphml\n  \
                      \n  \
                      # Neo4j / Cypher import script\n  \
                      $ bonsai-ninja export ./src --format cypher > graph.cypher\n  \
                      \n  \
                      # Count decls across the workspace\n  \
                      $ bonsai-ninja export ./src | jq '[.files[].decls | length] | add'\n  \
                      \n  \
                      # Inspect the taint graph shape\n  \
                      $ bonsai-ninja export ./src | jq '.taint_graph | keys'\n  \
                      \n  \
                      # Every interprocedural propagation edge\n  \
                      $ bonsai-ninja export ./src | jq '.taint_graph.propagations[].records[]'")
    )]
    Export {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Force exhaustive interprocedural propagation records in the export.
        /// Large workspaces skip this section by default because exact
        /// propagation-record materialization is the expensive part of export;
        /// `inspect`, `trace`, and `security taint-analysis` still query the
        /// indexed taint graph and compute only missing facts lazily.
        #[arg(long)]
        full_propagations: bool,
        /// Output shape. `json` is the full native export; `networkx`,
        /// `graphml`, and `cypher` project the same taint graph into
        /// graph-database-friendly node/edge formats.
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
    },

    /// Manage analyzer caches.
    #[command(
        display_order = 13,
        long_about = themed_subcommand_long_about("Inspect, clear, or rebuild bonsai-ninja's caches.\n\
                      \n\
                      bonsai-ninja keeps two kinds of cache state:\n\
                      \n  - In-process memo caches (chains, downstream, reachable, \
                      callees, enclosing) — built fresh each run, dropped on \
                      exit. Use `--no-cache` / `BONSAI_NO_CACHE=1` on any \
                      command to bypass them for a single invocation.\n\
                      \n  - On-disk artifacts under `<workspace>/.bonsai/` — \
                      used for persisted sidecars, currently including the \
                      dataflow taint graph at `dataflow.v2.bin` and the default \
                      export JSON; paginated commands also write rendered page \
                      windows under `page-cache.v2/`. `cache stats` reports \
                      the sidecar dir, `cache clear` removes it, and \
                      `cache rebuild` refreshes the dataflow graph."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      $ bonsai-ninja cache stats\n  \
                      $ bonsai-ninja cache clear ./src\n  \
                      $ bonsai-ninja cache clear ./src --dataflow-only\n  \
                      $ bonsai-ninja cache rebuild ./src\n  \
                      $ bonsai-ninja --no-cache inspect ./src --query system")
    )]
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Security analysis mode — rulepack-driven source / sink / dep /
    /// taint scanning. Each subcommand mirrors the surface of
    /// `bonsai-ninja search` (paginated tables, file filters, JSON
    /// format) but the rulepack is the query — you don't pass a string,
    /// the rules pre-declare what to look for. `taint-analysis` adds
    /// the inspect-style finding report; `source-analysis` maps downstream
    /// source paths without requiring sinks. See `docs/pattern-guide.mdx`.
    #[command(
        display_order = 14,
        long_about = themed_subcommand_long_about("`bonsai-ninja security` is a separate command family for \
                      rulepack-driven security analysis. It loads per-language \
                      `sources` / `sinks` / `sanitizers` YAML rules from a \
                      `security-patterns/` directory, applies them to the indexed \
                      taint graph with exact source seeds, and emits findings with stable \
                      `S:` content-hash ids.\n\
                      \n\
                      Every subcommand mirrors the pagination + filter surface \
                      of the browse commands (`--file`, `--limit`, `--context`, \
                      `--page`, `--format json`); the rulepack is the query. \
                      `taint-analysis` adds the inspect-style finding report; \
                      `source-analysis` maps downstream source paths without \
                      requiring sinks. See `docs/pattern-guide.mdx` for the \
                      rule schema."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Remote-trust sources (user input, network data)\n  \
                      $ bonsai-ninja security ./src sources --trust remote\n  \
                      \n  \
                      # Every command-injection sink the pack defines\n  \
                      $ bonsai-ninja security ./src sinks --tag command-injection\n  \
                      \n  \
                      # Which packages the rulepack flags are actually imported?\n  \
                      $ bonsai-ninja security ./src deps --severity critical\n  \
                      \n  \
                      # High-severity source→sink taint only\n  \
                      $ bonsai-ninja security ./src taint-analysis --severity high\n  \
                      \n  \
                      # Map downstream paths from remote sources\n  \
                      $ bonsai-ninja security ./src source-analysis --trust remote\n  \
                      \n  \
                      # JSON for CI / tooling, no row cap\n  \
                      $ bonsai-ninja security ./src taint-analysis --format json --all\n  \
                      \n  \
                      # Audit your own rulepack for coverage gaps\n  \
                      $ bonsai-ninja security ./src pack --audit")
    )]
    Security {
        /// Workspace root to analyze.
        workspace: PathBuf,
        #[command(subcommand)]
        action: SecurityAction,
    },

    /// Workspace tree with finding / flow / cross-file edge annotations.
    #[command(
        display_order = 23,
        long_about = themed_subcommand_long_about(
            "Hierarchical workspace view with each file row carrying \
             the connections that exist on top of it: finding ids \
             (`S:<16-hex>`), flow ids (`F:<16-hex>`), the most-severe \
             flow's entry/exit, and the cross-file caller / callee \
             edges that thread into and out of the file. Directory \
             rows roll up severity counts.\n\
             \n\
             Every connection field carries a full locator \
             (`module=… class=… fn=… file:line:col`) so renderers \
             compose decl headers the same way `dump-edges` and \
             `inspect` already do. The default view includes inline \
             `←in:` / `→out:` rows when a file has cross-file edges; \
             `--compact` drops those rows for a one-line-per-entry \
             tree.\n\
             \n\
             Findings populate when a rulepack is present (auto-\
             discovered at `./security-patterns/` or via \
             `--rules-dir`); without one, the tree still shows \
             cross-file edges and file structure."
        ),
        after_help = themed_subcommand_after_help(
            "EXAMPLES\n\n  \
             # Workspace navigation with finding annotations\n  \
             $ bonsai-ninja tree ./src\n  \
             \n  \
             # Cap depth and use the compact one-line tree\n  \
             $ bonsai-ninja tree ./src --max-depth 3 --compact\n  \
             \n  \
             # Only files with a critical-severity finding\n  \
             $ bonsai-ninja tree ./src --severity critical\n  \
             \n  \
             # Machine-readable shape for tooling\n  \
             $ bonsai-ninja tree ./src --format json | jq '.summary'"
        )
    )]
    Tree {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// Limit the tree to the first N levels.
        #[arg(long)]
        max_depth: Option<usize>,
        /// Substring match on file paths.
        #[arg(long)]
        file: Option<String>,
        /// Exclude files whose paths contain this substring.
        #[arg(long = "exclude-file")]
        exclude_file: Vec<String>,
        /// Only files whose findings reach at least this severity.
        #[arg(long)]
        severity: Option<String>,
        /// Children-per-dir cap (`0` = uncapped).
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Drop the inline annotation rows; emit a one-liner per file.
        #[arg(long, default_value_t = false)]
        compact: bool,
        /// Token-budget ceiling for text output (e.g. `4k`, `32k`,
        /// `128k`, `1m`). Defaults to `BONSAI_CONTEXT` or `32k`.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `next`, or `P:` cursor.
        #[arg(long)]
        page: Option<String>,
        /// Lift every cap; render the entire tree.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` or `json`.
        #[arg(long, default_value = "text")]
        format: String,
        /// Directory containing the rulepack tree (for finding /
        /// severity annotations). Lookup when omitted:
        /// `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
    },

    /// Single-file view with cross-file caller/callee bodies inlined.
    #[command(
        display_order = 24,
        name = "read-file",
        long_about = themed_subcommand_long_about(
            "Cat-style view of a single file overlaid with the \
             analysis facts that touch its lines: line marks for \
             every finding (source / sink / sanitizer), the flow's \
             entry / exit pair, and cross-file caller / callee bodies \
             inlined right below the primary source when available.\n\
             \n\
             Compact mode is a step list of marks (one line per \
             marked location, with finding id, rule, severity, and \
             tainted source name). The default view shows the \
             primary file source with marks beside the relevant \
             lines, then pulls in cross-file callers and callees \
             with full bodies. `--lines A:B` slices the primary \
             file; `--from <needle>` / `--to <needle>` filter the \
             rendered marks to flows that connect them.\n\
             \n\
             Findings populate when a rulepack is present (auto-\
             discovered at `./security-patterns/` or via \
             `--rules-dir`); without one, only structural facts \
             (decls, cross-file edges) render."
        ),
        after_help = themed_subcommand_after_help(
            "EXAMPLES\n\n  \
             # Sink-marked view of a known-bad file\n  \
             $ bonsai-ninja read-file ./src auth/verify_token.py\n  \
             \n  \
             # Compact mark list for quick triage\n  \
             $ bonsai-ninja read-file ./src auth/verify_token.py --compact\n  \
             \n  \
             # Slice + filter to flows on a chain from `request.args` to `os.system`\n  \
             $ bonsai-ninja read-file ./src auth/verify_token.py --lines 1:50 --from request.args --to os.system\n  \
             \n  \
             # Machine-readable shape for tooling\n  \
             $ bonsai-ninja read-file ./src auth/verify_token.py --format json"
        )
    )]
    ReadFile {
        /// Workspace root to analyze.
        workspace: PathBuf,
        /// File path (workspace-relative or absolute).
        path: String,
        /// Restrict to a 1-based line range (`A:B`, inclusive).
        #[arg(long)]
        lines: Option<String>,
        /// Filter to flows the needle participates in (source side).
        #[arg(long)]
        from: Option<String>,
        /// Filter to flows the needle participates in (sink side).
        #[arg(long)]
        to: Option<String>,
        /// Hard cap on inlined caller / callee bodies (default 8).
        #[arg(long)]
        max_inlined_bodies: Option<usize>,
        /// Drop the inlined-body section; emit a step-list of marks.
        #[arg(long, default_value_t = false)]
        compact: bool,
        /// Token-budget ceiling for text output (e.g. `4k`, `32k`,
        /// `128k`, `1m`). Defaults to `BONSAI_CONTEXT` or `32k`.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `next`, or `P:` cursor.
        #[arg(long)]
        page: Option<String>,
        /// Lift every cap; render the full file with all bodies.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` or `json`.
        #[arg(long, default_value = "text")]
        format: String,
        /// Directory containing the rulepack tree (for finding /
        /// severity annotations). Lookup when omitted:
        /// `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
pub(crate) enum SecurityAction {
    /// Enumerate source matches across the workspace — one row per fact
    /// a loaded `sources/` rule claimed. Mirrors `bonsai-ninja search`:
    /// table output with paging, JSON, file filters, etc. The rulepack
    /// is the query.
    #[command(
        long_about = themed_subcommand_long_about("Enumerate source matches across the workspace — one row per \
                      fact a loaded `sources/` rule claimed. Mirrors \
                      `bonsai-ninja search`: table output with paging, JSON, \
                      and file filters, except the rulepack is the query — \
                      you don't pass a search string.\n\
                      \n\
                      Use this to answer \"which user-input / network / IPC \
                      entry points does the pack flag in my workspace?\" \
                      without running a full flow analysis."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Remote-trust sources only (HTTP params, request bodies)\n  \
                      $ bonsai-ninja security ./src sources --trust remote\n  \
                      \n  \
                      # Narrow to a single rule id\n  \
                      $ bonsai-ninja security ./src sources --rule py.flask.request\n  \
                      \n  \
                      # JSON for tooling, no row cap\n  \
                      $ bonsai-ninja security ./src sources --format json --all")
    )]
    Sources {
        /// Directory containing the `langs/<lang>/…` rulepack tree.
        /// Lookup when omitted: `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
        /// Filter to rules whose id matches this exact string.
        #[arg(long)]
        rule: Option<String>,
        /// Filter to rules whose id matches this regex.
        #[arg(long)]
        rule_regex: Option<String>,
        /// Trust class narrower — `remote`, `local`, `service`, `ipc`,
        /// `database`, `library`, `config`, or `physical`.
        #[arg(long)]
        trust: Option<String>,
        /// Source category narrower. Common values across the
        /// shipped rulepack: `db-input`, `hardware-io`, `http-input`,
        /// `net-input`. Custom categories from project-local rules
        /// also work; the matcher does substring match.
        #[arg(long)]
        category: Option<String>,
        /// Source tag narrower. Documented vocabulary:
        /// `block-context`, `browser-input`, `calldata`,
        /// `caller-identity`, `caller-input`, `caller-value`,
        /// `cli-input`, `clipboard-input`, `cloud-event`, `cloud-input`,
        /// `config-input`, `db-input`, `db-row`, `deep-link`,
        /// `deprecated-auth`, `env-input`, `event-input`,
        /// `graphql-input`, `http-input`, `hw-input`, `ipc-input`,
        /// `ipc-message`, `local-input`, `net-input`, `network-input`,
        /// `network-response`, `oracle-input`, `push-input`,
        /// `push-message`, `queue-input`, `queue-message`, `rpc-input`,
        /// `socket-input`, `token-input`, `ui-input`, `ws-input`.
        #[arg(long)]
        tag: Option<String>,
        /// File-path include substring (repeatable). Keep only hits in
        /// files whose path contains any of the given substrings.
        #[arg(long = "file")]
        files: Vec<String>,
        /// File-path exclude substring (repeatable). Drop hits in files
        /// whose path contains any of the given substrings.
        #[arg(long = "exclude-file")]
        exclude_files: Vec<String>,
        /// Cap on rendered rows (mirrors `search --limit`). `0` =
        /// uncapped. JSON is always uncapped.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Token-budget ceiling for text output (`4k`, `32k`, `128k`,
        /// `1m`; `0`/`all`/`uncapped` disables).
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `P:xxxxxxxx` cursor, or
        /// `next`.
        #[arg(long)]
        page: Option<String>,
        /// Bypass paging entirely — emit every row.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Enumerate sink matches across the workspace. Same surface as
    /// `sources` — adds a `severity` column and `--severity` narrower.
    #[command(
        long_about = themed_subcommand_long_about("Enumerate sink matches across the workspace — one row per \
                      fact a loaded `sinks/` rule claimed. Same surface as \
                      `security sources` plus a severity column and \
                      `--severity` narrower so you can home in on high-risk \
                      sinks first.\n\
                      \n\
                      Sinks are the landing sites the pack considers \
                      dangerous — command exec, SQL concatenation, \
                      deserialization, HTML injection, etc. Run this before \
                      `security taint-analysis` when you want to know what \
                      the pack flags in your code regardless of reachability."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every high-severity sink\n  \
                      $ bonsai-ninja security ./src sinks --severity high\n  \
                      \n  \
                      # Command-injection sinks only\n  \
                      $ bonsai-ninja security ./src sinks --tag command-injection\n  \
                      \n  \
                      # Narrow to a directory for triage\n  \
                      $ bonsai-ninja security ./src sinks --file handlers/")
    )]
    Sinks {
        /// Directory containing the `langs/<lang>/…` rulepack tree.
        /// Lookup when omitted: `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
        /// Filter to rules whose id matches this exact string.
        #[arg(long)]
        rule: Option<String>,
        /// Filter to rules whose id matches this regex.
        #[arg(long)]
        rule_regex: Option<String>,
        /// Severity-floor filter — keep rules whose severity is at
        /// least this level. Accepts exactly one of `info`, `low`,
        /// `medium`, `high`, `critical` (strict — any other value is
        /// rejected with an error so typos like `hihg` can't silently
        /// widen the filter).
        #[arg(long)]
        severity: Option<String>,
        /// Sink tag narrower. Documented vocabulary:
        /// `access-control`, `address-squatting`, `atom-exhaustion`,
        /// `cache-poisoning`, `code-injection`, `command-injection`,
        /// `cookie-misconfig`, `cors`, `cql-injection`,
        /// `cypher-injection`, `dos`, `env-leak`, `ets-match-dos`,
        /// `external-call`, `file-upload`, `format-string`, `graphql`,
        /// `graphql-injection`, `hash-collision`, `header-injection`,
        /// `host-header`, `information-exposure`,
        /// `insecure-deserialization`, `insecure-temp-file`,
        /// `integer-overflow`, `intent-redirection`, `jndi-injection`,
        /// `jwt`, `ldap-injection`, `lfi`, `log-injection`,
        /// `mass-assignment`, `memory-safety`, `nosql-injection`,
        /// `oauth`, `open-redirect`, `oracle-manipulation`,
        /// `path-traversal`, `prototype-pollution`, `queue-injection`,
        /// `race`, `redos`, `reentrancy`, `signature-replay`,
        /// `smtp-injection`, `sql-injection`, `sqli`,
        /// `state-manipulation`, `ssrf`, `ssti`, `timeout-bypass`,
        /// `timing-attack`, `unchecked-return`, `untrusted-token`,
        /// `weak-auth`, `weak-crypto`, `weak-randomness`, `weak-tls`,
        /// `web-llm`, `xss`, `xxe`, `zip-slip`.
        #[arg(long)]
        tag: Option<String>,
        /// Sink family narrower — matches the rule's tag exactly OR
        /// its canonical sink family (e.g. `--category cmdi` hits any
        /// `*.cmdi.*` rule; `--category deserialization` and
        /// `--category deser` both hit `*.deser.*`). Common sink
        /// categories used by the rulepack: `code-exec`,
        /// `deserialize`, `file-read`, `file-write`, `memory`,
        /// `network-egress`, `process-exec`, `sql-exec`,
        /// `template-render`.
        #[arg(long)]
        category: Option<String>,
        /// File-path include substring (repeatable).
        #[arg(long = "file")]
        files: Vec<String>,
        /// File-path exclude substring (repeatable).
        #[arg(long = "exclude-file")]
        exclude_files: Vec<String>,
        /// Cap on rendered rows (`0` = uncapped).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Token-budget ceiling for text output (`4k`, `32k`, `128k`,
        /// `1m`; `0`/`all`/`uncapped` disables).
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `P:xxxxxxxx` cursor, or
        /// `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Enumerate sanitizer matches across the workspace. Same surface
    /// as `sources` / `sinks` — each row is a call site the rulepack
    /// claims is a cleansing operation (html-escape, shell-escape,
    /// url-encode, constant-time compare, etc).
    #[command(
        long_about = themed_subcommand_long_about("Enumerate sanitizer matches across the workspace — one row \
                      per fact a loaded `sanitizers/` rule claimed. Same \
                      surface as `security sources` / `sinks` plus a \
                      sanitizer-tag narrower. Sanitizers tag cleansing \
                      operations (html-escape, shell-escape, url-encode, \
                      constant-time compare) whose presence on a taint \
                      chain attaches sanitizer evidence to the finding. \
                      Use this to audit where the pack considers taint \
                      already cleansed without running full flows."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every sanitizer hit in the workspace\n  \
                      $ bonsai-ninja security ./src sanitizers\n  \
                      \n  \
                      # HTML-escape sanitizers only\n  \
                      $ bonsai-ninja security ./src sanitizers --tag html-encode\n  \
                      \n  \
                      # One rule id — e.g. every `shlex.quote` call site\n  \
                      $ bonsai-ninja security ./src sanitizers --rule python.sanitizer.shlex_quote")
    )]
    Sanitizers {
        /// Directory containing the `langs/<lang>/…` rulepack tree.
        /// Lookup when omitted: `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
        /// Filter to rules whose id matches this exact string.
        #[arg(long)]
        rule: Option<String>,
        /// Filter to rules whose id matches this regex.
        #[arg(long)]
        rule_regex: Option<String>,
        /// Tag narrower — sanitizer tag (e.g. `html-encode`,
        /// `shell-escape`, `url-encode`, `constant-time`,
        /// `sql-parameter`, `path-sanitize`).
        #[arg(long)]
        tag: Option<String>,
        /// Severity-floor filter for sanitizer rules that carry
        /// severity (e.g. `weak-hash` flagged as medium). Same
        /// strict parsing as `sinks --severity`.
        #[arg(long)]
        severity: Option<String>,
        /// Family narrower — matches the rule's tag exactly OR its
        /// canonical family. Mirrors `sinks --category`.
        #[arg(long)]
        category: Option<String>,
        /// File-path include substring (repeatable).
        #[arg(long = "file")]
        files: Vec<String>,
        /// File-path exclude substring (repeatable).
        #[arg(long = "exclude-file")]
        exclude_files: Vec<String>,
        /// Cap on rendered rows (`0` = uncapped).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Token-budget ceiling for text output.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `P:xxxxxxxx` cursor, or
        /// `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Dependency inventory — every package the rulepack mentions whose
    /// imports are actually used in the workspace, with the import-site
    /// locations inlined. Same paginated table surface as `sources` /
    /// `sinks` / `search`.
    #[command(
        long_about = themed_subcommand_long_about("Dependency inventory — every package the rulepack mentions \
                      whose imports are actually used in the workspace, with \
                      import-site locations inlined. Cross-references the \
                      pack's `frameworks` / package metadata against the \
                      workspace's import graph so you can tell at a glance \
                      which flagged libraries you're actually depending on.\n\
                      \n\
                      Same paginated table surface as `security sources` / \
                      `security sinks`."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every flagged package actually imported somewhere\n  \
                      $ bonsai-ninja security ./src deps\n  \
                      \n  \
                      # Only packages whose highest-severity rule is critical\n  \
                      $ bonsai-ninja security ./src deps --severity critical\n  \
                      \n  \
                      # A single package and its import sites\n  \
                      $ bonsai-ninja security ./src deps --framework flask")
    )]
    Deps {
        /// Directory containing the `langs/<lang>/…` rulepack tree.
        /// Lookup when omitted: `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
        /// Filter to a single package / framework key.
        #[arg(long)]
        framework: Option<String>,
        /// Severity-floor filter — keep packages whose highest-
        /// severity rule is at least this level. Accepts exactly one
        /// of `info`, `low`, `medium`, `high`, `critical` (strict —
        /// any other value is rejected so typos can't silently
        /// widen the filter).
        #[arg(long)]
        severity: Option<String>,
        /// File-path include substring (repeatable).
        #[arg(long = "file")]
        files: Vec<String>,
        /// File-path exclude substring (repeatable).
        #[arg(long = "exclude-file")]
        exclude_files: Vec<String>,
        /// Cap on rendered rows (`0` = uncapped).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Token-budget ceiling for text output.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `P:xxxxxxxx` cursor, or
        /// `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output shape — `text` for the rendered table, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Run automatic source→sink taint analysis using every loaded
    /// rule and emit a paginated security report. Mirrors `inspect`
    /// pagination — paging unit is one finding block; the report shows
    /// the source line, the sink line, the chain, and stable ids
    /// (`S:`, `F:`, `G:`).
    #[command(
        name = "taint-analysis",
        long_about = themed_subcommand_long_about("Run automatic source→sink taint analysis using every loaded \
                      rule and emit a paginated security report. The rulepack \
                      is the query: every `sources/` rule is seeded, every \
                      `sinks/` rule is the landing target, and matching \
                      `sanitizers/` rules attach sanitizer evidence along \
                      the way.\n\
                      \n\
                      Architecturally this consumes the same semantic \
                      graph as inspect, trace, source-analysis, export, \
                      and the debug dumps. Patterns identify sources, \
                      sinks, and sanitizers; propagation comes from the \
                      indexed dataflow graph, not from rule-side flow wiring.\n\
                      \n\
                      Mirrors `inspect` pagination — the paging unit is one \
                      finding block; each finding shows the source line, the \
                      sink line, the chain between them, and stable ids \
                      (`S:` for the finding, `F:` for the flow, `G:` for the \
                      flow group)."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # High-severity findings only\n  \
                      $ bonsai-ninja security ./src taint-analysis --severity high\n  \
                      \n  \
                      # Narrow to a single source + sink family\n  \
                      $ bonsai-ninja security ./src taint-analysis --source 'py\\.flask\\.' --sink '^py\\.os\\.system'\n  \
                      \n  \
                      # Remote HTTP / RPC entrypoints only\n  \
                      $ bonsai-ninja security ./src taint-analysis --trust remote --category http-input\n  \
                      \n  \
                      # Tag narrowing (CWE / OWASP family)\n  \
                      $ bonsai-ninja security ./src taint-analysis --tag command-injection\n  \
                      \n  \
                      # JSON for CI / tooling, no row cap\n  \
                      $ bonsai-ninja security ./src taint-analysis --format json --all")
    )]
    TaintAnalysis {
        /// Directory containing the `langs/<lang>/…` rulepack tree.
        /// Lookup when omitted: `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
        /// Bundle of defaults for common review postures. `production`
        /// applies the SKILL.md production exclusion set for common
        /// test, fixture, sample, vendored dependency, build artifact,
        /// generated-code, and language-specific non-production
        /// layouts; severity `high`; trust `remote`; and context
        /// `16k`. Per-flag overrides take precedence — passing
        /// `--severity critical --profile production` keeps
        /// `critical`.
        #[arg(long)]
        profile: Option<String>,
        /// Restrict to source rules whose id matches this regex.
        #[arg(long)]
        source: Option<String>,
        /// Source trust class narrower — `remote`, `local`, `service`,
        /// `ipc`, `database`, `library`, `config`, or `physical`.
        #[arg(long)]
        trust: Option<String>,
        /// Source category narrower. Common values across the
        /// shipped rulepack: `db-input`, `hardware-io`, `http-input`,
        /// `net-input`. The `inferred` pseudo-category matches every
        /// inferred entry-point seed (see `--inferred-sources`).
        #[arg(long)]
        category: Option<String>,
        /// Restrict to sink rules whose id matches this regex.
        #[arg(long)]
        sink: Option<String>,
        /// Severity-floor filter — drops findings whose sink rule is
        /// below this level. Accepts exactly one of `info`, `low`,
        /// `medium`, `high`, `critical` (strict — any other value is
        /// rejected with an error so typos can't silently widen the
        /// filter).
        #[arg(long)]
        severity: Option<String>,
        /// Sink tag narrower. Documented vocabulary:
        /// `access-control`, `address-squatting`, `atom-exhaustion`,
        /// `cache-poisoning`, `code-injection`, `command-injection`,
        /// `cookie-misconfig`, `cors`, `cql-injection`,
        /// `cypher-injection`, `dos`, `env-leak`, `ets-match-dos`,
        /// `external-call`, `file-upload`, `format-string`, `graphql`,
        /// `graphql-injection`, `hash-collision`, `header-injection`,
        /// `host-header`, `information-exposure`,
        /// `insecure-deserialization`, `insecure-temp-file`,
        /// `integer-overflow`, `intent-redirection`, `jndi-injection`,
        /// `jwt`, `ldap-injection`, `lfi`, `log-injection`,
        /// `mass-assignment`, `memory-safety`, `nosql-injection`,
        /// `oauth`, `open-redirect`, `oracle-manipulation`,
        /// `path-traversal`, `prototype-pollution`, `queue-injection`,
        /// `race`, `redos`, `reentrancy`, `signature-replay`,
        /// `smtp-injection`, `sql-injection`, `sqli`,
        /// `state-manipulation`, `ssrf`, `ssti`, `timeout-bypass`,
        /// `timing-attack`, `unchecked-return`, `untrusted-token`,
        /// `weak-auth`, `weak-crypto`, `weak-randomness`, `weak-tls`,
        /// `web-llm`, `xss`, `xxe`, `zip-slip`.
        #[arg(long)]
        tag: Option<String>,
        /// File-path include substring (repeatable). Keep only findings
        /// whose sink site is in one of the given paths.
        #[arg(long = "file")]
        files: Vec<String>,
        /// File-path exclude substring (repeatable). Drop findings
        /// whose sink site is in one of the given paths.
        #[arg(long = "exclude-file")]
        exclude_files: Vec<String>,
        /// Opt in to inferred per-function entry-point sources. By
        /// default `taint-analysis` only seeds taint at sites matched
        /// by a real `sources/*.yml` rule. With `--inferred-sources`,
        /// every unreferenced or framework-decorated function becomes
        /// its own synthetic source — useful for audit-style coverage
        /// when the rulepack is thin, but very noisy on large
        /// codebases. Combine with `--trust local --category inferred`
        /// to view only the synthetic set.
        #[arg(long = "inferred-sources", default_value_t = false)]
        inferred_sources: bool,
        /// Drop findings whose source OR sink lives in a conventional
        /// test path (`test/`, `tests/`, `*_test.go`, `Tests/`, etc.).
        /// Use for "production review" reports — large projects with
        /// strong test suites otherwise inflate the finding list with
        /// test-fixture flows that exercise the production code being
        /// reviewed. Findings carry a `from_test: true` boolean in the
        /// JSON output so consumers can filter without re-parsing
        /// paths.
        #[arg(long = "exclude-tests", default_value_t = false)]
        exclude_tests: bool,
        /// Compatibility flag. Sanitizer rules are evidence over
        /// propagated paths, not propagation blockers, so sanitized
        /// paths are included whenever source-to-sink reachability
        /// exists.
        #[arg(long = "show-sanitized", default_value_t = false)]
        show_sanitized: bool,
        /// Override the interprocedural `(function, seed)` chunk size
        /// for security taint-analysis. Default 512. This affects
        /// scheduling granularity, not result completeness.
        #[arg(long = "taint-budget")]
        taint_budget: Option<u32>,
        /// Override the intraprocedural CFG worklist iteration cap per
        /// function. Default derives from CFG size.
        #[arg(long = "intra-worklist-cap")]
        intra_worklist_cap: Option<u32>,
        /// Keep only findings at or below this flow precision. Values:
        /// `exact`, `narrowed`, `over-approximate`, `unknown`.
        #[arg(long, value_enum)]
        precision: Option<PrecisionFilter>,
        /// High-confidence flow mode. Equivalent to
        /// `--precision narrowed`, keeping exact/narrowed findings and
        /// dropping over-approximate/unknown paths.
        #[arg(long = "strict-flow", default_value_t = false)]
        strict_flow: bool,
        /// Token-budget ceiling for text output. Shorthand `4k` /
        /// `32k` / `128k` / `1m`; `0` / `all` / `uncapped` disables.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `P:xxxxxxxx` cursor, or
        /// `next`.
        #[arg(long)]
        page: Option<String>,
        /// Show every finding unconditionally — no paging, no cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Expand every flow body even when another rendered flow already
        /// printed the same function body.
        #[arg(long = "no-compact", default_value_t = false)]
        no_compact: bool,
        /// Output shape — `text` for the paginated finding report,
        /// `json` for the bonsai-native machine-readable shape, or
        /// `sarif` for SARIF 2.1.0 (GitHub code scanning, IDE
        /// plugins, CVEBench-SAST harness). SARIF results carry
        /// `properties.bonsai` with the original `S:` / `F:` /
        /// `G:` / CWE / status / tainted-args metadata so consumers
        /// that understand bonsai's stable IDs can drill back into
        /// `inspect` and `dump-edges`.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Render downstream taint/call paths starting at every matched
    /// source. No sink rule is required; use this to map entrypoint,
    /// API, service, and handler logic from the rulepack's source
    /// perspective.
    #[command(
        name = "source-analysis",
        long_about = themed_subcommand_long_about("Render downstream taint/call paths starting at every matched \
                      source. This is source-centric exploration, not \
                      source→sink vulnerability reporting: no `sinks/` rule \
                      is required. The command seeds every loaded `sources/` \
                      rule plus inferred entry-point parameters, then follows \
                      resolved user-defined call paths so reviewers can map \
                      application, service, API, queue, cloud, CLI, IPC, \
                      database, and hardware entrypoint logic.\n\
                      \n\
                      Use `security taint-analysis` when you need \
                      source→sink findings. Use `security source-analysis` when \
                      you need an attack-surface / entrypoint flow map."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Map every source-driven path in the workspace\n  \
                      $ bonsai-ninja security ./src source-analysis\n  \
                      \n  \
                      # Remote entrypoints only\n  \
                      $ bonsai-ninja security ./src source-analysis --trust remote\n  \
                      \n  \
                      # One source category only\n  \
                      $ bonsai-ninja security ./src source-analysis --category inferred\n  \
                      \n  \
                      # JSON for tooling\n  \
                      $ bonsai-ninja security ./src source-analysis --format json --all")
    )]
    SourceAnalysis {
        /// Directory containing the `langs/<lang>/…` rulepack tree.
        /// Lookup when omitted: `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
        /// Bundle of defaults for common postures. `production`
        /// applies the SKILL.md production exclusion set for common
        /// test, fixture, sample, vendored dependency, build artifact,
        /// generated-code, and language-specific non-production
        /// layouts; trust `remote`; and context `16k`. Per-flag
        /// overrides take precedence.
        #[arg(long)]
        profile: Option<String>,
        /// Restrict to source rules whose id matches this regex.
        #[arg(long)]
        source: Option<String>,
        /// Trust class narrower — `remote`, `local`, `service`, `ipc`,
        /// `database`, `library`, `config`, or `physical`.
        #[arg(long)]
        trust: Option<String>,
        /// Source tag narrower. Documented vocabulary:
        /// `block-context`, `browser-input`, `calldata`,
        /// `caller-identity`, `caller-input`, `caller-value`,
        /// `cli-input`, `clipboard-input`, `cloud-event`, `cloud-input`,
        /// `config-input`, `db-input`, `db-row`, `deep-link`,
        /// `deprecated-auth`, `env-input`, `event-input`,
        /// `graphql-input`, `http-input`, `hw-input`, `ipc-input`,
        /// `ipc-message`, `local-input`, `net-input`, `network-input`,
        /// `network-response`, `oracle-input`, `push-input`,
        /// `push-message`, `queue-input`, `queue-message`, `rpc-input`,
        /// `socket-input`, `token-input`, `ui-input`, `ws-input`.
        #[arg(long)]
        tag: Option<String>,
        /// Source category narrower. Common values across the
        /// shipped rulepack: `db-input`, `hardware-io`, `http-input`,
        /// `net-input`. The `inferred` pseudo-category matches every
        /// inferred entry-point seed (see `--inferred-sources`).
        #[arg(long)]
        category: Option<String>,
        /// File-path include substring (repeatable). Keep only source
        /// seeds in files whose path contains any of the given substrings.
        #[arg(long = "file")]
        files: Vec<String>,
        /// File-path exclude substring (repeatable).
        #[arg(long = "exclude-file")]
        exclude_files: Vec<String>,
        /// Opt in to inferred per-function entry-point sources. Off by
        /// default — synthetic per-function entries can produce 100+
        /// flows on a 30-function codebase and drown the real rule-
        /// matched seeds. Pass `--inferred-sources` to include them
        /// (combine with `--category inferred` to view only the
        /// synthetic set).
        #[arg(long = "inferred-sources", default_value_t = false)]
        inferred_sources: bool,
        /// Token-budget ceiling for text output. Shorthand `4k` /
        /// `32k` / `128k` / `1m`; `0` / `all` / `uncapped` disables.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `P:xxxxxxxx` cursor, or
        /// `next`.
        #[arg(long)]
        page: Option<String>,
        /// Show every source flow unconditionally — no paging, no cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Expand every flow body even when another rendered flow already
        /// printed the same function body.
        #[arg(long = "no-compact", default_value_t = false)]
        no_compact: bool,
        /// Output shape — `text` for the paginated source-flow report,
        /// `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },

    /// Inspect the loaded rulepack itself (no workspace scan). Lists
    /// every rule grouped by language and category, prints per-lang /
    /// per-category counts, and surfaces gaps (categories missing,
    /// canonical files missing, sparse families). Use this to audit
    /// your own pack and find what to expand next.
    #[command(
        long_about = themed_subcommand_long_about("Inspect the loaded rulepack itself — no workspace scan. Lists \
                      every rule grouped by language and category, prints \
                      per-lang / per-category counts, and (with `--audit`) \
                      surfaces gaps: missing categories, missing canonical \
                      files, sparse rule families.\n\
                      \n\
                      Use this when curating / growing your own pack — it's \
                      the fastest way to see what the pack actually covers \
                      today and where to expand next."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Every rule, grouped by lang / category\n  \
                      $ bonsai-ninja security ./src pack\n  \
                      \n  \
                      # Audit mode — coverage matrix + gap warnings\n  \
                      $ bonsai-ninja security ./src pack --audit\n  \
                      \n  \
                      # One language, one family\n  \
                      $ bonsai-ninja security ./src pack --lang python --category sqli\n  \
                      \n  \
                      # Only sinks at critical severity\n  \
                      $ bonsai-ninja security ./src pack --kind sink --severity critical")
    )]
    Pack {
        /// Directory containing the `langs/<lang>/…` rulepack tree.
        /// Lookup when omitted: `BONSAI_RULES_DIR` env var, then
        /// `<workspace>/security-patterns/`, then
        /// `<workspace>/../security-patterns/`, then
        /// `./security-patterns/` (cwd-relative).
        #[arg(long, value_name = "DIR", env = "BONSAI_RULES_DIR")]
        rules_dir: Option<PathBuf>,
        /// Filter to a single language (`python`, `go`, …).
        #[arg(long)]
        lang: Option<String>,
        /// Filter to a single category / family (`cmdi`, `sqli`,
        /// `deserialization`, …). Matches the rule's `tag` or the
        /// trailing segment of its id.
        #[arg(long)]
        category: Option<String>,
        /// Filter by rule kind (`source`, `sink`, `sanitizer`).
        #[arg(long)]
        kind: Option<String>,
        /// Severity-floor filter — drops rules below this level.
        /// Accepts exactly one of `info`, `low`, `medium`, `high`,
        /// `critical` (strict — any other value is rejected so
        /// typos can't silently widen the filter).
        #[arg(long)]
        severity: Option<String>,
        /// Audit mode — print a per-lang / per-category coverage
        /// matrix and warn about thin or missing families.
        #[arg(long, default_value_t = false)]
        audit: bool,
        /// Tree mode — walk `lang / kind / family` and list every
        /// rule id grouped by its on-disk file (`security-patterns/
        /// langs/<lang>/<kind>s/<family>.yml`). Use for a quick
        /// file-level survey of what the pack actually contains.
        #[arg(long, default_value_t = false)]
        tree: bool,
        /// Validate rule schema, required metadata, match_examples,
        /// and enabled-rule example collisions. Unknown YAML fields
        /// are rejected before this mode runs by the rulepack loader.
        #[arg(long, default_value_t = false)]
        validate: bool,
        /// Token-budget ceiling for text output. Shorthand `4k` etc.
        #[arg(long)]
        context: Option<String>,
        /// Page to render — 1-based number, `P:xxxxxxxx` cursor, or
        /// `next`.
        #[arg(long)]
        page: Option<String>,
        /// Emit every row, no paging or context cap.
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Cap on rendered rows (`0` = uncapped). JSON is always uncapped.
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Output shape — `text` for the rule listing / audit matrix, `json` for machine-readable output.
        #[arg(long, value_enum, default_value_t = BrowseFormat::Text)]
        format: BrowseFormat,
    },
}

#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
pub(crate) enum CacheAction {
    /// Print the in-process cache configuration (per-cache caps and
    /// the on-disk artifact path that `clear` would touch). Shows
    /// the dataflow sidecar's location + size + entry count when
    /// present.
    #[command(
        long_about = themed_subcommand_long_about("Print the in-process cache configuration (per-cache caps and \
                      the on-disk artifact path that `cache clear` would \
                      touch). Reports the dataflow sidecar's location, size, \
                      and entry count when present so you can tell whether \
                      the persisted taint graph is warm."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Config only (no workspace context)\n  \
                      $ bonsai-ninja cache stats\n  \
                      \n  \
                      # Include the on-disk sidecar for a specific workspace\n  \
                      $ bonsai-ninja cache stats ./src")
    )]
    Stats {
        /// Optional workspace root to report the on-disk cache path
        /// against. Defaults to the current directory.
        workspace: Option<PathBuf>,
    },
    /// Remove on-disk cache artifacts under `<workspace>/.bonsai/`.
    /// Specifically deletes `dataflow.v2.bin` (the persisted
    /// workspace taint graph) and any other sidecar files written
    /// by the engine. In-process caches don't need clearing — they
    /// drop at process exit; use `--no-cache` to bypass them within
    /// a single command.
    #[command(
        long_about = themed_subcommand_long_about("Remove on-disk cache artifacts under `<workspace>/.bonsai/`. \
                      Specifically deletes `dataflow.v2.bin` (the persisted \
                      workspace taint graph) and any other sidecar files \
                      written by the engine.\n\
                      \n\
                      In-process caches don't need clearing — they drop at \
                      process exit; use `--no-cache` / `BONSAI_NO_CACHE=1` to \
                      bypass them within a single command."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Wipe every sidecar under .bonsai/\n  \
                      $ bonsai-ninja cache clear ./src\n  \
                      \n  \
                      # Keep other sidecars, only drop the taint cache\n  \
                      $ bonsai-ninja cache clear ./src --dataflow-only")
    )]
    Clear {
        /// Workspace root whose `.bonsai/` cache dir should be removed.
        /// Defaults to the current directory.
        workspace: Option<PathBuf>,
        /// Only clear the dataflow sidecar (`dataflow.v2.bin`),
        /// leaving other `.bonsai/` contents intact. Useful when
        /// you want to force a taint-graph recompute without
        /// touching unrelated sidecars.
        #[arg(long)]
        dataflow_only: bool,
    },
    /// Remove the persisted dataflow sidecar and rebuild it from
    /// scratch. Equivalent to `cache clear --dataflow-only` followed
    /// by a workspace open (which runs `prewarm_all` + writes the
    /// sidecar back). Use after bulk edits, after upgrading to a
    /// new cache version, or when you suspect the cache is stale.
    #[command(
        long_about = themed_subcommand_long_about("Remove the persisted dataflow sidecar and rebuild it from \
                      scratch. Equivalent to `cache clear --dataflow-only` \
                      followed by a workspace open (which runs `prewarm_all` \
                      + writes the sidecar back).\n\
                      \n\
                      Use after bulk edits, after upgrading to a new cache \
                      version, or when you suspect the persisted taint graph \
                      has drifted from the source."),
        after_help = themed_subcommand_after_help("EXAMPLES\n\n  \
                      # Full rebuild of the taint sidecar\n  \
                      $ bonsai-ninja cache rebuild ./src")
    )]
    Rebuild {
        /// Workspace root. Defaults to the current directory.
        workspace: Option<PathBuf>,
    },
}
