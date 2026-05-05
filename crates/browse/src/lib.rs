//! Browse + dump command data layer.
//!
//! Every CLI browse command (`defs`, `calls`, `imports`, `vars`,
//! `strings`, `args`, `classes`, `refs`, `search`) and dump command
//! (`dump-hir`, `dump-cfg`, `dump-callgraph`, `dump-edges`,
//! `dump-resolve`, `dump-taint`, `dump-ast`) gets its data through
//! a function exposed here. The CLI binary is a renderer over this
//! crate; SDK consumers call the same functions to get the same
//! structured data without going through the CLI.
//!
//! Each command's filter struct + output struct is part of the
//! public surface, with stable field names that match the command's
//! own JSON output. Filters are `Copy`-able borrowed bundles so
//! callers can re-use one across many invocations.

// Submodules: external surface is the re-exports below. `refs` and
// `strings` stay `pub mod` because the SDK reaches into them
// (`bonsai_browse::refs::read_snippet`, `bonsai_browse::strings::
// enclosing_fn_for_file_line`); everything else is internal.
pub(crate) mod args;
pub(crate) mod ast;
pub(crate) mod calls;
pub(crate) mod classes;
pub(crate) mod comments;
pub(crate) mod common;
pub(crate) mod defs;
pub(crate) mod dumps;
pub(crate) mod edges;
pub(crate) mod flows;
pub(crate) mod graph_export;
pub(crate) mod imports;
pub(crate) mod native_export;
pub mod refs;
pub(crate) mod resolve;
pub(crate) mod search;
pub mod strings;
pub(crate) mod taint;
pub(crate) mod vars;

pub use args::{args, ArgOut, ArgsFilters};
pub use ast::{compute_node_id, dump_ast, AstFileDump, AstFilters, AstNode, AstOutcome};
pub use calls::{calls, CallOut, CallsFilters};
pub use classes::{classes, ClassOut, ClassesFilters};
pub use comments::{comments, CommentOut, CommentsFilters};
pub use common::{format_span, make_name_filter, Locator, NameFilter, Span};
pub use defs::{defs, DefOut, DefsFilters};
pub use dumps::{callgraph_summary, dump_callgraph, dump_cfg, dump_hir, CallgraphRow, HirDump};
pub use edges::{compute_edge_id, dump_edges, EdgeRecord, EdgesFilters, PrecisionClass};
pub use flows::FlowAnnotator;
pub use graph_export::{
    graph_projection, render_cypher, render_graph_export, render_graphml, render_networkx_json, GraphEdge,
    GraphExportFormat, GraphNode, GraphProjection,
};
pub use imports::{imports, ImportOut, ImportsFilters};
pub use native_export::{native_export_json, render_native_export_json};
pub use refs::{refs, RefOut, RefsFilters};
pub use resolve::{
    compute_candidate_id, dump_resolve, ResolveCandidate, ResolveFilters, ResolveOutcome, ResolveTrace,
};
pub use search::{search, SearchFilters, SearchHit};
pub use strings::{strings, StringOut, StringsFilters};
pub use taint::{
    compute_taint_id, dump_taint, precision_display, TaintFilters, TaintOutcome, TaintRecord, TaintReport,
    TaintedArgRecord,
};
pub use vars::{vars, VarOut, VarsFilters};
