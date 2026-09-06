//! `tree` — workspace navigation surface (CLI renderer).
//!
//! Builds and renders the workspace tree as text or JSON. Text mode draws
//! a `tree(1)`-style hierarchy with `├──` / `└──` / `│` connectors, themed via
//! the global [`crate::ui::Ui`] palette so it matches every other command. By
//! default the rendered files carry definition counts, imports, and cross-file
//! call edges projected from the persisted structural index; `--files-only`
//! renders the plain listing. The command never builds semantic graphs or
//! runs security analysis; findings belong to `security taint-analysis`.

use anyhow::Result;
use bonsai_common::{
    filter_looks_like_absolute_path, is_bonsai_case_probe_path, normalize_path_for_filter,
    normalized_path_contains,
};
use serde::Serialize;
use std::path::{Path, PathBuf};

use super::{emit_json_value_paged_cached, is_internal_workspace_entry_name};
use crate::args::BrowseFormat;
use crate::cli_println;
use crate::footer::render_paging_footer;
use crate::paging::{self, FormatClass};
use crate::progress;
use crate::ui;

pub(crate) struct TreeArgs<'a> {
    pub(crate) workspace: &'a Path,
    pub(crate) max_depth: Option<usize>,
    pub(crate) file: Option<&'a str>,
    pub(crate) exclude_file: &'a [String],
    pub(crate) limit: usize,
    pub(crate) context: Option<&'a str>,
    pub(crate) page: Option<&'a str>,
    pub(crate) all: bool,
    pub(crate) format: BrowseFormat,
    /// Skip compiler facts: a plain filesystem listing.
    pub(crate) files_only: bool,
}

#[derive(Serialize)]
struct StructuralTreeJson<'a> {
    analysis_complete: bool,
    analysis_incomplete_reasons: &'a [String],
    roots: Vec<StructuralTreeNodeJson<'a>>,
    summary: &'a StructuralTreeSummary,
}

struct StructuralTreeOut {
    analysis_complete: bool,
    analysis_incomplete_reasons: Vec<String>,
    roots: Vec<StructuralTreeNode>,
    summary: StructuralTreeSummary,
}

#[derive(Serialize)]
struct StructuralTreeSummary {
    #[serde(rename = "total_files")]
    files: usize,
    #[serde(rename = "total_files_scanned")]
    files_scanned: usize,
    #[serde(rename = "total_dirs")]
    dirs: usize,
    /// Declarations across every rendered file (compiler facts attached).
    #[serde(default)]
    total_decls: usize,
    /// Resolved cross-file call edges leaving rendered files.
    #[serde(default)]
    total_cross_file_edges: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StructuralNodeKind {
    Dir,
    File,
}

#[derive(Serialize)]
struct StructuralLocator {
    file: String,
    line: usize,
    column: usize,
}

struct StructuralTreeNode {
    kind: StructuralNodeKind,
    name: String,
    locator: StructuralLocator,
    depth: usize,
    children: Vec<StructuralTreeNode>,
    children_dropped: usize,
    /// Compiler facts for a file: declarations, resolved imports, and
    /// cross-file call edges in both directions.
    connections: Option<bonsai_sdk::FileConnections>,
    /// Aggregates for a directory: rendered files and declarations below it.
    files_below: usize,
    decls_below: usize,
}

#[derive(Serialize)]
struct StructuralTreeNodeJson<'a> {
    kind: StructuralNodeKind,
    name: &'a str,
    locator: &'a StructuralLocator,
    depth: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<StructuralTreeNodeJson<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<StructuralTreeTruncation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connections: Option<&'a bonsai_sdk::FileConnections>,
    #[serde(skip_serializing_if = "Option::is_none")]
    files_below: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decls_below: Option<usize>,
}

#[derive(Serialize)]
struct StructuralTreeTruncation {
    children_dropped: usize,
}

impl<'a> From<&'a StructuralTreeOut> for StructuralTreeJson<'a> {
    fn from(out: &'a StructuralTreeOut) -> Self {
        Self {
            analysis_complete: out.analysis_complete,
            analysis_incomplete_reasons: &out.analysis_incomplete_reasons,
            roots: out.roots.iter().map(StructuralTreeNodeJson::from).collect(),
            summary: &out.summary,
        }
    }
}

impl<'a> From<&'a StructuralTreeNode> for StructuralTreeNodeJson<'a> {
    fn from(node: &'a StructuralTreeNode) -> Self {
        Self {
            kind: node.kind,
            name: &node.name,
            locator: &node.locator,
            depth: node.depth,
            children: node.children.iter().map(Self::from).collect(),
            truncated: (node.children_dropped > 0).then_some(StructuralTreeTruncation {
                children_dropped: node.children_dropped,
            }),
            connections: node.connections.as_ref(),
            files_below: (node.kind == StructuralNodeKind::Dir).then_some(node.files_below),
            decls_below: (node.kind == StructuralNodeKind::Dir).then_some(node.decls_below),
        }
    }
}

pub(crate) fn cmd_tree(args: TreeArgs<'_>) -> Result<()> {
    let filters_hash = tree_filters_hash(&args);
    let stage = progress::ScopedSpinner::new("scanning filesystem tree");
    let mut out = build_fast_filesystem_tree(&args)?;
    stage.finish();
    // The open guard renders the workspace footer when dropped; keep it
    // alive until the tree itself has been rendered.
    let _workspace_footer = if args.files_only {
        None
    } else {
        attach_tree_connections(&args, &mut out)?
    };

    match args.format {
        BrowseFormat::Json => {
            let cfg = paging::config_from_raw(args.context, args.page, args.all, FormatClass::Programmatic)
                .map_err(|e| anyhow::anyhow!(e))?;
            emit_json_value_paged_cached(
                args.workspace,
                &StructuralTreeJson::from(&out),
                &cfg,
                "tree",
                filters_hash,
            )?;
        }
        BrowseFormat::Text => {
            render_text_paged(&out, args.context, args.page, args.all, filters_hash)?;
        }
    }
    Ok(())
}

struct FastTreeBuild {
    root: PathBuf,
    max_depth: usize,
    child_limit: usize,
    file_filter: Option<String>,
    exclude_files: Vec<String>,
    files_scanned: usize,
    files_rendered: usize,
    dirs_rendered: usize,
    depth_truncated: usize,
    children_dropped: usize,
}

fn build_fast_filesystem_tree(args: &TreeArgs<'_>) -> Result<StructuralTreeOut> {
    let root = args
        .workspace
        .canonicalize()
        .unwrap_or_else(|_| args.workspace.to_path_buf());
    let mut build = FastTreeBuild {
        root: root.clone(),
        max_depth: if args.file.is_some() {
            usize::MAX
        } else {
            args.max_depth.unwrap_or(usize::MAX)
        },
        child_limit: if args.all || args.limit == 0 {
            usize::MAX
        } else {
            args.limit
        },
        file_filter: args.file.map(str::to_string),
        exclude_files: args.exclude_file.to_vec(),
        files_scanned: 0,
        files_rendered: 0,
        dirs_rendered: 0,
        depth_truncated: 0,
        children_dropped: 0,
    };
    let root_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_else(|| root.to_str().unwrap_or("."))
        .to_string();
    let root_node = build_fast_dir_node(&root, root_name, 0, &mut build)?;
    let mut reasons = Vec::new();
    if build.depth_truncated > 0 {
        reasons.push(format!(
            "tree-files-truncated:depth_limited_nodes={}",
            build.depth_truncated
        ));
    }
    if build.children_dropped > 0 {
        reasons.push(format!(
            "tree-children-truncated:children_dropped={}",
            build.children_dropped
        ));
    }
    let analysis_complete = reasons.is_empty();
    Ok(StructuralTreeOut {
        analysis_complete,
        analysis_incomplete_reasons: reasons,
        roots: vec![root_node],
        summary: StructuralTreeSummary {
            files: build.files_rendered,
            files_scanned: build.files_scanned,
            dirs: build.dirs_rendered,
            total_decls: 0,
            total_cross_file_edges: 0,
        },
    })
}

/// Above this many files a cold `tree` (no persisted callgraph yet) stays a
/// filesystem listing and reports the gap; `index --semantic` publishes the
/// partitioned callgraph that makes connections cheap on every later run.
const TREE_COMPLETE_OPEN_FILE_LIMIT: usize = 5_000;

/// Attach compiler facts to every file node: declarations, imports resolved
/// to workspace files, and cross-file call edges. One workspace open, one
/// module-map projection; nodes are joined by workspace-relative path.
fn attach_tree_connections(
    args: &TreeArgs<'_>,
    out: &mut StructuralTreeOut,
) -> Result<Option<crate::footer::WorkspaceFooter>> {
    let large = super::workspace_file_count_exceeds(args.workspace, TREE_COMPLETE_OPEN_FILE_LIMIT);
    let (project, footer) = super::open_project_index_only(args.workspace)?;
    let ws = project.workspace();
    if large && !ws.has_persisted_callgraph() {
        out.analysis_incomplete_reasons.push(
            "tree-connections-unavailable: large workspace without a persisted callgraph; run `bonsai-ninja index <workspace> --semantic` once"
                .to_string(),
        );
        out.analysis_complete = false;
        return Ok(Some(footer));
    }
    let stage = progress::ScopedSpinner::new("projecting module connections");
    // Only the files this tree renders need their connections; a depth or
    // child limit must not turn into a whole-workspace projection.
    fn rendered_files(node: &StructuralTreeNode, out: &mut Vec<String>) {
        match node.kind {
            StructuralNodeKind::File => out.push(node.locator.file.clone()),
            StructuralNodeKind::Dir => {
                for child in &node.children {
                    rendered_files(child, out);
                }
            }
        }
    }
    let mut rendered = Vec::new();
    for root in &out.roots {
        rendered_files(root, &mut rendered);
    }
    let rendered_ids: Vec<bonsai_common::FileId> = rendered
        .iter()
        .filter_map(|file| bonsai_sdk::workspace_file_id(ws, file))
        .collect();
    let mut by_path: std::collections::HashMap<String, bonsai_sdk::FileConnections> =
        if rendered_ids.is_empty() {
            std::collections::HashMap::new()
        } else {
            bonsai_sdk::file_connections(ws, &rendered_ids)
                .into_iter()
                .map(|facts| (normalize_path_for_filter(&facts.file), facts))
                .collect()
        };
    stage.finish();
    fn attach(
        node: &mut StructuralTreeNode,
        by_path: &mut std::collections::HashMap<String, bonsai_sdk::FileConnections>,
    ) -> (usize, usize, usize) {
        match node.kind {
            StructuralNodeKind::File => {
                let facts = by_path.remove(&normalize_path_for_filter(&node.locator.file));
                let decls = facts.as_ref().map_or(0, |facts| named_decl_counts(facts).0);
                let edges = facts
                    .as_ref()
                    .map_or(0, bonsai_sdk::FileConnections::calls_out_count);
                node.connections = facts;
                (1, decls, edges)
            }
            StructuralNodeKind::Dir => {
                let mut totals = (0, 0, 0);
                for child in &mut node.children {
                    let (files, decls, edges) = attach(child, by_path);
                    totals.0 += files;
                    totals.1 += decls;
                    totals.2 += edges;
                }
                node.files_below = totals.0;
                node.decls_below = totals.1;
                totals
            }
        }
    }
    let mut totals = (0, 0, 0);
    for root in &mut out.roots {
        let (files, decls, edges) = attach(root, &mut by_path);
        totals.0 += files;
        totals.1 += decls;
        totals.2 += edges;
    }
    out.summary.total_decls = totals.1;
    out.summary.total_cross_file_edges = totals.2;
    Ok(Some(footer))
}

fn build_fast_dir_node(
    path: &Path,
    name: String,
    depth: usize,
    build: &mut FastTreeBuild,
) -> Result<StructuralTreeNode> {
    build.dirs_rendered += 1;
    let mut node = empty_tree_node(StructuralNodeKind::Dir, name, path, depth, &build.root);
    if depth >= build.max_depth {
        let dropped = visible_child_count(path, build)?;
        if dropped > 0 {
            node.children_dropped = dropped;
            build.depth_truncated += dropped;
        }
        return Ok(node);
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(path)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|entry_path| !fast_tree_should_skip(entry_path, build))
        .collect();
    entries.sort();
    let mut children = Vec::new();
    for entry_path in entries {
        let Some(name) = entry_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let Some(kind) = fast_tree_entry_kind(&entry_path) else {
            continue;
        };
        if kind == StructuralNodeKind::Dir {
            if children.len() >= build.child_limit {
                node.children_dropped += 1;
                build.children_dropped += 1;
                continue;
            }
            let child = build_fast_dir_node(&entry_path, name, depth + 1, build)?;
            if build.file_filter.is_none() || !child.children.is_empty() {
                children.push(child);
            }
        } else {
            if !fast_tree_file_matches(&entry_path, build) {
                continue;
            }
            build.files_scanned += 1;
            if children.len() >= build.child_limit {
                node.children_dropped += 1;
                build.children_dropped += 1;
                continue;
            }
            build.files_rendered += 1;
            children.push(empty_tree_node(
                StructuralNodeKind::File,
                name,
                &entry_path,
                depth + 1,
                &build.root,
            ));
        }
    }
    node.children = children;
    Ok(node)
}

fn fast_tree_entry_kind(path: &Path) -> Option<StructuralNodeKind> {
    let file_type = std::fs::symlink_metadata(path).ok()?.file_type();
    if file_type.is_dir() {
        Some(StructuralNodeKind::Dir)
    } else if file_type.is_file() || file_type.is_symlink() {
        // Render directory symlinks as leaf entries. Following them can escape
        // the workspace or recurse forever through a cycle.
        Some(StructuralNodeKind::File)
    } else {
        None
    }
}

fn empty_tree_node(
    kind: StructuralNodeKind,
    name: String,
    path: &Path,
    depth: usize,
    root: &Path,
) -> StructuralTreeNode {
    let relative = path
        .strip_prefix(root)
        .map(|relative| normalize_path_for_filter(&relative.to_string_lossy()))
        .unwrap_or_else(|_| normalize_path_for_filter(&path.to_string_lossy()));
    StructuralTreeNode {
        kind,
        name,
        locator: StructuralLocator {
            file: if relative.is_empty() {
                ".".to_string()
            } else {
                relative
            },
            line: 1,
            column: 1,
        },
        depth,
        children: Vec::new(),
        children_dropped: 0,
        connections: None,
        files_below: 0,
        decls_below: 0,
    }
}

fn visible_child_count(path: &Path, build: &FastTreeBuild) -> Result<usize> {
    let mut count = 0usize;
    for entry in std::fs::read_dir(path)?.flatten() {
        let entry_path = entry.path();
        if fast_tree_should_skip(&entry_path, build) {
            continue;
        }
        match fast_tree_entry_kind(&entry_path) {
            Some(StructuralNodeKind::Dir) => count += 1,
            Some(StructuralNodeKind::File) if fast_tree_file_matches(&entry_path, build) => count += 1,
            _ => {}
        }
    }
    Ok(count)
}

fn fast_tree_should_skip(path: &Path, build: &FastTreeBuild) -> bool {
    if crate::output::is_pending_output_path(path) {
        return true;
    }
    if is_bonsai_case_probe_path(path) {
        return true;
    }
    if build
        .exclude_files
        .iter()
        .any(|needle| fast_tree_path_matches_filter(&build.root, path, needle))
    {
        return true;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_internal_workspace_entry_name)
}

fn fast_tree_file_matches(path: &Path, build: &FastTreeBuild) -> bool {
    build
        .file_filter
        .as_deref()
        .is_none_or(|needle| fast_tree_path_matches_filter(&build.root, path, needle))
}

fn fast_tree_path_matches_filter(root: &Path, path: &Path, filter: &str) -> bool {
    let relative = path
        .strip_prefix(root)
        .map(|relative| normalize_path_for_filter(&relative.to_string_lossy()))
        .unwrap_or_else(|_| normalize_path_for_filter(&path.to_string_lossy()));
    if normalized_path_contains(&relative, filter) {
        return true;
    }
    filter_looks_like_absolute_path(filter)
        && normalized_path_contains(&normalize_path_for_filter(&path.to_string_lossy()), filter)
}

fn tree_filters_hash(args: &TreeArgs<'_>) -> u64 {
    let max_depth = args.max_depth.map(|n| n.to_string()).unwrap_or_default();
    let exclude_file = args.exclude_file.join("\0");
    let limit = args.limit.to_string();
    paging::hash_filters(&[
        ("max_depth", &max_depth),
        ("file", args.file.unwrap_or("")),
        ("exclude_file", &exclude_file),
        ("limit", &limit),
        ("files_only", if args.files_only { "1" } else { "0" }),
    ])
}

fn render_text_paged(
    out: &StructuralTreeOut,
    context: Option<&str>,
    page: Option<&str>,
    all: bool,
    filters_hash: u64,
) -> Result<()> {
    let rows = tree_text_rows(out);
    let cfg =
        paging::config_from_raw(context, page, all, FormatClass::Text).map_err(|e| anyhow::anyhow!(e))?;
    let (page_rows, info) = paging::paginate(&rows, &cfg, "tree", filters_hash, TreeTextRow::cost)?;
    for row in page_rows {
        cli_println!("{}", row.render());
    }
    render_paging_footer(&info, "bonsai-ninja tree <workspace>");
    Ok(())
}

#[derive(Clone)]
enum TreeTextRow<'a> {
    Header {
        files: usize,
        files_scanned: usize,
        dirs: usize,
        decls: usize,
        cross_file_edges: usize,
        partial: bool,
    },
    Incomplete(&'a [String]),
    RerunHint,
    Blank,
    Node {
        node: &'a StructuralTreeNode,
        prefix: String,
        is_last: bool,
    },
    /// A file's workspace links, aligned under its row.
    Link {
        prefix: String,
        text: String,
    },
}

impl TreeTextRow<'_> {
    fn cost(&self) -> u64 {
        match self {
            Self::Header { .. } => 192,
            Self::Incomplete(reasons) => reasons.iter().map(String::len).sum::<usize>() as u64 + 192,
            Self::RerunHint => 192,
            Self::Blank => 32,
            Self::Node { node, prefix, .. } => {
                (prefix.len() + node.name.len()) as u64 + 128 + connection_suffix_cost(node)
            }
            Self::Link { prefix, text } => (prefix.len() + text.len()) as u64 + 32,
        }
    }

    fn render(&self) -> String {
        let u = ui();
        match self {
            Self::Header {
                files,
                files_scanned,
                dirs,
                decls,
                cross_file_edges,
                partial,
            } => {
                let file_chip = if files_scanned > files {
                    format!(
                        "{} file{} ({} scanned)",
                        files,
                        if *files == 1 { "" } else { "s" },
                        files_scanned
                    )
                } else {
                    format!("{} file{}", files, if *files == 1 { "" } else { "s" })
                };
                let facts = if *decls > 0 || *cross_file_edges > 0 {
                    format!(" · {decls} fn · {cross_file_edges} cross-file call edge(s)")
                } else {
                    String::new()
                };
                let scope = if *partial { " · partial view" } else { "" };
                u.heading(&format!(
                    "tree — {} · {} dir{}{facts}{scope}",
                    file_chip,
                    dirs,
                    if *dirs == 1 { "" } else { "s" },
                ))
            }
            Self::Incomplete(reasons) => {
                let reasons = if reasons.is_empty() {
                    "analysis-incomplete".to_string()
                } else {
                    reasons.join("; ")
                };
                format!("{} {}", u.warn("tree view incomplete:"), u.dim(&reasons))
            }
            Self::RerunHint => {
                u.dim("rerun with --all and avoid restrictive --max-depth when you need every node")
            }
            Self::Blank => String::new(),
            Self::Node {
                node,
                prefix,
                is_last,
            } => {
                let connector = if *is_last { "└── " } else { "├── " };
                let name = match node.kind {
                    StructuralNodeKind::Dir => u.kind(&format!("{}/", node.name)),
                    StructuralNodeKind::File => u.name(&node.name),
                };
                let suffix = connection_suffix(node);
                if suffix.is_empty() {
                    format!("{prefix}{}{}", u.dim(connector), name)
                } else {
                    format!("{prefix}{}{}  {}", u.dim(connector), name, u.dim(&suffix))
                }
            }
            Self::Link { prefix, text } => format!("{prefix}{}", u.dim(text)),
        }
    }
}

/// Named callables and types a file declares; synthesized module bodies
/// and lambdas are real compiler callables but noise in a module map.
fn named_decl_counts(facts: &bonsai_sdk::FileConnections) -> (usize, usize) {
    let mut callables = 0;
    let mut types = 0;
    for decl in &facts.decls {
        if decl.name == "__module__" || decl.name.starts_with('<') {
            continue;
        }
        match decl.kind.as_str() {
            "function" | "method" | "constructor" => callables += 1,
            "class" | "struct" | "interface" | "enum" | "trait" => types += 1,
            _ => {}
        }
    }
    (callables, types)
}

/// Short language tag for a file row.
fn language_tag(language: &str) -> &str {
    // The adapter owns the language-to-extension vocabulary. Reuse that
    // registration instead of duplicating a language-id table in the CLI.
    crate::syntax_highlight::extension_for_language(language).unwrap_or(language)
}

/// One-line compiler facts for a node: a directory's file/callable totals; a
/// file's language, named callable/type counts, and external import count.
fn connection_suffix(node: &StructuralTreeNode) -> String {
    match node.kind {
        StructuralNodeKind::Dir => {
            if node.files_below == 0 && node.decls_below == 0 {
                return String::new();
            }
            format!("{} files · {} fn", node.files_below, node.decls_below)
        }
        StructuralNodeKind::File => {
            let Some(facts) = node.connections.as_ref() else {
                return String::new();
            };
            let mut parts: Vec<String> = Vec::new();
            if let Some(language) = facts.language.as_deref() {
                parts.push(language_tag(language).to_string());
            }
            let (callables, types) = named_decl_counts(facts);
            if callables > 0 {
                parts.push(format!("{callables} fn"));
            }
            if types > 0 {
                parts.push(format!("{types} type"));
            }
            let external = facts
                .imports
                .iter()
                .filter(|import| import.resolved_files.is_empty())
                .count();
            if external > 0 {
                parts.push(format!("{external} ext"));
            }
            parts.join(" · ")
        }
    }
}

/// Workspace links of a file, one line each: `→` the files it imports or
/// calls into, `←` the files that call into it.
fn connection_rows(node: &StructuralTreeNode) -> Vec<String> {
    let Some(facts) = node.connections.as_ref() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    let mut uses: Vec<&str> = Vec::new();
    for import in &facts.imports {
        for file in &import.resolved_files {
            if !uses.contains(&file.as_str()) {
                uses.push(file.as_str());
            }
        }
    }
    for group in &facts.calls_out {
        if !uses.contains(&group.file.as_str()) {
            uses.push(group.file.as_str());
        }
    }
    if !uses.is_empty() {
        rows.push(format!("→ {}", uses.join(", ")));
    }
    let used_by: Vec<&str> = facts.callers_in.iter().map(|group| group.file.as_str()).collect();
    if !used_by.is_empty() {
        rows.push(format!("← {}", used_by.join(", ")));
    }
    rows
}

fn connection_suffix_cost(node: &StructuralTreeNode) -> u64 {
    connection_suffix(node).len() as u64
}

fn tree_text_rows(out: &StructuralTreeOut) -> Vec<TreeTextRow<'_>> {
    let mut rows = Vec::new();
    // Heading
    // When `--max-depth` truncated the rendered tree, the rendered
    // file count is much smaller than what the underlying scan saw.
    // Surface the scanned count so users don't read "0 files" and
    // assume the workspace is empty.
    rows.push(TreeTextRow::Header {
        files: out.summary.files,
        files_scanned: out.summary.files_scanned,
        dirs: out.summary.dirs,
        decls: out.summary.total_decls,
        cross_file_edges: out.summary.total_cross_file_edges,
        partial: !out.analysis_complete,
    });
    if !out.analysis_complete {
        rows.push(TreeTextRow::Incomplete(&out.analysis_incomplete_reasons));
        rows.push(TreeTextRow::RerunHint);
    }
    rows.push(TreeTextRow::Blank);

    let last = out.roots.len().saturating_sub(1);
    for (root_index, root) in out.roots.iter().enumerate() {
        let is_last = root_index == last;
        collect_tree_node_rows(root, String::new(), is_last, &mut rows);
    }

    rows.push(TreeTextRow::Blank);
    rows
}

fn collect_tree_node_rows<'a>(
    node: &'a StructuralTreeNode,
    prefix: String,
    is_last: bool,
    rows: &mut Vec<TreeTextRow<'a>>,
) {
    let next_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });
    let links = connection_rows(node);
    rows.push(TreeTextRow::Node {
        node,
        prefix,
        is_last,
    });
    for text in links {
        rows.push(TreeTextRow::Link {
            prefix: format!("{next_prefix}  "),
            text,
        });
    }

    let last = node.children.len().saturating_sub(1);
    for (child_index, child) in node.children.iter().enumerate() {
        let child_is_last = child_index == last;
        collect_tree_node_rows(child, next_prefix.clone(), child_is_last, rows);
    }
}

#[cfg(test)]
mod tests {
    use super::is_internal_workspace_entry_name;

    #[test]
    fn scanner_state_and_pre_upgrade_backups_are_not_user_tree_entries() {
        for name in [".bonsai", ".bonsai-agent", ".bonsai.pre-20260730-120000"] {
            assert!(is_internal_workspace_entry_name(name), "{name}");
        }
        assert!(!is_internal_workspace_entry_name(".bonsaiignore"));
        assert!(!is_internal_workspace_entry_name(".bonsai-notes"));
    }
}
