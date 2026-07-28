//! `tree` — workspace navigation surface (CLI renderer).
//!
//! Builds and renders a filesystem-only tree as text or JSON. Text mode draws
//! a `tree(1)`-style hierarchy with `├──` / `└──` / `│` connectors, themed via
//! the global [`crate::ui::Ui`] palette so it matches every other command. This
//! command never opens the compiler or runs security analysis; findings belong
//! to `security taint-analysis`.

use anyhow::Result;
use bonsai_common::is_bonsai_case_probe_path;
use serde::Serialize;
use std::path::{Path, PathBuf};

use super::emit_json_value_paged_cached;
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
    pub(crate) legacy_security_option: bool,
    pub(crate) limit: usize,
    pub(crate) compact: bool,
    pub(crate) context: Option<&'a str>,
    pub(crate) page: Option<&'a str>,
    pub(crate) all: bool,
    pub(crate) format: &'a str,
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
        }
    }
}

pub(crate) fn cmd_tree(args: TreeArgs<'_>) -> Result<()> {
    if args.legacy_security_option {
        anyhow::bail!(
            "`tree` is filesystem-only and never runs taint analysis; use \
             `bonsai-ninja security <workspace> taint-analysis` for findings, \
             severity filters, and rulepack selection"
        );
    }
    let filters_hash = tree_filters_hash(&args);
    let stage = progress::ScopedSpinner::new("scanning filesystem tree");
    let out = build_fast_filesystem_tree(&args)?;
    stage.finish();

    match args.format {
        "json" => {
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
        _ => render_text_paged(&out, args.context, args.page, args.all, filters_hash)?,
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
        },
    })
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
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some(
            ".git"
                | ".bonsai"
                | ".bonsai-agent"
                | "target"
                | "node_modules"
                | ".gradle"
                | "build"
                | "dist"
                | "out"
                | ".idea"
        )
    )
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

fn normalized_path_contains(path: &str, filter: &str) -> bool {
    let filter = normalize_path_for_filter(filter);
    !filter.is_empty() && normalize_path_for_filter(path).contains(&filter)
}

fn filter_looks_like_absolute_path(filter: &str) -> bool {
    let normalized = normalize_path_for_filter(filter);
    if normalized.len() >= 3 && normalized.as_bytes()[1] == b':' && normalized.as_bytes()[2] == b'/' {
        return true;
    }
    Path::new(filter).is_absolute() && normalized.trim_matches('/').contains('/')
}

fn normalize_path_for_filter(value: &str) -> String {
    value.replace('\\', "/").trim_start_matches("./").to_string()
}

fn tree_filters_hash(args: &TreeArgs<'_>) -> u64 {
    let max_depth = args.max_depth.map(|n| n.to_string()).unwrap_or_default();
    let exclude_file = args.exclude_file.join("\0");
    let limit = args.limit.to_string();
    let compact = if args.compact { "1" } else { "0" };
    paging::hash_filters(&[
        ("max_depth", &max_depth),
        ("file", args.file.unwrap_or("")),
        ("exclude_file", &exclude_file),
        ("limit", &limit),
        ("compact", compact),
    ])
}

fn render_text_paged(
    out: &StructuralTreeOut,
    context: Option<&str>,
    page: Option<&str>,
    all: bool,
    filters_hash: u64,
) -> Result<()> {
    let lines = render_text_lines(out);
    let cfg =
        paging::config_from_raw(context, page, all, FormatClass::Text).map_err(|e| anyhow::anyhow!(e))?;
    let rows: Vec<usize> = (0..lines.len()).collect();
    let (page_rows, info) = paging::paginate(&rows, &cfg, "tree", filters_hash, |idx| {
        lines[*idx].len() as u64 + 128
    });
    for idx in page_rows {
        cli_println!("{}", lines[idx]);
    }
    render_paging_footer(&info, "bonsai-ninja tree <workspace>");
    Ok(())
}

fn render_text_lines(out: &StructuralTreeOut) -> Vec<String> {
    let u = ui();
    let mut lines = Vec::new();
    // Heading
    let total = out.summary.files;
    let scanned = out.summary.files_scanned;
    // When `--max-depth` truncated the rendered tree, the rendered
    // file count is much smaller than what the underlying scan saw.
    // Surface the scanned count so users don't read "0 files" and
    // assume the workspace is empty.
    let file_chip = if scanned > total {
        format!(
            "{} file{} ({} scanned)",
            total,
            if total == 1 { "" } else { "s" },
            scanned
        )
    } else {
        format!("{} file{}", total, if total == 1 { "" } else { "s" })
    };
    let header = format!(
        "tree — {} · {} dir{}",
        file_chip,
        out.summary.dirs,
        if out.summary.dirs == 1 { "" } else { "s" },
    );
    lines.push(u.heading(&header));
    if !out.analysis_complete {
        let reasons = if out.analysis_incomplete_reasons.is_empty() {
            "analysis-incomplete".to_string()
        } else {
            out.analysis_incomplete_reasons.join("; ")
        };
        lines.push(format!("{} {}", u.warn("tree view incomplete:"), u.dim(&reasons)));
        lines.push(u.dim("rerun with --all and avoid restrictive --max-depth when you need every node"));
    }
    lines.push(String::new());

    let last = out.roots.len().saturating_sub(1);
    for (root_index, root) in out.roots.iter().enumerate() {
        let is_last = root_index == last;
        render_node_lines(root, "", is_last, &mut lines);
    }

    lines.push(String::new());
    lines
}

fn render_node_lines(node: &StructuralTreeNode, prefix: &str, is_last: bool, lines: &mut Vec<String>) {
    let u = ui();
    let connector = if is_last { "└── " } else { "├── " };
    let next_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });

    // Node line: connector + name.
    let name_styled = match node.kind {
        StructuralNodeKind::Dir => u.kind(&format!("{}/", node.name)),
        StructuralNodeKind::File => u.name(&node.name),
    };
    lines.push(format!("{prefix}{}{}", u.dim(connector), name_styled));

    let last = node.children.len().saturating_sub(1);
    for (child_index, child) in node.children.iter().enumerate() {
        let child_is_last = child_index == last;
        render_node_lines(child, &next_prefix, child_is_last, lines);
    }
}
