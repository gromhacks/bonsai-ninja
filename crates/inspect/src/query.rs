//! Query matching — the name-resolution layer the CLI's `inspect`
//! command uses to turn a user-typed query string into the decls
//! and non-decl hits it should enumerate chains for.
//!
//! A programmatic consumer that wants inspect's data without the
//! CLI renderer composes this module with [`crate::ChainCache`]:
//!
//! 1. [`matching_decls`] / [`Matcher`] resolves the query to the
//!    set of decls + non-decl hits it applies to.
//! 2. [`crate::ChainCache::chains_resolved`] enumerates upstream
//!    chains for each target.
//! 3. [`crate::chain_matches_filters`] filters chains against the
//!    active `--from` / `--to` needles.
//!
//! The CLI does steps 1–3 plus rendering; library consumers stop at
//! step 3 and produce their own output.

use bonsai_common::FuncId;
use bonsai_lang_api::{Decl, DeclKind};
use bonsai_workspace::Workspace;

/// Simple matcher abstraction. Mirrors the CLI's own `Matcher` so
/// `inspect --regex` / substring / no-query semantics are the same
/// via the SDK.
#[derive(Clone, Debug)]
pub enum Matcher {
    /// Case-insensitive substring match.
    Contains(String),
    /// Precompiled regex.
    Regex(regex::Regex),
    /// Every name matches. Used in "filter-only" mode where the
    /// narrowing comes from `--from` / `--to` / `--file` / `--kind`
    /// rather than a positive query.
    MatchAll,
}

impl Matcher {
    /// Build a [`Matcher`] from the CLI-style (pattern, is_regex)
    /// pair. `None` → [`Matcher::MatchAll`].
    pub fn build(pattern: Option<&str>, is_regex: bool) -> Result<Self, regex::Error> {
        match pattern {
            None => Ok(Self::MatchAll),
            Some(p) if is_regex => Ok(Self::Regex(regex::Regex::new(p)?)),
            Some(p) => Ok(Self::Contains(p.to_lowercase())),
        }
    }

    #[must_use]
    pub fn is_match(&self, haystack: &str) -> bool {
        match self {
            Self::Contains(needle) => haystack.to_lowercase().contains(needle),
            Self::Regex(re) => re.is_match(haystack),
            Self::MatchAll => true,
        }
    }

    #[must_use]
    pub fn is_universal(&self) -> bool {
        matches!(self, Self::MatchAll)
    }
}

/// Return every decl in the workspace whose name matches the
/// matcher, sorted callables-first (functions / methods /
/// constructors before classes / structs before everything else).
/// This is what `inspect` iterates to build its decl hits.
pub fn matching_decls(ws: &Workspace, matcher: &Matcher) -> Vec<Decl> {
    let global = ws.db().global_index();
    let mut hits: Vec<Decl> = Vec::new();
    for file in global.all_files() {
        for d in global.decls_in(file) {
            if matcher.is_match(&d.name) {
                hits.push(d.clone());
            }
        }
    }
    hits.sort_by_key(|d| match d.kind {
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor => 0,
        DeclKind::Class | DeclKind::Struct => 1,
        _ => 2,
    });
    hits
}

/// Project the matching decls down to FuncIds that can be fed
/// straight into [`crate::ChainCache::chains_resolved`]. Only
/// callable decls (functions, methods, constructors) survive —
/// classes / structs are dropped because chain enumeration is
/// function-level.
pub fn matching_func_ids(ws: &Workspace, matcher: &Matcher) -> Vec<FuncId> {
    matching_decls(ws, matcher)
        .into_iter()
        .filter(|d| {
            matches!(
                d.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
        .map(|d| FuncId::new(d.symbol.raw()))
        .collect()
}
