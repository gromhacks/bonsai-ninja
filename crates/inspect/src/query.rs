//! Query matching — the name-resolution layer the CLI's `inspect`
//! command uses to turn a user-typed query string into declarations
//! and non-declaration evidence hits.
//!
//! A programmatic consumer that wants inspect's data without the
//! CLI renderer composes this module with [`crate::ChainCache`]:
//!
//! 1. [`matching_decls`] / [`Matcher`] resolves the query to the
//!    set of decls + non-decl hits it applies to.
//! 2. [`crate::ChainCache`] hydrates direct resolver and syntax facts.
//! 3. [`crate::chain_matches_filters`] applies the active `--from` /
//!    `--to` predicates to the bounded evidence unit.
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

    /// Match one declaration while preserving qualified owner identity.
    ///
    /// Ordinary names remain fuzzy. For `Owner.member`, however, the member
    /// portion must match the declaration's own name as well as the complete
    /// qualified spelling. This prevents newly-correct nested identities such
    /// as `Owner.member.<lambda>` from becoming extra hits for `Owner.member`.
    #[must_use]
    pub fn is_declaration_match(&self, decl: &Decl) -> bool {
        match self {
            Self::Contains(needle) => contains_declaration_name(
                needle,
                &decl.name.to_lowercase(),
                decl.qualified_name.as_deref().map(str::to_lowercase).as_deref(),
            ),
            Self::Regex(re) => {
                re.is_match(&decl.name)
                    || decl
                        .qualified_name
                        .as_deref()
                        .is_some_and(|name| re.is_match(name))
            }
            Self::MatchAll => true,
        }
    }

    #[must_use]
    pub fn is_universal(&self) -> bool {
        matches!(self, Self::MatchAll)
    }
}

fn contains_declaration_name(needle: &str, name: &str, qualified_name: Option<&str>) -> bool {
    let tail = bonsai_common::short_qualified_tail(needle);
    if tail != needle {
        !tail.is_empty()
            && name.contains(tail)
            && qualified_name.is_some_and(|qualified| qualified.contains(needle))
    } else {
        name.contains(needle) || qualified_name.is_some_and(|qualified| qualified.contains(needle))
    }
}

/// Return every decl in the workspace whose name matches the
/// matcher, sorted callables-first (functions / methods /
/// constructors before classes / structs before everything else).
/// This is what `inspect` iterates to build its decl hits.
///
/// Iterates the workspace-cached `decl_name_index` so `Contains`
/// matchers consult precomputed lowercased names; regex matchers
/// consult the original names. Replaces a per-query
/// `for file in global.all_files() for decl in decls_in(file)`
/// double-loop.
pub fn matching_decls(ws: &Workspace, matcher: &Matcher) -> Vec<Decl> {
    let headers = ws.compiler_header_index();
    let entries = ws.decl_name_index().entries(headers.as_ref());
    let mut hits: Vec<Decl> = Vec::new();
    for entry in entries.iter() {
        let matches = match matcher {
            Matcher::Contains(needle) => contains_declaration_name(
                needle,
                &entry.lowercased_name,
                entry.lowercased_qualified_name.as_deref(),
            ),
            Matcher::Regex(re) => {
                re.is_match(&entry.decl.name)
                    || entry
                        .decl
                        .qualified_name
                        .as_ref()
                        .is_some_and(|name| re.is_match(name))
            }
            Matcher::MatchAll => true,
        };
        if matches {
            hits.push(entry.decl.clone());
        }
    }
    hits.sort_by_key(|d| match d.kind {
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor => 0,
        DeclKind::Class | DeclKind::Struct => 1,
        _ => 2,
    });
    hits
}

/// Project matching declarations to callable FuncIds. Classes and structs
/// are omitted because symbol evidence is callable-scoped.
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

/// Match callable ids against an explicitly selected compiler-header
/// projection. Query planners use this for complete endpoint lookup while a
/// scoped compiler session keeps its own canonical header index file-local.
pub fn matching_func_ids_in_headers(
    ws: &Workspace,
    headers: &bonsai_index::GlobalIndex,
    matcher: &Matcher,
) -> Vec<FuncId> {
    let entries = ws.decl_name_index().entries(headers);
    let mut hits = entries
        .iter()
        .filter(|entry| match matcher {
            Matcher::Contains(needle) => contains_declaration_name(
                needle,
                &entry.lowercased_name,
                entry.lowercased_qualified_name.as_deref(),
            ),
            Matcher::Regex(re) => {
                re.is_match(&entry.decl.name)
                    || entry
                        .decl
                        .qualified_name
                        .as_ref()
                        .is_some_and(|name| re.is_match(name))
            }
            Matcher::MatchAll => true,
        })
        .filter(|entry| {
            matches!(
                entry.decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
        .map(|entry| FuncId::new(entry.decl.symbol.raw()))
        .collect::<Vec<_>>();
    hits.sort_unstable_by_key(|func| func.raw());
    hits.dedup();
    hits
}
