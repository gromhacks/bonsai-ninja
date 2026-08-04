//! Language-neutral name helpers.
//!
//! This module deliberately owns no source-language punctuation inventory.
//! Adapters lower language syntax; shared candidate lookup only reasons about
//! identifier-shaped segments and punctuation boundaries. Exact identity is
//! still established by compiler symbols and the resolver.

/// Filename prefix used by the VFS case-sensitivity probe.
///
/// The probe is a short-lived filesystem artifact, not source code. Consumers
/// that render raw filesystem views may hide files matching
/// [`is_bonsai_case_probe_path`], but source ingest should not broadly ignore
/// arbitrary user files that merely share this prefix.
pub const BONSAI_CASE_PROBE_PREFIX: &str = ".bonsai_case_probe_";

/// True when `path` is the exact temporary file shape created by the VFS
/// case-sensitivity probe: `.bonsai_case_probe_<pid>_<nanos>`.
///
/// This intentionally rejects names with extensions or non-numeric suffixes so
/// a user-owned file such as `.bonsai_case_probe_notes.py` is not hidden.
#[must_use]
pub fn is_bonsai_case_probe_path(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let Some(rest) = name.strip_prefix(BONSAI_CASE_PROBE_PREFIX) else {
        return false;
    };
    let Some((pid, nanos)) = rest.split_once('_') else {
        return false;
    };
    !pid.is_empty()
        && !nanos.is_empty()
        && pid.chars().all(|c| c.is_ascii_digit())
        && nanos.chars().all(|c| c.is_ascii_digit())
}

/// Return the final identifier-shaped segment in a qualified compiler name.
///
/// This is intentionally vocabulary-free: it recognizes a top-level run of
/// non-identifier punctuation between two identifier segments instead of a
/// union of source-language separators. Delimiters nested inside generic,
/// call, or subscript syntax are ignored. This is candidate lookup only;
/// semantic resolution remains authoritative.
#[must_use]
pub fn short_qualified_tail(name: &str) -> &str {
    qualified_boundary(name).map_or(name, |(_, tail_start)| &name[tail_start..])
}

/// True when two adapter-emitted qualified names are identical or
/// share the same non-empty callable tail.
///
/// Tail equality is intentionally a candidate/de-duplication rule, not
/// proof that two symbols resolve to the same declaration. Callers that
/// need symbol identity must still use the resolver.
#[must_use]
pub fn qualified_names_match(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let left_tail = short_qualified_tail(left);
    !left_tail.is_empty() && left_tail == short_qualified_tail(right)
}

/// True when `prefix` ends at a qualified-name punctuation boundary.
#[must_use]
pub fn ends_at_qualified_name_boundary(prefix: &str) -> bool {
    prefix
        .chars()
        .next_back()
        .is_some_and(|ch| !is_name_segment_char(ch))
}

/// True when `suffix` starts at a qualified-name punctuation boundary.
#[must_use]
pub fn starts_at_qualified_name_boundary(suffix: &str) -> bool {
    suffix.chars().next().is_some_and(|ch| !is_name_segment_char(ch))
}

/// Strip source punctuation preceding an adapter-emitted identifier/place.
///
/// No concrete sigil is known here. The operation stops at the first Unicode
/// alphanumeric or underscore and is safe only for compiler facts already
/// classified as names—not arbitrary source text.
#[must_use]
pub fn trim_leading_name_punctuation(value: &str) -> &str {
    value.trim_start_matches(is_name_punctuation)
}

/// Predicate used with `str::trim_start_matches` for compiler-classified
/// names. It is structural Unicode classification, not a source-language
/// punctuation inventory.
#[must_use]
pub fn is_name_punctuation(ch: char) -> bool {
    !is_name_segment_char(ch)
}

/// Return the owner portion of a qualified compiler name.
#[must_use]
pub fn qualified_name_owner(name: &str) -> Option<&str> {
    qualified_boundary(name)
        .and_then(|(separator_start, _)| name.get(..separator_start))
        .map(str::trim)
        .filter(|owner| !owner.is_empty())
}

/// Split a compiler-qualified name into top-level identifier segments without
/// knowing the source language's separator vocabulary.
#[must_use]
pub fn qualified_name_segments(name: &str) -> Vec<&str> {
    let mut reversed = Vec::new();
    let mut remaining = name.trim();
    while let Some((separator_start, tail_start)) = qualified_boundary(remaining) {
        let tail = remaining[tail_start..].trim();
        if !tail.is_empty() {
            reversed.push(tail);
        }
        let owner = remaining[..separator_start].trim();
        if owner.is_empty() || owner == remaining {
            break;
        }
        remaining = owner;
    }
    if !remaining.is_empty() {
        reversed.push(remaining);
    }
    reversed.reverse();
    reversed
}

/// Return every non-empty top-level qualified-name prefix while preserving
/// the adapter-emitted punctuation between its segments.
///
/// This is the structural replacement for shared callers that previously
/// tried a union of source-language separators. The input must already be a
/// compiler-classified name or module identity. No punctuation spelling is
/// interpreted here.
#[must_use]
pub fn qualified_name_prefixes(name: &str) -> Vec<&str> {
    let mut reversed = Vec::new();
    let mut remaining = name.trim();
    if remaining.is_empty() {
        return reversed;
    }
    reversed.push(remaining);
    while let Some((separator_start, _)) = qualified_boundary(remaining) {
        let owner = remaining[..separator_start].trim();
        if owner.is_empty() || owner == remaining {
            break;
        }
        reversed.push(owner);
        remaining = owner;
    }
    reversed.reverse();
    reversed
}

/// Split a compiler-qualified name at its first structural punctuation
/// boundary. The returned tail preserves any later qualification.
#[must_use]
pub fn split_qualified_name_head_tail(name: &str) -> Option<(&str, &str)> {
    let trimmed = name.trim();
    let prefixes = qualified_name_prefixes(trimmed);
    if prefixes.len() < 2 {
        return None;
    }
    let head = *prefixes.first()?;
    let tail = trimmed
        .strip_prefix(head)?
        .trim_start_matches(is_name_punctuation)
        .trim();
    (!head.is_empty() && !tail.is_empty()).then_some((head, tail))
}

/// Split a compiler-qualified name at its final structural punctuation
/// boundary.
#[must_use]
pub fn split_qualified_name_owner_tail(name: &str) -> Option<(&str, &str)> {
    let trimmed = name.trim();
    let owner = qualified_name_owner(trimmed)?;
    let tail = short_qualified_tail(trimmed).trim();
    (!owner.is_empty() && !tail.is_empty()).then_some((owner, tail))
}

/// Canonicalize top-level compiler-qualified name segments to dotted IR.
///
/// The input must already be classified as a name/place by an adapter. No
/// separator spelling is recognized here; structural punctuation boundaries
/// between top-level identifier segments become the canonical `.` delimiter.
#[must_use]
pub fn normalize_qualified_name(name: &str) -> String {
    let segments = qualified_name_segments(name);
    if segments.len() <= 1 {
        return name.trim().to_string();
    }
    segments.join(".")
}

fn qualified_boundary(name: &str) -> Option<(usize, usize)> {
    let mut depth = 0_u32;
    let mut punctuation_start = None;
    let mut last_boundary = None;
    let mut previous_was_name = false;

    for (index, ch) in name.char_indices() {
        match ch {
            '(' | '[' | '{' | '<' => {
                depth = depth.saturating_add(1);
                punctuation_start = None;
                previous_was_name = false;
            }
            ')' | ']' | '}' | '>' if depth > 0 => {
                depth = depth.saturating_sub(1);
                punctuation_start = None;
                previous_was_name = depth == 0;
            }
            _ if depth == 0 && is_name_segment_char(ch) => {
                if let Some(start) = punctuation_start.take() {
                    if previous_was_name
                        || name[..start]
                            .chars()
                            .next_back()
                            .is_some_and(is_name_segment_char)
                    {
                        last_boundary = Some((start, index));
                    }
                }
                previous_was_name = true;
            }
            _ if depth == 0 => {
                punctuation_start.get_or_insert(index);
            }
            _ => {}
        }
    }
    last_boundary
}

fn is_name_segment_char(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

/// Per-workspace bonsai cache/state directory.
///
/// The default is an OS cache location namespaced by the canonical workspace
/// path, for example
/// `~/Library/Caches/bonsai-ninja/workspaces/project-0123abcd...` on macOS.
/// Analysis must not dirty the repository it inspects. Set
/// `BONSAI_WORKSPACE_DIR` to an exact directory when a workflow deliberately
/// wants a different location; relative overrides remain workspace-relative
/// for compatibility with earlier releases.
#[must_use]
pub fn workspace_bonsai_dir(workspace_root: &std::path::Path) -> std::path::PathBuf {
    match std::env::var_os("BONSAI_WORKSPACE_DIR") {
        Some(raw) if !raw.is_empty() => {
            let path = std::path::PathBuf::from(raw);
            if path.is_absolute() {
                path
            } else {
                workspace_root.join(path)
            }
        }
        _ => default_workspace_bonsai_dir(workspace_root, dirs::cache_dir().as_deref()),
    }
}

fn default_workspace_bonsai_dir(
    workspace_root: &std::path::Path,
    system_cache_root: Option<&std::path::Path>,
) -> std::path::PathBuf {
    let identity = workspace_root.canonicalize().unwrap_or_else(|_| {
        if workspace_root.is_absolute() {
            workspace_root.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(workspace_root))
                .unwrap_or_else(|_| workspace_root.to_path_buf())
        }
    });
    let mut hasher = bonsai_hash::Hasher::new();
    hasher.absorb(identity.to_string_lossy().as_bytes());
    let digest = hasher.finish();
    let slug = identity
        .file_name()
        .and_then(|name| name.to_str())
        .map(workspace_cache_slug)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "workspace".to_string());
    system_cache_root
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir)
        .join("bonsai-ninja")
        .join("workspaces")
        .join(format!("{slug}-{digest:016x}"))
}

fn workspace_cache_slug(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .take(48)
        .collect()
}

#[cfg(test)]
#[path = "names_tests.rs"]
mod tests;
