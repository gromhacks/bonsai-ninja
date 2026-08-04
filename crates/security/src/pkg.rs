//! Rulepack-driven package identity matching.
//!
//! Language adapters surface import/call identities in their canonical IR.
//! Each language's `metadata.yml` entry declares the separators, wrappers,
//! and binding shape used by those identities. Shared security code applies
//! that data generically; it owns no language, runtime, or package spellings.

use crate::loader::PackageMatchSemantics;

/// True when adapter-emitted `imported` identifies rule-declared package
/// `needle` under the language's metadata-defined spelling semantics.
#[must_use]
pub(crate) fn import_matches_package(
    imported: &str,
    needle: &str,
    semantics: &PackageMatchSemantics,
) -> bool {
    if needle.is_empty() {
        return false;
    }

    let imported = semantics
        .strip_import_prefixes
        .iter()
        .find_map(|prefix| imported.strip_prefix(prefix))
        .unwrap_or(imported);
    if imported == needle {
        return true;
    }

    let stripped = semantics
        .strip_import_suffixes
        .iter()
        .find_map(|suffix| imported.strip_suffix(suffix))
        .unwrap_or(imported);
    if stripped == needle {
        return true;
    }

    semantics.package_separators.iter().any(|separator| {
        starts_with_package_separator(imported, needle, separator)
            || (stripped != imported && starts_with_package_separator(stripped, needle, separator))
    })
}

fn starts_with_package_separator(imported: &str, needle: &str, separator: &str) -> bool {
    !separator.is_empty()
        && imported.len() > needle.len() + separator.len()
        && imported.starts_with(needle)
        && imported[needle.len()..].starts_with(separator)
}

/// True when metadata proves that a package path's last component is the
/// local call qualifier used by adapter-emitted call identities.
#[must_use]
pub(crate) fn call_candidate_matches_package_tail(
    candidate: &str,
    needle: &str,
    semantics: &PackageMatchSemantics,
) -> bool {
    let Some(binding) = semantics.call_qualifier_from_package_tail.as_ref() else {
        return false;
    };
    if candidate.is_empty() || binding.package_separator.is_empty() {
        return false;
    }
    let Some((head, tail)) = needle.rsplit_once(binding.package_separator.as_str()) else {
        return false;
    };
    if head.is_empty() || tail.is_empty() {
        return false;
    }
    let candidate_head = binding
        .call_separators
        .iter()
        .filter_map(|separator| candidate.find(separator).map(|index| (index, separator.len())))
        .min_by_key(|(index, _)| *index)
        .map_or(candidate, |(index, _)| &candidate[..index])
        .trim();
    !candidate_head.is_empty() && candidate_head == tail
}

#[cfg(test)]
#[path = "pkg_tests.rs"]
mod tests;
