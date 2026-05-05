//! Stable content-hash IDs and label assignment for rendered flows.
//!
//! Both `flow_id` (`F:`) and `group_id` (`G:`) are full FNV-1a-64
//! digests over null-separated chain names. FNV-1a is a fixed public
//! constant so every run + every host produces the same digest for the
//! same input bytes (`ahash` would seed from a per-process RNG and
//! break that contract).
//!
//! `compute_flow_labels_from` assigns the human-facing labels
//! (`"14"`, `"15a"`, `"15b"`) — chains that share an `entry → sink`
//! pair are treated as branch siblings and get letter suffixes; the
//! rest get a bare number.

/// Compute the stable `flow_id` for a rendered chain.
///
/// Inputs: just the chain's display names joined with `\0`. Same
/// query + same workspace → same id across runs / cache modes /
/// render modes / themes / precision changes.
#[must_use]
pub fn compute_flow_id(chain_names: &[String]) -> String {
    format!("F:{:016x}", fnv1a_names64(chain_names))
}

/// Stable content-hash id for a flow group (`G:` + 16 hex). Same
/// FNV-1a body as [`compute_flow_id`], different prefix so the two
/// id namespaces never collide in tools that handle both.
#[must_use]
pub fn compute_group_id(shared_suffix: &[String]) -> String {
    format!("G:{:016x}", fnv1a_names64(shared_suffix))
}

// FNV-1a-64 implementation lives in `bonsai_hash`; re-exported here so
// existing call sites continue to use the `bonsai_inspect::fnv1a_*`
// spelling. New code should import directly from `bonsai_hash`.
pub use bonsai_hash::{fnv1a_names64, fnv1a_names_low32};

/// Test-only convenience wrapper that resets the counter to 1 each
/// call. Production code threads a running counter via
/// [`compute_flow_labels_from`] so multi-hit pipelines get
/// sequential FLOW 1, FLOW 2, … numbering.
#[cfg(test)]
#[must_use]
pub(crate) fn compute_flow_labels(chains: &[Vec<String>]) -> Vec<String> {
    let mut ctr: u32 = 1;
    compute_flow_labels_from(chains, &mut ctr)
}

/// Assign flow labels that reveal branch splits.
///
/// Chains that share the same *entry* (first element) and the same
/// *sink* (last element) but take different intermediate paths are
/// treated as sibling branches of a single logical flow: the first
/// gets `"a"`, later siblings get `"b"`, `"c"`, …  Chains that
/// don't share an `entry → sink` pair with any other chain just use
/// their numeric index.
///
/// `next_number` threads a running counter across calls so multi-hit
/// pipelines get sequential FLOW 1, FLOW 2, … numbering without
/// every hit restarting at FLOW 1.
#[allow(clippy::implicit_hasher)] // hash-keyed cache; default hasher is fine for the access pattern
pub fn compute_flow_labels_from(chains: &[Vec<String>], next_number: &mut u32) -> Vec<String> {
    let mut groups: ahash::AHashMap<(String, String), Vec<usize>> = ahash::AHashMap::new();
    let mut ordered_keys: Vec<(String, String)> = Vec::new();
    for (i, chain) in chains.iter().enumerate() {
        let entry = chain.first().cloned().unwrap_or_default();
        let sink = chain.last().cloned().unwrap_or_default();
        let key = (entry, sink);
        let idxs = groups.entry(key.clone()).or_insert_with(|| {
            ordered_keys.push(key);
            Vec::new()
        });
        idxs.push(i);
    }
    let mut labels: Vec<String> = vec![String::new(); chains.len()];
    for key in ordered_keys {
        let Some(idxs) = groups.get(&key) else {
            continue;
        };
        let group_no = *next_number;
        *next_number += 1;
        if idxs.len() == 1 {
            labels[idxs[0]] = group_no.to_string();
        } else {
            for (slot, idx) in idxs.iter().enumerate() {
                let suffix = sibling_suffix(slot);
                labels[*idx] = format!("{group_no}{suffix}");
            }
        }
    }
    labels
}

/// Excel-style alphabetic suffix: 0→a, 25→z, 26→aa, 27→ab, …
/// Stays lowercase ASCII for any slot count instead of overflowing
/// past `'z'` into punctuation.
fn sibling_suffix(slot: usize) -> String {
    let mut n = slot;
    let mut chars: Vec<char> = Vec::new();
    loop {
        chars.push((b'a' + u8::try_from(n % 26).unwrap_or(0)) as char);
        n /= 26;
        if n == 0 {
            break;
        }
        n -= 1;
    }
    chars.iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::{compute_flow_labels, sibling_suffix};

    #[test]
    fn sibling_suffix_rolls_over_past_z() {
        assert_eq!(sibling_suffix(0), "a");
        assert_eq!(sibling_suffix(25), "z");
        assert_eq!(sibling_suffix(26), "aa");
        assert_eq!(sibling_suffix(27), "ab");
        assert_eq!(sibling_suffix(51), "az");
        assert_eq!(sibling_suffix(52), "ba");
        assert_eq!(sibling_suffix(701), "zz");
        assert_eq!(sibling_suffix(702), "aaa");
    }

    fn chain(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn single_chain_gets_plain_number() {
        let labels = compute_flow_labels(&[chain(&["handle", "sink"])]);
        assert_eq!(labels, vec!["1"]);
    }

    #[test]
    fn unrelated_chains_get_separate_numbers() {
        let labels = compute_flow_labels(&[chain(&["entry_a", "sink_x"]), chain(&["entry_b", "sink_y"])]);
        assert_eq!(labels, vec!["1", "2"]);
    }

    #[test]
    fn same_entry_different_sink_is_not_a_split() {
        let labels = compute_flow_labels(&[chain(&["handle", "sink_x"]), chain(&["handle", "sink_y"])]);
        assert_eq!(labels, vec!["1", "2"]);
    }

    #[test]
    fn same_entry_same_sink_via_different_path_is_a_split() {
        let labels = compute_flow_labels(&[
            chain(&["handle", "left", "sink"]),
            chain(&["handle", "right", "sink"]),
        ]);
        assert_eq!(labels, vec!["1a", "1b"]);
    }

    #[test]
    fn three_way_split_gets_abc() {
        let labels = compute_flow_labels(&[
            chain(&["handle", "p1", "sink"]),
            chain(&["handle", "p2", "sink"]),
            chain(&["handle", "p3", "sink"]),
        ]);
        assert_eq!(labels, vec!["1a", "1b", "1c"]);
    }

    #[test]
    fn mix_of_split_and_lone() {
        let labels = compute_flow_labels(&[
            chain(&["entry_a", "sink_x"]),
            chain(&["entry_b", "p1", "sink_y"]),
            chain(&["entry_b", "p2", "sink_y"]),
        ]);
        assert_eq!(labels, vec!["1", "2a", "2b"]);
    }
}
