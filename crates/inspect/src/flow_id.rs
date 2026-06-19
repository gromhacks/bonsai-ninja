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

/// Minimal identity surface for a raw taint-flow row.
///
/// The CLI, security analysis, SDK, and future graph exports can have
/// different row structs, but a `T:` id must be derived from the same
/// ordered fields everywhere. Implement this trait for the local row
/// step type and call [`compute_taint_flow_id`] instead of re-creating
/// the hash loop at each rendering surface.
pub trait TaintFlowIdentityStep {
    fn caller(&self) -> &str;
    fn callee(&self) -> &str;
    fn file(&self) -> &str;
    fn line(&self) -> u32;
    fn column(&self) -> u32;
    fn for_each_tainted_arg(&self, visit: &mut dyn FnMut(usize, &str, Option<&str>));
}

/// Compute a stable raw-taint-row id (`T:` + 8 lower-case hex chars).
///
/// This intentionally keeps the historic 32-bit display width used by
/// `inspect --taint-flow` so saved `T:` filters remain short and output
/// compatible. The full row contents still decide the hash: entry,
/// terminal, ordered steps, source locations, and tainted argument
/// evidence.
#[must_use]
pub fn compute_taint_flow_id<S: TaintFlowIdentityStep>(entry: &str, terminal: &str, steps: &[S]) -> String {
    let mut hasher = bonsai_hash::Hasher::new();
    absorb_hash_field(&mut hasher, entry);
    absorb_hash_field(&mut hasher, terminal);
    for step in steps {
        absorb_hash_field(&mut hasher, step.caller());
        absorb_hash_field(&mut hasher, step.callee());
        absorb_hash_field(&mut hasher, step.file());
        absorb_hash_field(&mut hasher, &step.line().to_string());
        absorb_hash_field(&mut hasher, &step.column().to_string());
        step.for_each_tainted_arg(&mut |index, value_text, param_name| {
            absorb_hash_field(&mut hasher, &index.to_string());
            absorb_hash_field(&mut hasher, value_text);
            if let Some(param_name) = param_name {
                absorb_hash_field(&mut hasher, param_name);
            }
        });
    }
    format!("T:{:08x}", hasher.finish() as u32)
}

fn absorb_hash_field(hasher: &mut bonsai_hash::Hasher, value: &str) {
    hasher.absorb(value.as_bytes());
    hasher.absorb_separator();
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
#[path = "flow_id_tests.rs"]
mod tests;
