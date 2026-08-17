//! ChainCache + flow-id integration tests.
//!
//! Moved verbatim from the CLI's inline test module when these
//! types graduated from the binary into this SDK crate. Coverage
//! is otherwise identical: every cache method must return what
//! the uncached implementation would return and every flow-id must hash
//! deterministically.
//!
//! The fixture is a tiny Python program (the Python adapter is the
//! one dev-dep) so the resolver / global index / call graph all
//! get exercised end-to-end.

use crate::{compute_flow_id, find_call_span_to_func_uncached, BoundedCache, CallEdgeResolver, ChainCache};
use bonsai_callgraph::collect_callable_targets;
use bonsai_common::{Span, SymbolId};
use bonsai_lang_api::LanguageRegistry;
use bonsai_workspace::Workspace;
use std::sync::Arc;

/// Tiny three-function chain: `entry -> middle -> sink`.
/// `middle` also directly calls `helper`, so
/// `flow_reachable_names([entry, middle])` must pick up `sink`,
/// `helper`, and the short-name variants.
const FIXTURE: &str = r"
def helper(x):
    return x

def sink(payload):
    os.system(payload)

def middle(p):
    helper(p)
    sink(p)

def entry(user_input):
    middle(user_input)
";

fn ws_with_python(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("fixture.py".to_string(), Arc::<str>::from(source));
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

/// Resolve a unique decl name from the FIXTURE workspace to its
/// `FuncId`. Panics if the name doesn't appear or has multiple
/// matches — the FIXTURE is small and curated specifically so that
/// each name (`entry`, `middle`, `sink`, `helper`) is unique.
fn func_id(ws: &Workspace, name: &str) -> bonsai_common::FuncId {
    let candidates = collect_callable_targets(&ws.db().global_index(), name);
    assert_eq!(
        candidates.len(),
        1,
        "fixture name `{name}` must resolve to exactly one FuncId, got {}",
        candidates.len()
    );
    candidates[0]
}

#[test]
fn reachable_resolved_walks_chain_callees() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::new(&ws);
    let entry = func_id(&ws, "entry");
    let middle = func_id(&ws, "middle");
    let helper = func_id(&ws, "helper");
    let sink = func_id(&ws, "sink");
    let chain = vec![entry, middle];
    let reachable = cache.reachable_resolved(&chain);
    // Hops themselves + middle's direct callees (helper, sink).
    assert!(reachable.contains(&entry));
    assert!(reachable.contains(&middle));
    assert!(reachable.contains(&helper));
    assert!(reachable.contains(&sink));
}

#[test]
fn reachable_resolved_repeat_is_a_cache_hit() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::new(&ws);
    let chain = vec![func_id(&ws, "entry"), func_id(&ws, "middle")];
    let first = cache.reachable_resolved(&chain);
    let second = cache.reachable_resolved(&chain);
    assert_eq!(first, second);
}

#[test]
fn callees_of_resolved_matches_resolved_graph_edges() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::new(&ws);
    let middle = func_id(&ws, "middle");
    let helper = func_id(&ws, "helper");
    let sink = func_id(&ws, "sink");
    let callees = cache.callees_of_resolved(middle);
    assert!(callees.contains(&helper));
    assert!(callees.contains(&sink));
}

#[test]
fn enclosing_func_returns_funcid_and_name() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::new(&ws);
    let global = ws.db().global_index();
    let file = ws.vfs().all_files()[0];
    let idx = global.file_index(file).expect("file_index");
    let decls: Vec<&bonsai_lang_api::Decl> = idx.defs.iter().collect();
    let sink_decl = decls
        .iter()
        .find(|d| d.name == "sink")
        .expect("sink decl must exist");
    let (id, name) = cache
        .enclosing_func(file, &decls, sink_decl.name_span)
        .expect("enclosing must resolve to sink");
    assert_eq!(name, "sink");
    assert_eq!(id, bonsai_common::FuncId::new(sink_decl.symbol.raw()));
}

#[test]
fn enclosing_cache_hit_is_stable() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::new(&ws);
    let global = ws.db().global_index();
    let file = ws.vfs().all_files()[0];
    let idx = global.file_index(file).expect("file_index");
    let decls: Vec<&bonsai_lang_api::Decl> = idx.defs.iter().collect();
    let span = decls
        .iter()
        .find(|d| d.name == "middle")
        .expect("middle decl")
        .name_span;
    let first = cache.enclosing(file, &decls, span);
    let second = cache.enclosing(file, &decls, span);
    assert_eq!(first, second);
    assert_eq!(first.as_deref(), Some("middle"));
}

#[test]
fn enclosing_cache_stores_positive_and_negative_results() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::new(&ws);
    let global = ws.db().global_index();
    let file = ws.vfs().all_files()[0];
    let idx = global.file_index(file).expect("file_index");
    let decls: Vec<&bonsai_lang_api::Decl> = idx.defs.iter().collect();
    let middle_span = decls
        .iter()
        .find(|d| d.name == "middle")
        .expect("middle decl")
        .name_span;

    assert!(cache.enclosing.lock().is_empty());
    let positive = cache.enclosing_func(file, &decls, middle_span);
    assert_eq!(positive.as_ref().map(|(_, name)| name.as_str()), Some("middle"));
    assert_eq!(cache.enclosing.lock().len(), 1);
    let positive_again = cache.enclosing_func(file, &decls, middle_span);
    assert_eq!(positive, positive_again);
    assert_eq!(cache.enclosing.lock().len(), 1);

    let miss = Span {
        file,
        start: u64::from(u32::MAX) - 1,
        end: u64::from(u32::MAX),
    };
    assert!(cache.enclosing_func(file, &decls, miss).is_none());
    assert_eq!(cache.enclosing.lock().len(), 2);
    assert!(cache.enclosing_func(file, &decls, miss).is_none());
    assert_eq!(cache.enclosing.lock().len(), 2);
}

#[test]
fn resolved_graph_is_built_once() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::new(&ws);
    // `.resolved_graph()` returns a reference tied to the cache —
    // first call builds, second call hits the OnceCell. Confirm
    // the pointer is identical across calls so we know the graph
    // isn't being rebuilt.
    let first_ptr = std::ptr::from_ref(cache.resolved_graph());
    let second_ptr = std::ptr::from_ref(cache.resolved_graph());
    assert_eq!(
        first_ptr, second_ptr,
        "resolved_graph() must return a stable pointer"
    );
}

/// Skipping the `--from` / `--to` filter compute when neither is set
/// is an emergent property of the code path, not a method on
/// `ChainCache`. Assert semantically: the reachable() computation
/// never has to run when the filter is `None`, by showing the cache
/// stays empty across an end-to-end chain walk that doesn't invoke it.
#[test]
fn filter_skip_leaves_reachable_cache_cold() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::new(&ws);
    let _ = cache.resolved_graph();
    assert!(
        cache.reachable_r.lock().is_empty(),
        "reachable cache must stay cold when no --from/--to filter is applied"
    );
}

#[test]
fn reset_clears_every_map() {
    let ws = ws_with_python(FIXTURE);
    let mut cache = ChainCache::new(&ws);
    let middle = func_id(&ws, "middle");
    // Populate every cache.
    let _ = cache.resolved_graph();
    let _ = cache.callees_of_resolved(middle);
    let _ = cache.reachable_resolved(&[func_id(&ws, "entry"), middle]);
    assert!(cache.resolved.get().is_some());
    assert!(!cache.callees_r.lock().is_empty());
    assert!(!cache.reachable_r.lock().is_empty());

    cache.reset();
    assert!(
        cache.resolved.get().is_none(),
        "resolved OnceCell must be cleared"
    );
    assert!(cache.callees_r.lock().is_empty());
    assert!(cache.reachable_r.lock().is_empty());
    assert!(cache.enclosing.lock().is_empty());

    assert!(cache.resolved_graph().callees_of(middle).next().is_some());
}

#[test]
fn disabled_cache_never_populates_maps() {
    let ws = ws_with_python(FIXTURE);
    let cache = ChainCache::without_cache(&ws);
    let middle = func_id(&ws, "middle");
    // Every method must return a correct value but leave the memo
    // maps empty — `--no-cache` is a true pass-through.
    let _ = cache.callees_of_resolved(middle);
    let _ = cache.reachable_resolved(&[func_id(&ws, "entry"), middle]);
    assert!(cache.callees_r.lock().is_empty());
    assert!(cache.reachable_r.lock().is_empty());
}

#[test]
fn taint_facts_cache_reuses_the_canonical_graph_profile() {
    let ws = ws_with_python(
        r"
def sanitize(x):
    return x

def sink(payload):
    os.system(payload)

def entry(user_input):
    cleaned = sanitize(user_input)
    sink(cleaned)
",
    );
    ws.dataflow().prewarm_all(ws.db());
    assert_eq!(
        ws.dataflow().pending_count(ws.db()),
        0,
        "test setup must start from a fully warmed graph"
    );

    // Rulepack classifications are report evidence, not cache profiles.
    // Transfer semantics are applied by the exact security/dump query paths,
    // while ChainCache reads the one canonical compiler graph.
    let cache = ChainCache::new(&ws);
    let _ = cache.taint_facts_for_entry(func_id(&ws, "entry"));

    assert_eq!(
        ws.dataflow().pending_count(ws.db()),
        0,
        "inspect taint lookups must not treat sanitizer names as a distinct graph profile"
    );
}

/// Architectural correctness: a name that resolves to multiple
/// distinct callable decls must produce that many distinct nodes
/// in the resolved graph (one per FuncId). Direct demonstration
/// that the spec-mandated FuncId disambiguation works — the
/// `Pool::__construct` vs `CurlFactory::__construct` problem
/// can't recur.
#[test]
fn name_collisions_become_distinct_funcids() {
    let ws = ws_with_python(
        r"
class A:
    def __init__(self): pass
class B:
    def __init__(self): pass
class C:
    def __init__(self): pass
",
    );
    let global = ws.db().global_index();
    // All three `__init__` decls share the same display name but
    // must have distinct FuncIds.
    let candidates = collect_callable_targets(&global, "__init__");
    assert_eq!(
        candidates.len(),
        3,
        "expected 3 __init__ candidates (one per class), got {}",
        candidates.len()
    );
    // FuncIds must be pairwise distinct.
    let mut seen = ahash::AHashSet::new();
    for f in &candidates {
        assert!(seen.insert(*f), "duplicate FuncId in candidates: {f:?}");
    }
}

/// Direct symbol evidence retains the resolver's semantic precision.
#[test]
fn direct_edge_retains_semantic_precision() {
    // `target` is unique → caller→target edge is Direct/Narrowed.
    let ws = ws_with_python(
        r"
def target(): pass
def caller():
    target()
",
    );
    ws.vfs().write(
        std::path::PathBuf::from("a.py"),
        std::sync::Arc::<str>::from("def m(): pass\n"),
    );
    ws.vfs().write(
        std::path::PathBuf::from("b.py"),
        std::sync::Arc::<str>::from("def m(): pass\ndef driver():\n    m()\n"),
    );
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    let cache = ChainCache::new(&ws);

    let target = func_id(&ws, "target");
    let caller = func_id(&ws, "caller");
    let edge = cache
        .resolved_graph()
        .callees_of(caller)
        .find(|edge| edge.to == target)
        .expect("expected compiler-resolved caller → target edge");
    assert_eq!(
        edge.precision,
        bonsai_common::Precision::Narrowed,
        "single-candidate edge must retain Narrowed precision"
    );

    let driver = func_id(&ws, "driver");
    let edges: Vec<_> = cache.resolved_graph().callees_of(driver).collect();
    assert!(
        edges.iter().all(|edge| edge.precision.is_semantic()),
        "resolved graph must not expose over-approximate edges: {edges:?}"
    );
}

/// Spec compliance: unique resolution gets `EdgeKind::Direct` /
/// `Precision::Narrowed`; ambiguous broad resolution is not emitted.
#[test]
fn resolved_graph_assigns_correct_precision() {
    // Build a graph where `caller` calls `target` and `target` is
    // unique → expect Direct/Narrowed.
    let ws = ws_with_python(
        r"
def target(): pass
def caller():
    target()
",
    );
    let cache = ChainCache::new(&ws);
    let target = func_id(&ws, "target");
    let edges: Vec<_> = cache.resolved_graph().callers_of(target).collect();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, bonsai_callgraph::EdgeKind::Direct);
    assert_eq!(edges[0].precision, bonsai_common::Precision::Narrowed);

    // A bare call with same-named candidates must not fan out into
    // over-approximate virtual edges.
    let ws2 = ws_with_python(
        r"
def m(): pass
def m_alias(): pass
",
    );
    // Inject a second `m` decl in a separate file so the resolver
    // sees two candidates by the same bare name.
    ws2.vfs().write(
        std::path::PathBuf::from("other.py"),
        std::sync::Arc::<str>::from("def m(): pass\ndef driver():\n    m()\n"),
    );
    for f in ws2.vfs().all_files() {
        let _ = ws2.db().decl_index(f);
    }
    let cache2 = ChainCache::new(&ws2);
    let driver = func_id(&ws2, "driver");
    let edges: Vec<_> = cache2.resolved_graph().callees_of(driver).collect();
    assert!(
        edges.iter().all(|edge| edge.precision.is_semantic()),
        "ambiguous broad resolution must not expose over-approximate edges: {edges:?}"
    );
    assert!(edges.len() <= 1, "ambiguous call fanned out: {edges:?}");
}

#[test]
fn call_span_resolution_uses_semantic_graph_edges_only() {
    let ws = ws_with_python(
        r"
class A:
    def load(self): pass

class B:
    def load(self): pass

def driver(obj):
    obj.load()
",
    );
    let global = ws.db().global_index();
    let targets = collect_callable_targets(&global, "load");
    assert!(
        targets.len() >= 2,
        "fixture must expose duplicate method candidates"
    );
    let driver = func_id(&ws, "driver");
    let caller_decl = global.decl_of(SymbolId::new(driver.raw())).expect("driver decl");
    let semantic_targets: ahash::AHashSet<_> = ws
        .resolved_call_graph()
        .callees_of(driver)
        .filter(|edge| edge.precision.is_semantic())
        .map(|edge| edge.to)
        .collect();
    let non_semantic_targets: Vec<_> = targets
        .iter()
        .copied()
        .filter(|target| !semantic_targets.contains(target))
        .collect();
    assert!(
        !non_semantic_targets.is_empty(),
        "ambiguous receiver call should leave at least one candidate without semantic edge"
    );

    let mut resolver = CallEdgeResolver::new(&ws);
    for target in non_semantic_targets {
        assert!(
            find_call_span_to_func_uncached(&ws, caller_decl, target, "load").is_none(),
            "uncached inspect resolver must not fallback to ambiguous name-only call-site evidence"
        );
        assert_eq!(
            resolver.call_spans_for_chain(&[driver, target]),
            vec![None, None],
            "cached inspect resolver must not fallback to ambiguous name-only call-site evidence"
        );
    }
}

#[test]
fn call_span_resolution_honors_query_scoped_graph() {
    let ws = ws_with_python(FIXTURE);
    let entry = func_id(&ws, "entry");
    let helper = func_id(&ws, "helper");
    assert!(
        ws.resolved_call_graph()
            .callees_of(entry)
            .all(|edge| edge.to != helper),
        "fixture workspace must not already contain the synthetic scoped edge"
    );

    let span = Span::new(ws.vfs().all_files()[0], 7, 11);
    let mut graph = bonsai_callgraph::CallGraph::new();
    graph.add_edge(bonsai_callgraph::CallEdge {
        from: entry,
        to: helper,
        span,
        kind: bonsai_callgraph::EdgeKind::Direct,
        precision: bonsai_common::Precision::Exact,
        provenance: bonsai_callgraph::EdgeProvenance::direct_symbol(),
    });
    let scoped = Arc::new(bonsai_callgraph::ResolvedCallGraph::from_call_graph(graph));
    let mut resolver = CallEdgeResolver::with_resolved_graph(&ws, scoped);

    assert_eq!(
        resolver.call_spans_for_chain(&[entry, helper]),
        vec![Some(span), None],
        "presentation must verify against the compiler corridor supplied by its query planner"
    );
}

// ---------- BoundedCache eviction tests ----------

#[test]
fn bounded_cache_respects_capacity() {
    let mut c: BoundedCache<i32, &'static str> = BoundedCache::with_capacity(3);
    c.insert(1, "a");
    c.insert(2, "b");
    c.insert(3, "c");
    assert_eq!(c.len(), 3);
    c.insert(4, "d");
    assert_eq!(c.len(), 3, "len must never exceed capacity");
    assert_eq!(c.capacity(), 3);
}

#[test]
fn bounded_cache_zero_capacity_stays_empty() {
    let mut c: BoundedCache<i32, &'static str> = BoundedCache::with_capacity(0);
    c.insert(1, "a");
    c.insert(2, "b");
    assert!(c.is_empty(), "zero-capacity cache must not retain entries");
    assert_eq!(c.capacity(), 0);
}

#[test]
fn bounded_cache_evicts_oldest_first() {
    let mut c: BoundedCache<i32, i32> = BoundedCache::with_capacity(2);
    c.insert(1, 100);
    c.insert(2, 200);
    // Inserting `3` must evict `1` (the oldest).
    c.insert(3, 300);
    assert!(c.get(&1).is_none(), "key 1 must be evicted");
    assert_eq!(c.get(&2), Some(&200));
    assert_eq!(c.get(&3), Some(&300));
}

#[test]
fn bounded_cache_overwrite_existing_doesnt_evict() {
    let mut c: BoundedCache<i32, i32> = BoundedCache::with_capacity(2);
    c.insert(1, 100);
    c.insert(2, 200);
    // Re-inserting key `1` must update the value but not evict
    // anything — we're at capacity but the key already exists.
    c.insert(1, 999);
    assert_eq!(c.len(), 2);
    assert_eq!(c.get(&1), Some(&999));
    assert_eq!(c.get(&2), Some(&200));
}

#[test]
fn bounded_cache_clear_resets() {
    let mut c: BoundedCache<i32, &'static str> = BoundedCache::with_capacity(8);
    c.insert(1, "a");
    c.insert(2, "b");
    assert!(!c.is_empty());
    c.clear();
    assert!(c.is_empty());
}

/// The headline correctness guarantee: an evicted entry must
/// recompute identically on its next access. Otherwise the bound
/// would change output, which would violate the loss-free
/// contract the cache exists to uphold.
#[test]
fn eviction_then_recompute_returns_identical_value() {
    let ws = ws_with_python(FIXTURE);
    // A cache with capacity 1 forces eviction on every new key,
    // so any second lookup of an old key is a recompute.
    let mut cache = ChainCache::new(&ws);
    // Replace the reachable map with a tightly bounded one so we
    // can observe eviction explicitly.
    cache.reachable_r = parking_lot::Mutex::new(BoundedCache::with_capacity(1));

    let entry = func_id(&ws, "entry");
    let middle = func_id(&ws, "middle");
    let sink = func_id(&ws, "sink");
    let chain_a = vec![entry, middle];
    let chain_b = vec![middle, sink];

    let first_a = cache.reachable_resolved(&chain_a);
    // This insert evicts `chain_a` from the reachable map.
    let _first_b = cache.reachable_resolved(&chain_b);
    assert_eq!(cache.reachable_r.lock().len(), 1);
    // Re-asking for `chain_a` must recompute and return an
    // identical Vec — no flow is dropped just because an eviction
    // happened in between.
    let second_a = cache.reachable_resolved(&chain_a);
    assert_eq!(
        first_a, second_a,
        "eviction-then-recompute must return byte-identical value"
    );
}

#[test]
fn small_cache_matches_large_cache_for_direct_reachability() {
    let ws = ws_with_python(FIXTURE);
    let mut tight = ChainCache::new(&ws);
    tight.reachable_r = parking_lot::Mutex::new(BoundedCache::with_capacity(1));
    let mut loose = ChainCache::new(&ws);
    loose.reachable_r = parking_lot::Mutex::new(BoundedCache::with_capacity(1024));

    for name in &["entry", "middle", "sink", "helper"] {
        let target = func_id(&ws, name);
        let t = tight.reachable_resolved(&[target]);
        let l = loose.reachable_resolved(&[target]);
        assert_eq!(t, l, "direct reachability for {name} must ignore cache size");
    }
}

#[test]
fn disabled_cache_returns_identical_values() {
    // Correctness check: results from a cache with memoization ON
    // must match results from a cache with memoization OFF for every
    // method. If these diverge, `--no-cache` is unsafe as a hatch.
    let ws = ws_with_python(FIXTURE);
    let cached = ChainCache::new(&ws);
    let uncached = ChainCache::without_cache(&ws);
    let middle = func_id(&ws, "middle");
    let entry = func_id(&ws, "entry");

    assert_eq!(
        cached.callees_of_resolved(middle),
        uncached.callees_of_resolved(middle),
        "callees_of_resolved() must match"
    );
    let chain = vec![entry, middle];
    assert_eq!(
        cached.reachable_resolved(&chain),
        uncached.reachable_resolved(&chain),
        "reachable_resolved() must match"
    );
}

// -----------------------------------------------------------------
// Phase A: flow_id hash properties
//
// flow_id is a content-addressed identifier for a rendered flow.
// It must be:
//  - deterministic across runs / hosts / processes (no random seed)
//  - collision-resistant for the differences that matter
//    (name set, order, null boundaries)
//  - formatted as "F:" + exactly 16 lower-case hex chars
// -----------------------------------------------------------------

#[test]
fn flow_id_is_deterministic() {
    // Same input bytes, run twice: must match exactly.
    let names: Vec<String> = ["handle_request", "update_user", "run_admin_command"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let a = compute_flow_id(&names);
    let b = compute_flow_id(&names);
    assert_eq!(a, b, "flow_id must be deterministic for identical inputs");
}

#[test]
fn flow_id_format_is_f_plus_16_hex() {
    let names = vec!["a".to_string(), "b".to_string()];
    let id = compute_flow_id(&names);
    assert!(id.starts_with("F:"), "flow_id must start with F:, got {id}");
    let body = &id[2..];
    assert_eq!(
        body.len(),
        16,
        "flow_id body must be exactly 16 hex chars, got {} ({id})",
        body.len()
    );
    assert!(
        body.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "flow_id body must be lower-case hex, got `{body}`"
    );
}

#[test]
fn flow_id_differs_for_different_chain_names() {
    // Changing any name in the chain must (overwhelmingly likely)
    // change the id. FNV's distribution is good enough that
    // single-byte-delta inputs never collide in our test space.
    let base = vec!["entry".to_string(), "sink".to_string()];
    let variant = vec!["entry".to_string(), "sink2".to_string()];
    assert_ne!(
        compute_flow_id(&base),
        compute_flow_id(&variant),
        "different chain names must hash to different flow_ids"
    );
}

#[test]
fn flow_id_order_matters() {
    // [A,B,C] and [C,B,A] describe different flows and must differ.
    let forward = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let reverse = vec!["c".to_string(), "b".to_string(), "a".to_string()];
    assert_ne!(
        compute_flow_id(&forward),
        compute_flow_id(&reverse),
        "chain order must affect flow_id (not a set hash)"
    );
}

#[test]
fn flow_id_null_separator_prevents_concat_collision() {
    // Without the null separator, ["ab","c"] and ["a","bc"] would
    // hash identically because the feed stream is `abc` either way.
    // The null byte between names breaks that collision.
    let a = vec!["ab".to_string(), "c".to_string()];
    let b = vec!["a".to_string(), "bc".to_string()];
    assert_ne!(
        compute_flow_id(&a),
        compute_flow_id(&b),
        "name boundaries must affect flow_id (null separator required)"
    );
}

#[test]
fn flow_id_single_name_is_stable() {
    // Degenerate case: one-element chain (a sink with no callers).
    // Must still produce a well-formed id.
    let id = compute_flow_id(&["only".to_string()]);
    assert!(id.starts_with("F:"));
    assert_eq!(id.len(), 18);
}

#[test]
fn flow_id_known_digest_is_frozen() {
    // Pin a known output so any accidental change to the hash
    // function (wrong constant, different separator, endianness,
    // etc.) trips this test immediately. If this changes, every
    // saved flow_id in user scripts / bookmarks / tests breaks.
    let names = vec![
        "handle_request".to_string(),
        "update_user".to_string(),
        "run_admin_command".to_string(),
    ];
    assert_eq!(compute_flow_id(&names), "F:84e8764cf9b99efd");
}

// -----------------------------------------------------------------
