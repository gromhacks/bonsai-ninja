//! 10-concept alignment tests for the taint engine.
//!
//! Each test pins one of the 10 fundamental properties of a fully
//! procedural taint engine:
//!
//! 1. Source model — caller-supplied seed identifiers (no built-in patterns)
//! 2. Sink model — engine reports tainted_calls; caller decides what's a sink
//! 3. Sanitizer model — engine respects sanitizer config / doesn't invent
//! 4. Call graph — A calls B, resolved across imports
//! 5. Data-flow graph — variable / field / return / argument relationships
//! 6. Module resolver — imports, exports, require(), aliases
//! 7. Context sensitivity — same function with safe vs tainted data
//! 8. Field sensitivity — obj.safe distinct from obj.dangerous
//! 9. Path sensitivity — branches don't dilute clean paths
//! 10. Summary generation — `param 0 → return`, `param 1 → sink`

// `.sink` is a test convention (`parent.sink`), not a real file extension.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use bonsai_common::{FuncId, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_taint::{interprocedural_taint, InterTaintConfig, TokenSet};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn python_db(files: &[(&str, &str)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn javascript_db(files: &[(&str, &str)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn func_id(db: &AnalyzerDb, name: &str) -> FuncId {
    let mut candidates = bonsai_resolve::resolve_callable(&db.global_index(), name);
    assert!(!candidates.is_empty(), "fixture missing function `{name}`");
    candidates.remove(0)
}

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn default_config() -> InterTaintConfig {
    InterTaintConfig::default()
}

fn touches(result: &bonsai_taint::InterTaintResult, db: &AnalyzerDb, callee_name: &str) -> bool {
    let global = db.global_index();
    result.call_records.iter().any(|r| {
        global
            .decl_of(SymbolId::new(r.callee.raw()))
            .is_some_and(|d| d.name == callee_name)
    }) || result
        .tainted_calls
        .iter()
        .any(|c| c.name == callee_name || c.name.ends_with(&format!(".{callee_name}")))
}

// -------------------------------------------------------------------------
// 1. SOURCE MODEL — caller-supplied seed identifiers; engine has no
//    built-in source patterns. Empty seed produces zero propagation.
// -------------------------------------------------------------------------

#[test]
fn concept_1_source_model_empty_seed_no_propagation() {
    let src = "
def helper(x):
    sink(x)

def entry(req):
    helper(req)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &TokenSet::default(), &default_config(), &db);
    assert!(
        result.call_records.is_empty() && result.tainted_calls.is_empty(),
        "engine must invent no taint on empty seed (engine invariant); \
         got {} call_records, {} tainted_calls",
        result.call_records.len(),
        result.tainted_calls.len(),
    );
}

#[test]
fn concept_1_source_model_explicit_seed_propagates() {
    let src = "
def helper(x):
    sink(x)

def entry(req):
    helper(req)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    assert!(
        !result.call_records.is_empty(),
        "engine must propagate when caller seeds a source identifier; got {} records",
        result.call_records.len(),
    );
}

// -------------------------------------------------------------------------
// 2. SINK MODEL — engine surfaces unresolved external calls as
//    tainted_calls. Caller's security layer decides what's actually a
//    sink; the engine never filters by name pattern.
// -------------------------------------------------------------------------

#[test]
fn concept_2_sink_model_unresolved_external_call_surfaces() {
    let src = "
def entry(req):
    db_query(req)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    // db_query is not declared in the workspace → engine reports it
    // as a tainted_calls entry, not call_records.
    let saw_db_query = result
        .tainted_calls
        .iter()
        .any(|c| c.name == "db_query" || c.name.ends_with(".db_query"));
    assert!(
        saw_db_query,
        "unresolved external call must appear in tainted_calls so the security layer can flag it; \
         tainted_calls: {:?}",
        result.tainted_calls.iter().map(|c| &c.name).collect::<Vec<_>>(),
    );
}

// -------------------------------------------------------------------------
// 3. SANITIZER MODEL — engine accepts sanitizer config but does not
//    apply it during propagation (sanitizer attribution is a security-
//    layer concern; engine over-approximates conservatively).
// -------------------------------------------------------------------------

#[test]
fn concept_3_sanitizer_model_engine_does_not_drop_taint_for_sanitized_path() {
    // Pass a "sanitizer" name in config; engine still propagates.
    // The security layer is responsible for crediting sanitizer
    // evidence on the chain; the engine itself is conservative.
    let src = "
def entry(req):
    cleaned = escape(req)
    sink(cleaned)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let mut config = default_config();
    config.sanitizers = seed(&["escape"]);
    let result = interprocedural_taint(entry, &seed(&["req"]), &config, &db);
    // Engine is conservative — sink still receives a tainted call.
    let saw_sink = result
        .tainted_calls
        .iter()
        .any(|c| c.name == "sink" || c.name.ends_with(".sink"));
    assert!(
        saw_sink,
        "engine must not pre-emptively drop taint based on sanitizer config; \
         security layer applies sanitizer attribution. tainted_calls: {:?}",
        result.tainted_calls.iter().map(|c| &c.name).collect::<Vec<_>>(),
    );
}

// -------------------------------------------------------------------------
// 4. CALL GRAPH — A calls B, B calls C; engine threads taint through
//    the chain.
// -------------------------------------------------------------------------

#[test]
fn concept_4_call_graph_three_hop_propagation() {
    let src = "
def hop_c(x):
    sink(x)

def hop_b(y):
    hop_c(y)

def hop_a(z):
    hop_b(z)

def entry(req):
    hop_a(req)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    // Each hop should appear as a call_record with the tainted arg.
    for hop in ["hop_a", "hop_b", "hop_c"] {
        assert!(
            touches(&result, &db, hop),
            "call graph must propagate through {hop}; records: {:?}",
            result
                .call_records
                .iter()
                .map(|r| (r.caller.raw(), r.callee.raw()))
                .collect::<Vec<_>>(),
        );
    }
}

// -------------------------------------------------------------------------
// 5. DATA-FLOW GRAPH — variables, fields, returns, arguments.
// -------------------------------------------------------------------------

#[test]
fn concept_5_dataflow_through_variable_field_return_argument() {
    let src = "
def copy(user):
    return {'value': user}

def build_query(obj):
    return obj['value']

def entry(req):
    data = copy(req)
    q = build_query(data)
    sink(q)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    // The chain req → copy → build_query → sink must be present in
    // call records / tainted_calls.
    assert!(touches(&result, &db, "copy"));
    assert!(touches(&result, &db, "build_query"));
    assert!(
        touches(&result, &db, "sink"),
        "full data-flow chain (variable → field → return → argument → sink) must reach sink"
    );
}

// -------------------------------------------------------------------------
// 6. MODULE RESOLVER — cross-file imports, exports, aliases.
// -------------------------------------------------------------------------

#[test]
fn concept_6_module_resolver_cross_file_import_propagates() {
    // Keep this contract focused on module resolution. A bare legacy token
    // seed intentionally does not promote every field of an object; field
    // projection semantics are covered separately by concept 8 and the
    // security rule-match seed policy.
    let input_js = "export function getName(req) { return req; }\n";
    let route_js =
        "import { getName } from './input.js';\nfunction handler(req) { dbQuery(getName(req)); }\n";
    let db = javascript_db(&[("input.js", input_js), ("route.js", route_js)]);
    let handler = func_id(&db, "handler");
    let result = interprocedural_taint(handler, &seed(&["req"]), &default_config(), &db);
    // Resolution should follow the import alias to input.js::getName,
    // so the call_records contain (handler → getName). The
    // dbQuery call (unresolved) shows up in tainted_calls.
    assert!(
        touches(&result, &db, "getName"),
        "cross-file import must resolve `getName` to input.js's impl; records: {:?}",
        result
            .call_records
            .iter()
            .map(|r| (r.caller.raw(), r.callee.raw()))
            .collect::<Vec<_>>(),
    );
    assert!(
        touches(&result, &db, "dbQuery"),
        "tainted return from cross-file getName must reach the dbQuery sink; \
         tainted_calls: {:?}",
        result.tainted_calls.iter().map(|c| &c.name).collect::<Vec<_>>(),
    );
}

// -------------------------------------------------------------------------
// 7. CONTEXT SENSITIVITY — same callee with different seeds re-runs
//    in a fresh context.
// -------------------------------------------------------------------------

#[test]
fn concept_7_context_sensitivity_same_callee_distinct_results() {
    // Same callee `helper` invoked in two callers with different
    // seeds. The engine memoizes by (FuncId, sorted-seed) so each
    // call site gets its own context.
    let src = "
def helper(x):
    sink(x)

def entry_tainted(req):
    helper(req)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry_tainted");
    let result_tainted = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    let result_clean = interprocedural_taint(entry, &TokenSet::default(), &default_config(), &db);
    assert!(
        !result_tainted.call_records.is_empty(),
        "tainted seed must produce records",
    );
    assert!(
        result_clean.call_records.is_empty(),
        "clean seed (separate context) must produce no records — engine memoization is per-seed, \
         not just per-FuncId; got {} records",
        result_clean.call_records.len(),
    );
}

// -------------------------------------------------------------------------
// 8. FIELD SENSITIVITY — engine tracks field-qualified targets so
//    `data.value` and `data.other` are distinct tokens.
// -------------------------------------------------------------------------

#[test]
fn concept_8_field_sensitivity_qualified_targets_distinct() {
    // `data['value'] = req` taints data.value; reading
    // `data['other']` (never written) must NOT taint sink(out).
    // After the per-field-granularity fix in insert_target_taint,
    // the qualified write does NOT promote the bare carrier
    // `data` to wholesale tainted, so reads of unrelated fields
    // do not match.
    let src = "
def entry(req):
    data = {}
    data['value'] = req
    out = data['other']
    sink(out)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    let saw_sink_with_tainted_arg = result.tainted_calls.iter().any(|c| {
        (c.name == "sink" || c.name.ends_with(".sink"))
            && c.tainted_args.iter().any(|arg| arg.value_text == "out")
    });
    assert!(
        !saw_sink_with_tainted_arg,
        "field-distinct read `data['other']` (never written from req) must not taint sink(out); \
         tainted_calls: {:?}",
        result
            .tainted_calls
            .iter()
            .map(|c| (
                &c.name,
                c.tainted_args.iter().map(|a| &a.value_text).collect::<Vec<_>>()
            ))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn concept_8_field_sensitivity_descendant_container_propagates() {
    // A bare object seed (`obj`) is value taint, not "every possible
    // field" taint. Wildcard field reads require explicit descendant
    // container state (`obj.*`) from a parameter/container source rule
    // or a source API that writes into a mutable container.
    let src = "
def get_input(req):
    return req

def entry(req):
    obj = get_input(req)
    sink(obj['anything'])
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req.*"]), &default_config(), &db);
    let saw_sink = result
        .tainted_calls
        .iter()
        .any(|c| c.name == "sink" || c.name.ends_with(".sink"));
    assert!(
        saw_sink,
        "explicit descendant-container taint must propagate to field reads; tainted_calls: {:?}",
        result.tainted_calls.iter().map(|c| &c.name).collect::<Vec<_>>(),
    );
}

#[test]
fn concept_8_field_sensitivity_distinct_qualified_writes_propagate_individually() {
    let src = "
def entry(req):
    obj = {}
    obj['value'] = req
    sink(obj['value'])
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    let saw_sink = result
        .tainted_calls
        .iter()
        .any(|c| c.name == "sink" || c.name.ends_with(".sink"));
    assert!(
        saw_sink,
        "qualified write `obj['value'] = req` followed by qualified read `obj['value']` \
         must propagate to sink",
    );
}

// -------------------------------------------------------------------------
// 9. PATH SENSITIVITY — branch merge semantics.
// -------------------------------------------------------------------------

#[test]
fn concept_9_path_sensitivity_branch_clean_overwrite_clears_at_merge() {
    // Both branches reassign x to a clean literal value. The
    // engine must clear x at the merge so sink(x) is NOT tainted.
    // propagate_taint_through_events clones state into each arm,
    // each arm's `x = 'clean'` Assign goes through
    // remove_target_taint, both arms produce clean state, the
    // union of two clean states is still clean.
    let src = "
def entry(req):
    x = req
    if cond():
        x = 'clean'
    else:
        x = 'clean'
    sink(x)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    let saw_sink_with_x = result.tainted_calls.iter().any(|c| {
        (c.name == "sink" || c.name.ends_with(".sink")) && c.tainted_args.iter().any(|a| a.value_text == "x")
    });
    assert!(
        !saw_sink_with_x,
        "clean-overwrite in BOTH branches must clear x at the merge; tainted_calls: {:?}",
        result
            .tainted_calls
            .iter()
            .map(|c| (
                &c.name,
                c.tainted_args.iter().map(|a| &a.value_text).collect::<Vec<_>>()
            ))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn concept_9_path_sensitivity_one_branch_keeps_taint() {
    // Only one branch leaves x tainted — engine MUST report.
    let src = "
def entry(req):
    if cond():
        x = req
    else:
        x = 'clean'
    sink(x)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    let saw_sink = result
        .tainted_calls
        .iter()
        .any(|c| c.name == "sink" || c.name.ends_with(".sink"));
    assert!(
        saw_sink,
        "branch where one arm leaves x tainted must still surface sink; tainted_calls: {:?}",
        result.tainted_calls.iter().map(|c| &c.name).collect::<Vec<_>>(),
    );
}

// -------------------------------------------------------------------------
// 10. SUMMARY GENERATION — function summaries describe param→return
//     transit so callers don't have to re-analyze the body.
// -------------------------------------------------------------------------

#[test]
fn concept_10_summary_generation_param_to_return_transits() {
    // `passthrough(p) -> p` should produce returns_taint_of: [0]
    // so a caller's `y = passthrough(tainted)` taints y without
    // re-analyzing passthrough's body.
    let src = "
def passthrough(p):
    return p

def entry(req):
    y = passthrough(req)
    sink(y)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    assert!(
        touches(&result, &db, "sink"),
        "summary should propagate param 0 → return → caller's LHS → sink",
    );
}

#[test]
fn concept_10_summary_generation_clean_helper_does_not_taint_lhs() {
    // `constant() -> "literal"` returns a constant; the summary
    // should be empty so a caller's `y = constant()` doesn't get
    // tainted from anywhere.
    let src = "
def constant():
    return 'literal'

def entry(req):
    y = constant()
    sink(y)
";
    let db = python_db(&[("a.py", src)]);
    let entry = func_id(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["req"]), &default_config(), &db);
    // sink(y) must NOT receive taint — y is bound from a constant
    // helper, the engine's summary generation must report
    // returns_taint_of: [] and the assignment transfer must clear
    // y's prior taint state.
    let saw_sink_with_taint = result
        .tainted_calls
        .iter()
        .any(|c| (c.name == "sink" || c.name.ends_with(".sink")) && !c.tainted_args.is_empty());
    assert!(
        !saw_sink_with_taint,
        "constant-returning helper must not taint sink(y); tainted_calls: {:?}",
        result.tainted_calls.iter().collect::<Vec<_>>(),
    );
}
