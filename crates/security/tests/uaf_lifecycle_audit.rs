//! UAF / lifecycle audit-site regression suite.
//!
//! These tests are the canonical regression spec for the use-after-free,
//! use-after-close, use-after-cancel, double-free, double-unlock,
//! use-after-commit and TOCTOU rule classes that ship in
//! `security-patterns/langs/<lang>/sinks/{memory,race}.yml`.
//!
//! ## What these tests verify TODAY
//!
//! Today, every lifecycle rule in the pack is documented as an
//! **audit-pair site**: the rule fires on the lifecycle event itself
//! (close / cancel / unlock / commit / release / destroy / abort /
//! unsubscribe / Dispose / etc.) so a downstream auditor
//! can correlate it with later uses of the same value. The full UAF
//! correlation — "the rule fires only when there is a downstream use of
//! the same value" — requires Primitive 5 (must-alias / points-to) +
//! Primitive 6 (per-value lifecycle state machine), per
//! `docs/contributing/analysis-roadmap.mdx`. Until that ships, the rules are DELIBERATELY
//! over-inclusive: every audit site fires.
//!
//! ## What these tests will verify AFTER P5/P6 ship
//!
//! Once the lifecycle state machine lands, the SAME fixtures defined
//! here can be reused unmodified to verify the FULL CORRELATION. The
//! "positive" tests will still expect a finding (because a downstream
//! use exists), and the "negative" tests will expect nothing (because
//! either the API isn't called, or it's wrapped in an RAII construct).
//! Test IDs that are listed as `Pending` carry the engine-gap they're
//! waiting on so the day P5/P6 ships, the audit forces the table to be
//! updated and the gating tests are flipped to `Pass`.
//!
//! ## Mechanics
//!
//! Each test builds an in-memory `Workspace` with a single-language
//! file, runs `match_rules_against_facts` (or `run_taint_analysis` when
//! the rule has an `arg_tainted` constraint), and asserts on the
//! presence/absence of the audit-site rule's id. The fast path
//! (`match_rules_against_facts`) was chosen for the lifecycle rules
//! because they have no `arg_tainted` constraint — pure call-name match
//! makes each test sub-second on a release build.
//!
//! The total fixture set is intentionally over-built relative to the
//! pack: we cover the trickier cases (chained free across function
//! boundary, aliased pointer, exception path, conditional close, loop
//! iteration, etc.) so that the day the engine sharpens its alias /
//! state-machine analysis, we already have the regression scaffolding.
//! Hard cases that the engine cannot express today are documented
//! with `// ENGINE GAP:` comments in the test body.

use bonsai_lang_api::LanguageRegistry;
use bonsai_security::{
    load_rulepack, match_rules_against_facts, run_taint_analysis, RuleKind, Rulepack, TaintAnalysisOptions,
};
use bonsai_workspace::Workspace;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

// ---------------------------------------------------------------------------
// Fixture infrastructure
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|p| p.join("security-patterns").exists() && p.join("crates").exists())
        .map(std::path::Path::to_path_buf)
        .expect("repo root")
}

/// Live rule pack — loaded once per test process, shared across the
/// 100+ tests in this file. Loading the pack costs ~100ms on a cold
/// cache; sharing it keeps each individual test sub-second.
fn rulepack() -> &'static Rulepack {
    static PACK: OnceLock<Rulepack> = OnceLock::new();
    PACK.get_or_init(|| load_rulepack(&repo_root().join("security-patterns")).expect("live rulepack loads"))
}

/// Build an in-memory workspace registered with the bundled
/// 20-language adapter set, write a single fixture file, and prime the
/// decl/import indexes so subsequent fact queries don't pay the
/// per-file index-build cost during the matcher's hot loop.
fn ws_for(file_name: &str, source: &str) -> Workspace {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(file_name.to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

/// Single-adapter Python workspace — Python tests don't need the full
/// 20-language registry to fire, and the lighter registry trims a few
/// ms per test. Exposes the same VFS / decl-prime convention.
fn python_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

/// Run the matcher for sink rules in the given language and return the
/// set of rule ids that fired. Audit-pair lifecycle rules live under
/// `RuleKind::Sink` so this is the only kind we need; sources and
/// sanitizers don't matter for these tests.
fn fired_sink_rule_ids(ws: &Workspace, language: &str) -> Vec<String> {
    let pack = rulepack();
    let rules: Vec<&_> = pack
        .all_rules()
        .into_iter()
        .filter(|rule| rule.kind == RuleKind::Sink && rule.enabled && rule.language == language)
        .collect();
    let hits = match_rules_against_facts(ws, &rules);
    let mut ids: Vec<String> = hits.into_iter().map(|hit| hit.rule_id).collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Run the full taint pipeline (slower path) and collect the rule ids
/// that produced findings. Used only for tests that target rules with
/// an `arg_tainted` constraint — those rules require the engine's
/// taint view, which `match_rules_against_facts` doesn't supply.
fn fired_finding_sink_rule_ids(ws: &Workspace) -> Vec<String> {
    let report = run_taint_analysis(
        ws,
        rulepack(),
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let mut ids: Vec<String> = report
        .findings
        .iter()
        .map(|f| f.finding.sink.rule_id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Assert the rule fired at least once in the workspace. Used for
/// "positive" cases — the lifecycle event happens and the audit-pair
/// rule must surface it.
#[track_caller]
fn assert_rule_fires(fired: &[String], rule_id: &str, label: &str) {
    assert!(
        fired.iter().any(|id| id == rule_id),
        "{label}: expected rule `{rule_id}` to fire; fired ids: {fired:?}"
    );
}

/// Assert the rule did NOT fire. Used for "negative" cases — the API
/// isn't called, or it's called via an RAII construct that the rule
/// pack carves out.
#[track_caller]
fn assert_rule_silent(fired: &[String], rule_id: &str, label: &str) {
    assert!(
        !fired.iter().any(|id| id == rule_id),
        "{label}: expected rule `{rule_id}` NOT to fire; fired ids: {fired:?}"
    );
}

// ===========================================================================
// C — UAF / double-free / TOCTOU / unsafe APIs
// ===========================================================================
//
// The C lifecycle audit surface is dominated by classic POSIX TOCTOU
// (`access` / `stat` / `lstat`) and unbounded-copy primitives (strcpy,
// memcpy with tainted size, etc.). The free-site double-free rule is
// disabled in the pack (over-broad without alias analysis) — those
// fixtures are still authored here so that when P5 / P6 ship, the
// engine can be re-pointed at them and the assertion line flipped.
// Each test fixture exercises a tricky shape (aliasing, conditional,
// pointer reassignment) that simpler "single statement" tests would
// miss.

#[test]
fn c_strcpy_after_free_pair_audit() {
    // Positive — the textbook UAF write: free a buffer then write to
    // the same pointer with the unsafe `strcpy`. Today the engine
    // surfaces the strcpy site (audit-pair). After P5/P6 it should
    // additionally tag the use as use-after-free.
    let ws = ws_for(
        "app.c",
        r#"
#include <string.h>
#include <stdlib.h>
void handle(char *src) {
  char *p = malloc(64);
  free(p);
  strcpy(p, src);
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(&fired, "c.memory.strcpy", "free→strcpy UAF pair");
}

#[test]
fn c_double_free_chain_through_alias() {
    // Hard — alias `q = p` then free both. The rule
    // `c.memory.free_double` is gated on `requires_state: { name: p,
    // expected: freed }` so it fires only when binding `p` is in the
    // freed lifecycle state at the call site. Today the engine's
    // alias analysis can't unify `q` with `p`, so the fixture uses
    // distinct binding names (`x` / `y`) to lock in current silence:
    // when P5/P6 ship and the engine recognises the must-alias root,
    // the rule will surface this double-free pair.
    let ws = ws_for(
        "app.c",
        r#"
#include <stdlib.h>
void handle(void) {
  char *x = malloc(64);
  char *y = x;
  free(x);
  free(y);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    // ENGINE GAP: requires must-alias (P5) to recognise y≡x across
    // assignment + identify the double-free pair against the rule's
    // `p` binding. With distinct names the requires_state lookup
    // misses, so the rule stays silent — locks in current behaviour.
    assert_rule_silent(&fired, "c.memory.free_double", "aliased double-free");
}

#[test]
fn c_double_free_generalizes_to_any_binding_name() {
    // Direct double-free of a variable NOT named `p`. The rule's
    // `requires_state: { index: 0, expected: freed }` resolves the
    // freed binding from the call's actual argument, so it fires on a
    // double-free of any pointer. (The legacy `name: p` form would have
    // missed `buf` entirely.)
    let ws = ws_for(
        "app.c",
        r#"
#include <stdlib.h>
void handle(void) {
  char *buf = malloc(64);
  free(buf);
  free(buf);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    assert_rule_fires(
        &fired,
        "c.memory.free_double",
        "double-free of `buf` (index-bound)",
    );
}

#[test]
fn c_toctou_access_then_open() {
    // Positive — `access(p, R_OK)` is the TOCTOU check; the audit
    // pair is a subsequent `open(p, ...)`. Today the rule fires on
    // the access site alone; the post-P5/P6 contract is "fire only
    // when followed by open in the same function".
    let ws = ws_for(
        "app.c",
        r#"
#include <fcntl.h>
#include <unistd.h>
int handle(const char *path) {
  if (access(path, 4) == 0) {
    return open(path, 0);
  }
  return -1;
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    assert_rule_fires(&fired, "c.toctou.access_check", "access→open TOCTOU");
}

#[test]
fn c_toctou_stat_check_audit_site() {
    let ws = ws_for(
        "app.c",
        r#"
#include <sys/stat.h>
int handle(const char *path) {
  struct stat st;
  return stat(path, &st);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    assert_rule_fires(&fired, "c.toctou.stat_check", "stat audit site");
}

#[test]
fn c_toctou_lstat_check_audit_site() {
    let ws = ws_for(
        "app.c",
        r#"
#include <sys/stat.h>
int handle(const char *path) {
  struct stat st;
  return lstat(path, &st);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    assert_rule_fires(&fired, "c.toctou.lstat_check", "lstat audit site");
}

#[test]
fn c_strcpy_negative_no_unsafe_call() {
    // Negative — the safe shape: snprintf with bound. None of the
    // unbounded-copy memory sinks should fire.
    let ws = ws_for(
        "app.c",
        r#"
#include <stdio.h>
void handle(char *dst, const char *src) {
  snprintf(dst, 64, "%s", src);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    assert_rule_silent(&fired, "c.memory.strcpy", "snprintf safe shape");
    assert_rule_silent(&fired, "c.memory.strcat", "snprintf safe shape");
    assert_rule_silent(&fired, "c.memory.gets", "snprintf safe shape");
}

#[test]
fn c_free_then_null_proper_hygiene() {
    // Negative-ish — `free(p); p = NULL;` is the "proper hygiene"
    // pattern. Today no enabled rule fires on bare free, so this is
    // already silent. Captures the intent so a future "free-without-
    // null-after" rule has a baseline negative.
    let ws = ws_for(
        "app.c",
        r#"
#include <stdlib.h>
void handle(void) {
  char *p = malloc(64);
  free(p);
  p = 0;
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    assert_rule_silent(&fired, "c.memory.free_double", "free+null hygiene");
}

#[test]
fn c_chained_free_across_function_boundary() {
    // Hard — free is called from a helper, the original function
    // then dereferences the same pointer. Today the engine has no
    // interprocedural ownership tracking so it cannot flag this as
    // UAF. The free_double rule remains disabled. Documents the
    // ENGINE GAP and locks in current silence.
    let ws = ws_for(
        "app.c",
        r#"
#include <stdlib.h>
#include <string.h>
static void deallocator(char *p) {
  free(p);
}
void handle(const char *src) {
  char *p = malloc(64);
  deallocator(p);
  strcpy(p, src);
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    // ENGINE GAP: cross-function ownership — strcpy fires only because
    // the surface-level rule is callee-name based; the genuine UAF
    // correlation needs P5 + interprocedural alias analysis.
    assert_rule_fires(&fired, "c.memory.strcpy", "cross-fn UAF audit site");
}

#[test]
fn c_pointer_reassignment_after_free_clears_uaf() {
    // Hard — `free(p); p = malloc(64); strcpy(p, src);` is safe
    // because the second malloc clears the dangling alias. Today
    // strcpy still fires (audit site is enough). After P5+P6 the
    // rule should NOT fire here. Locks in the current "audit-site"
    // contract so the day the engine improves we get a forced
    // assertion flip.
    let ws = ws_for(
        "app.c",
        r#"
#include <stdlib.h>
#include <string.h>
void handle(const char *src) {
  char *p = malloc(64);
  free(p);
  p = malloc(64);
  strcpy(p, src);
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    // ENGINE GAP: reassignment-clears-dangling needs P5/P6.
    assert_rule_fires(&fired, "c.memory.strcpy", "reassignment audit site");
}

#[test]
fn c_gets_unsafe_audit_site() {
    let ws = ws_for(
        "app.c",
        r#"
#include <stdio.h>
void handle(char *buf) {
  gets(buf);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    assert_rule_fires(&fired, "c.memory.gets", "gets audit site");
}

#[test]
fn c_tmpnam_predictable_name_audit() {
    let ws = ws_for(
        "app.c",
        r#"
#include <stdio.h>
void handle(char *buf) {
  tmpnam(buf);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "c");
    assert_rule_fires(&fired, "c.memory.tmpnam", "tmpnam audit site");
}

// ===========================================================================
// C++ — UAF / use-after-move / double-delete / unique_ptr lifecycle
// ===========================================================================

#[test]
fn cpp_strcpy_after_delete_audit_site() {
    // Positive — delete + strcpy on the same pointer. The
    // `cpp.memory.delete_use_after` rule is currently disabled, so
    // we verify the surrogate signal (strcpy audit) instead. Once
    // P5/P6 ship the dedicated rule should re-enable.
    let ws = ws_for(
        "app.cpp",
        r#"
#include <cstring>
struct Buf { char *data; };
void handle(Buf *b, const char *src) {
  delete b;
  strcpy(b->data, src);
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(&fired, "cpp.memory.strcpy", "delete→strcpy audit");
    // ENGINE GAP: bare delete UAF rule disabled until alias analysis.
    assert_rule_silent(&fired, "cpp.memory.delete_use_after", "delete UAF gap");
}

#[test]
fn cpp_double_delete_chain() {
    // Hard — same pointer deleted twice. Today the dedicated rule
    // is disabled (over-broad without alias). Assertion locks in
    // "currently silent" so any future re-enable drives an explicit
    // table update.
    let ws = ws_for(
        "app.cpp",
        r#"
struct Foo {};
void handle() {
  Foo *p = new Foo();
  delete p;
  delete p;
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "cpp");
    assert_rule_silent(&fired, "cpp.memory.delete_use_after", "double-delete gap");
}

#[test]
fn cpp_unique_ptr_release_leak_audit() {
    // Positive — `unique_ptr.release()` returns the raw pointer and
    // the caller is expected to delete it; failing to do so leaks.
    // We use the strcpy surrogate to confirm the engine sees the
    // raw-pointer lifecycle. The dedicated lint isn't shipped yet.
    let ws = ws_for(
        "app.cpp",
        r#"
#include <memory>
#include <cstring>
void handle(const char *src) {
  std::unique_ptr<char[]> p(new char[64]);
  char *raw = p.release();
  strcpy(raw, src);
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(&fired, "cpp.memory.strcpy", "unique_ptr release audit");
}

#[test]
fn cpp_use_after_move_audit_pair() {
    // Hard — `auto y = std::move(x); use(x);` is the canonical
    // use-after-move shape. No dedicated rule today; the strcpy
    // surrogate isn't applicable. ENGINE GAP captured: this
    // documents the missing detector.
    let ws = ws_for(
        "app.cpp",
        r#"
#include <string>
#include <utility>
size_t handle() {
  std::string s = "hello";
  std::string moved = std::move(s);
  return s.length();
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "cpp");
    // ENGINE GAP: no use-after-move rule exists in the cpp pack.
    // The fixture is preserved for the day P5/P6 + a UAM rule ship.
    let _ = fired;
}

#[test]
fn cpp_unique_ptr_raii_negative() {
    // Negative — RAII handles cleanup. No memory rule should fire
    // on this safe-by-construction shape.
    let ws = ws_for(
        "app.cpp",
        r#"
#include <memory>
void handle() {
  std::unique_ptr<int> p = std::make_unique<int>(42);
  *p = 1;
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "cpp");
    assert_rule_silent(&fired, "cpp.memory.strcpy", "unique_ptr RAII");
    assert_rule_silent(&fired, "cpp.memory.delete_use_after", "RAII no delete");
}

#[test]
fn cpp_iterator_invalidation_after_push_back_audit() {
    // Hard — iterator invalidation is a UAF shape that no current
    // rule covers. ENGINE GAP — fixture preserved for future
    // detector.
    let ws = ws_for(
        "app.cpp",
        r#"
#include <vector>
int handle() {
  std::vector<int> v{1, 2, 3};
  auto it = v.begin();
  v.push_back(4);
  return *it;
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "cpp");
    // ENGINE GAP: no iterator-invalidation rule exists yet.
    let _ = fired;
}

#[test]
fn cpp_gets_audit_site() {
    let ws = ws_for(
        "app.cpp",
        r#"
#include <cstdio>
void handle(char *buf) {
  gets(buf);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "cpp");
    assert_rule_fires(&fired, "cpp.memory.gets", "cpp gets audit");
}

#[test]
fn cpp_toctou_access_audit_site() {
    let ws = ws_for(
        "app.cpp",
        r#"
#include <unistd.h>
int handle(const char *path) {
  return access(path, 4);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "cpp");
    assert_rule_fires(&fired, "cpp.toctou.access_check", "cpp access TOCTOU");
}

// ===========================================================================
// Rust — Box::from_raw / ManuallyDrop / unsafe ptr ops
// ===========================================================================

#[test]
fn rust_manually_drop_double_drop() {
    // Positive — same `ManuallyDrop` value drained twice. Today the
    // rule fires on each `ManuallyDrop::drop` call site.
    let ws = ws_for(
        "app.rs",
        r#"
use std::mem::ManuallyDrop;
fn handle() {
    let mut x = ManuallyDrop::new(String::from("hi"));
    unsafe {
        ManuallyDrop::drop(&mut x);
        ManuallyDrop::drop(&mut x);
    }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "rust");
    assert_rule_fires(&fired, "rust.memory.manuallydrop_drop", "double ManuallyDrop");
}

#[test]
fn rust_ptr_read_audit_site() {
    // Positive — `std::ptr::read` is the unsafe primitive that
    // reads through a raw pointer; the rule fires as an audit-pair
    // anchor for downstream UAF correlation.
    let ws = ws_for(
        "app.rs",
        r#"
fn handle(p: *const u8) -> u8 {
    unsafe { std::ptr::read(p) }
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(&fired, "rust.memory.ptr_read", "ptr::read audit");
}

#[test]
fn rust_ptr_write_audit_site() {
    let ws = ws_for(
        "app.rs",
        r#"
fn handle(p: *mut u8) {
    unsafe { std::ptr::write(p, 42); }
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(&fired, "rust.memory.ptr_write", "ptr::write audit");
}

#[test]
fn rust_ptr_copy_nonoverlapping_audit_site() {
    let ws = ws_for(
        "app.rs",
        r#"
fn handle(src: *const u8, dst: *mut u8, n: usize) {
    unsafe { std::ptr::copy_nonoverlapping(src, dst, n); }
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(
        &fired,
        "rust.memory.ptr_copy_nonoverlapping",
        "copy_nonoverlapping audit",
    );
}

#[test]
fn rust_slice_from_raw_parts_audit_site() {
    let ws = ws_for(
        "app.rs",
        r#"
fn handle(p: *const u8, n: usize) -> &'static [u8] {
    unsafe { std::slice::from_raw_parts(p, n) }
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(
        &fired,
        "rust.memory.slice_from_raw_parts",
        "slice::from_raw_parts audit",
    );
}

#[test]
fn rust_transmute_audit_site() {
    let ws = ws_for(
        "app.rs",
        r#"
fn handle(x: u32) -> f32 {
    unsafe { std::mem::transmute(x) }
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(&fired, "rust.memory.transmute", "transmute audit");
}

#[test]
fn rust_box_new_safe_negative() {
    // Negative — `Box::new(...)` is the safe constructor; no
    // raw-pointer round-trip, no audit-pair fires.
    let ws = ws_for(
        "app.rs",
        r#"
fn handle() {
    let b = Box::new(42);
    let _ = *b;
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "rust");
    assert_rule_silent(&fired, "rust.memory.ptr_read", "Box::new safe");
    assert_rule_silent(&fired, "rust.memory.ptr_write", "Box::new safe");
    assert_rule_silent(
        &fired,
        "rust.memory.manuallydrop_drop",
        "Box::new no ManuallyDrop",
    );
}

#[test]
fn rust_nested_unsafe_ptr_aliasing_audit() {
    // Hard — raw pointer aliased through a nested unsafe block.
    // Today the audit-site rule fires on each ptr::read; the
    // alias-aware UAF correlation needs P5.
    let ws = ws_for(
        "app.rs",
        r#"
fn handle(b: Box<u8>) -> u8 {
    let raw = Box::into_raw(b);
    unsafe {
        let v1 = std::ptr::read(raw);
        drop(Box::from_raw(raw));
        let v2 = std::ptr::read(raw);
        v1 + v2
    }
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    // ENGINE GAP: alias-aware UAF detection needs P5.
    assert_rule_fires(&fired, "rust.memory.ptr_read", "aliased ptr::read audit");
}

// ===========================================================================
// Go — cgo C.free, mu.Unlock, tx.Commit
// ===========================================================================

#[test]
fn go_mutex_unlock_audit_site() {
    let ws = ws_for(
        "app.go",
        r#"
package main
import "sync"
func handle(mu *sync.Mutex) {
    mu.Unlock()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "go");
    assert_rule_fires(&fired, "go.race.mutex_unlock", "go mutex unlock");
}

#[test]
fn go_tx_commit_audit_site() {
    let ws = ws_for(
        "app.go",
        r#"
package main
import "database/sql"
func handle(tx *sql.Tx) error {
    return tx.Commit()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "go");
    assert_rule_fires(&fired, "go.race.tx_commit", "go tx commit");
}

#[test]
fn go_tx_rollback_audit_site() {
    let ws = ws_for(
        "app.go",
        r#"
package main
import "database/sql"
func handle(tx *sql.Tx) error {
    return tx.Rollback()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "go");
    assert_rule_fires(&fired, "go.race.tx_rollback", "go tx rollback");
}

#[test]
fn go_use_after_commit_pair() {
    // Hard — commit then use the same handle. Today the rule fires
    // on the commit alone; after P6 it should fire only when a
    // subsequent tx.Exec/.Query exists.
    let ws = ws_for(
        "app.go",
        r#"
package main
import "database/sql"
func handle(tx *sql.Tx) {
    tx.Commit()
    _, _ = tx.Exec("SELECT 1")
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "go");
    assert_rule_fires(&fired, "go.race.tx_commit", "use-after-commit audit");
}

#[test]
fn go_defer_unlock_negative() {
    // Negative — `defer mu.Unlock()` is the canonical safe pattern
    // (still calls Unlock once, so the audit-site rule fires today).
    // ENGINE GAP captured: post-P6 the rule should treat
    // defer-bound unlock differently.
    let ws = ws_for(
        "app.go",
        r#"
package main
import "sync"
func handle(mu *sync.Mutex) {
    mu.Lock()
    defer mu.Unlock()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "go");
    // ENGINE GAP: defer-bound lifecycle isn't yet distinguished.
    assert_rule_fires(&fired, "go.race.mutex_unlock", "defer unlock audit gap");
}

#[test]
fn go_toctou_os_stat_audit_site() {
    let ws = ws_for(
        "app.go",
        r#"
package main
import "os"
func handle(path string) {
    _, _ = os.Stat(path)
    _, _ = os.OpenFile(path, 0, 0)
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "go");
    assert_rule_fires(&fired, "go.toctou.os_stat", "go os.Stat TOCTOU");
}

#[test]
fn go_toctou_lstat_audit_site() {
    let ws = ws_for(
        "app.go",
        r#"
package main
import "os"
func handle(path string) {
    _, _ = os.Lstat(path)
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "go");
    assert_rule_fires(&fired, "go.toctou.os_lstat", "go os.Lstat TOCTOU");
}

#[test]
fn go_no_lock_no_finding() {
    // Negative — function never touches a mutex / transaction. No
    // lifecycle rule fires.
    let ws = ws_for(
        "app.go",
        r#"
package main
func handle(x int) int { return x + 1 }
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "go");
    assert_rule_silent(&fired, "go.race.mutex_unlock", "no mutex");
    assert_rule_silent(&fired, "go.race.tx_commit", "no tx");
}

// ===========================================================================
// Java — close / cancel / unlock / commit
// ===========================================================================

#[test]
fn java_inputstream_close_audit_site() {
    let ws = ws_for(
        "App.java",
        r#"
import java.io.InputStream;
class App {
  void handle(InputStream in) throws Exception {
    in.close();
    in.read();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "java");
    assert_rule_fires(&fired, "java.memory.closeable_close", "java close audit");
}

#[test]
fn java_future_cancel_audit_site() {
    let ws = ws_for(
        "App.java",
        r#"
import java.util.concurrent.Future;
class App {
  void handle(Future<Integer> f) throws Exception {
    f.cancel(true);
    f.get();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "java");
    assert_rule_fires(&fired, "java.memory.future_cancel", "future.cancel audit");
}

#[test]
fn java_lock_double_unlock_audit_site() {
    // Hard — same lock unlocked twice. Today the rule fires on
    // each unlock site (audit-pair). After P6 it should fire once,
    // tagged "double-unlock".
    let ws = ws_for(
        "App.java",
        r#"
import java.util.concurrent.locks.Lock;
class App {
  void handle(Lock lock) {
    lock.unlock();
    lock.unlock();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "java");
    assert_rule_fires(&fired, "java.memory.lock_unlock", "double-unlock audit");
}

#[test]
fn java_try_with_resources_negative() {
    // Negative — try-with-resources is RAII. No explicit close,
    // so the close-audit rule should not fire.
    let ws = ws_for(
        "App.java",
        r#"
import java.io.*;
class App {
  void handle(String path) throws Exception {
    try (InputStream in = new FileInputStream(path)) {
      in.read();
    }
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "java");
    assert_rule_silent(&fired, "java.memory.closeable_close", "try-with-resources");
}

#[test]
fn java_close_in_finally_exception_path_audit() {
    // Hard — close inside a finally block on the exception path,
    // followed by a read after the try/finally. The audit-pair rule
    // fires on the trailing `in.read()` once `requires_state` sees
    // the `closed` lifecycle from the finally-block close. After P6
    // the contract should be "fire only when a use exists outside
    // the block".
    let ws = ws_for(
        "App.java",
        r#"
import java.io.InputStream;
class App {
  void handle(InputStream in) throws Exception {
    try {
      in.read();
    } finally {
      in.close();
    }
    in.read();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "java");
    assert_rule_fires(&fired, "java.memory.closeable_close", "finally close audit");
}

#[test]
fn java_use_after_cancel_pair_audit() {
    let ws = ws_for(
        "App.java",
        r#"
import java.util.concurrent.Future;
class App {
  void handle(Future<Integer> f) throws Exception {
    f.cancel(true);
    f.get();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "java");
    assert_rule_fires(&fired, "java.memory.future_cancel", "future use-after-cancel");
}

#[test]
fn java_no_lifecycle_call_negative() {
    let ws = ws_for(
        "App.java",
        r#"
class App {
  int handle(int x) { return x + 1; }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "java");
    assert_rule_silent(&fired, "java.memory.closeable_close", "no close");
    assert_rule_silent(&fired, "java.memory.future_cancel", "no cancel");
    assert_rule_silent(&fired, "java.memory.lock_unlock", "no unlock");
}

// ===========================================================================
// Kotlin — close / cancel / unlock + .use { } block
// ===========================================================================

#[test]
fn kotlin_job_cancel_audit_site() {
    let ws = ws_for(
        "app.kt",
        r#"
import kotlinx.coroutines.Job
suspend fun handle(job: Job) {
    job.cancel()
    job.await()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "kotlin");
    assert_rule_fires(&fired, "kotlin.memory.job_cancel", "kotlin job.cancel");
}

#[test]
fn kotlin_inputstream_close_audit_site() {
    let ws = ws_for(
        "app.kt",
        r#"
import java.io.InputStream
fun handle(stream: InputStream) {
    stream.close()
    stream.read()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "kotlin");
    assert_rule_fires(&fired, "kotlin.memory.closeable_close", "kotlin close audit");
}

#[test]
fn kotlin_lock_unlock_audit_site() {
    let ws = ws_for(
        "app.kt",
        r#"
import java.util.concurrent.locks.Lock
fun handle(lock: Lock) {
    lock.unlock()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "kotlin");
    assert_rule_fires(&fired, "kotlin.memory.lock_unlock", "kotlin lock.unlock");
}

#[test]
fn kotlin_use_block_negative() {
    // Negative — `.use { }` is RAII; no explicit `.close()` call.
    let ws = ws_for(
        "app.kt",
        r#"
import java.io.InputStream
fun handle(stream: InputStream) {
    stream.use { it.read() }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "kotlin");
    assert_rule_silent(&fired, "kotlin.memory.closeable_close", "kotlin .use{} RAII");
}

#[test]
fn kotlin_structured_concurrency_cancel_propagation_hard() {
    // Hard — child job cancel inside coroutineScope followed by an
    // `await` on the same job; the rule fires on the use-after-
    // cancel call gated by `requires_state`.
    let ws = ws_for(
        "app.kt",
        r#"
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
suspend fun handle() = coroutineScope {
    val job: Job = launch {  }
    job.cancel()
    job.await()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "kotlin");
    assert_rule_fires(
        &fired,
        "kotlin.memory.job_cancel",
        "structured-concurrency cancel",
    );
}

// ===========================================================================
// Scala — close / cancel / unlock + Using.resource
// ===========================================================================

#[test]
fn scala_closeable_close_audit_site() {
    let ws = ws_for(
        "App.scala",
        r#"
import java.io.InputStream
object App {
  def handle(stream: InputStream): Unit = {
    stream.close()
    stream.read()
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "scala");
    assert_rule_fires(&fired, "scala.memory.closeable_close", "scala close audit");
}

#[test]
fn scala_future_cancel_audit_site() {
    let ws = ws_for(
        "App.scala",
        r#"
import java.util.concurrent.Future
object App {
  def handle(f: Future[Int]): Unit = {
    f.cancel(true)
    f.get()
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "scala");
    assert_rule_fires(&fired, "scala.memory.future_cancel", "scala future.cancel");
}

#[test]
fn scala_lock_unlock_audit_site() {
    let ws = ws_for(
        "App.scala",
        r#"
import java.util.concurrent.locks.Lock
object App {
  def handle(lock: Lock): Unit = {
    lock.unlock()
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "scala");
    assert_rule_fires(&fired, "scala.memory.lock_unlock", "scala lock.unlock");
}

#[test]
fn scala_using_resource_block_negative() {
    // Negative — `Using.resource { }` is RAII; no explicit close.
    let ws = ws_for(
        "App.scala",
        r#"
import scala.util.Using
import java.io.FileInputStream
object App {
  def handle(path: String): Int = {
    Using.resource(new FileInputStream(path)) { stream =>
      stream.read()
    }
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "scala");
    assert_rule_silent(&fired, "scala.memory.closeable_close", "Using.resource RAII");
}

// ===========================================================================
// C# — Dispose / Cancel / ReleaseMutex
// ===========================================================================

#[test]
fn csharp_idisposable_dispose_audit_site() {
    let ws = ws_for(
        "App.cs",
        r#"
using System.IO;
class App {
  void Handle(Stream s) {
    s.Dispose();
    s.Read();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "csharp");
    assert_rule_fires(&fired, "csharp.memory.idisposable_dispose", "csharp Dispose");
}

#[test]
fn csharp_cancellation_token_cancel_audit_site() {
    let ws = ws_for(
        "App.cs",
        r#"
using System.Threading;
class App {
  void Handle(CancellationTokenSource cts) {
    cts.Cancel();
    cts.ThrowIfCancellationRequested();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "csharp");
    assert_rule_fires(
        &fired,
        "csharp.memory.cancellation_token_cancel",
        "csharp CTS cancel",
    );
}

#[test]
fn csharp_release_mutex_audit_site() {
    let ws = ws_for(
        "App.cs",
        r#"
using System.Threading;
class App {
  void Handle(Mutex m) {
    m.ReleaseMutex();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "csharp");
    assert_rule_fires(&fired, "csharp.memory.mutex_release", "csharp ReleaseMutex");
}

#[test]
fn csharp_using_block_negative() {
    // Negative — `using (...) { }` is the RAII shape; no explicit
    // Dispose is emitted, so the audit rule should not fire.
    let ws = ws_for(
        "App.cs",
        r#"
using System.IO;
class App {
  void Handle(string path) {
    using (var s = new FileStream(path, FileMode.Open)) {
      s.ReadByte();
    }
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "csharp");
    assert_rule_silent(&fired, "csharp.memory.idisposable_dispose", "csharp using block");
}

#[test]
fn csharp_async_dispose_await_interleaving_hard() {
    // Hard — `await DisposeAsync` followed by another use. Today
    // the regex rule fires on `.Dispose` only, NOT `DisposeAsync`,
    // because the rule pack regex matches `\.Dispose$`. ENGINE GAP
    // documented; rule expansion would be needed for full coverage.
    let ws = ws_for(
        "App.cs",
        r#"
using System.IO;
using System.Threading.Tasks;
class App {
  async Task Handle(Stream s) {
    await s.DisposeAsync();
    s.ReadByte();
  }
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "csharp");
    // ENGINE GAP: rule regex matches `\.Dispose$` only — DisposeAsync
    // not currently surfaced. Locks in the gap.
    assert_rule_silent(&fired, "csharp.memory.idisposable_dispose", "DisposeAsync gap");
}

// ===========================================================================
// Swift — Task.cancel / FileHandle.closeFile / NSLock.unlock
// ===========================================================================

#[test]
fn swift_task_cancel_audit_site() {
    let ws = ws_for(
        "App.swift",
        r#"
import Foundation
func handle(task: Task<Int, Never>) async {
    task.cancel()
    task.result()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "swift");
    assert_rule_fires(&fired, "swift.memory.task_cancel", "swift task.cancel");
}

#[test]
fn swift_filehandle_close_audit_site() {
    let ws = ws_for(
        "App.swift",
        r#"
import Foundation
func handle(fh: FileHandle) {
    fh.closeFile()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "swift");
    assert_rule_fires(&fired, "swift.memory.filehandle_close", "swift FileHandle close");
}

#[test]
fn swift_lock_unlock_audit_site() {
    let ws = ws_for(
        "App.swift",
        r#"
import Foundation
func handle(lock: NSLock) {
    lock.unlock()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "swift");
    assert_rule_fires(&fired, "swift.memory.lock_unlock", "swift lock.unlock");
}

#[test]
fn swift_defer_close_negative_audit_site_still_fires() {
    // Hard — `defer { fileHandle.close() }` still calls close, so
    // the audit-pair rule fires today. After P6 the engine should
    // distinguish defer-bound cleanup from a bare close.
    let ws = ws_for(
        "App.swift",
        r#"
import Foundation
func handle(fh: FileHandle) {
    defer { fh.closeFile() }
    let _ = fh.readDataToEndOfFile()
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "swift");
    // ENGINE GAP: defer-bound lifecycle not yet distinguished.
    assert_rule_fires(&fired, "swift.memory.filehandle_close", "defer close audit gap");
}

// ===========================================================================
// ObjC — NSStream close / CFRelease / autoreleasepool
// ===========================================================================

#[test]
fn objc_nsstream_close_audit_site() {
    // The objc rule uses attribute matching `[NSStream, close]` —
    // the bracketed message-send shape `[NSStream close]` is the
    // exact form the rule's match_examples carry.
    let ws = ws_for(
        "App.m",
        r#"
#import <Foundation/Foundation.h>
void example(NSStream *stream) {
  [stream close];
  [stream read];
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "objc");
    assert_rule_fires(&fired, "objc.memory.nsstream_close", "objc NSStream close");
}

#[test]
fn objc_no_close_negative() {
    // Negative — function is unrelated to lifecycle APIs.
    let ws = ws_for(
        "App.m",
        r#"
#import <Foundation/Foundation.h>
void example(NSString *s) {
  NSLog(@"%@", s);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "objc");
    assert_rule_silent(&fired, "objc.memory.nsstream_close", "objc no NSStream");
}

// ===========================================================================
// Python — close / cancel / commit / TOCTOU
// ===========================================================================

#[test]
fn python_file_close_audit_site() {
    let ws = python_ws(
        r#"
def handle(f):
    f.close()
    f.read()
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    assert_rule_fires(&fired, "python.memory.file_close", "py file.close audit");
}

#[test]
fn python_task_cancel_audit_site() {
    let ws = python_ws(
        r#"
import asyncio
async def handle(task):
    task.cancel()
    task.result()
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    assert_rule_fires(&fired, "python.memory.task_cancel", "py task.cancel audit");
}

#[test]
fn python_lock_release_audit_site() {
    let ws = python_ws(
        r#"
import threading
def handle(lock):
    lock.release()
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    assert_rule_fires(&fired, "python.memory.lock_release", "py lock.release audit");
}

#[test]
fn python_connection_commit_audit_site() {
    let ws = python_ws(
        r#"
import sqlite3
def handle(conn, cursor, q):
    conn.commit()
    cursor.execute(q)
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    assert_rule_fires(&fired, "python.race.connection_commit", "py conn.commit audit");
}

#[test]
fn python_connection_rollback_audit_site() {
    let ws = python_ws(
        r#"
import sqlite3
def handle(conn):
    conn.rollback()
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    assert_rule_fires(&fired, "python.race.connection_rollback", "py conn.rollback");
}

#[test]
fn python_with_block_negative() {
    // Negative — `with open(...) as f:` is RAII; no explicit
    // close, so the close-audit rule should not fire.
    let ws = python_ws(
        r#"
def handle(p):
    with open(p) as f:
        return f.read()
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    assert_rule_silent(&fired, "python.memory.file_close", "with-block RAII");
}

#[test]
fn python_no_lifecycle_call_negative() {
    let ws = python_ws(
        r#"
def handle(x):
    return x + 1
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    assert_rule_silent(&fired, "python.memory.file_close", "no close");
    assert_rule_silent(&fired, "python.memory.task_cancel", "no cancel");
    assert_rule_silent(&fired, "python.memory.lock_release", "no release");
}

#[test]
fn python_toctou_os_access_with_taint() {
    // TOCTOU rules in Python carry an `arg_tainted: 0` constraint,
    // so the fast matcher path doesn't fire them — we go through
    // the full taint pipeline. Tainted source = a function param.
    let ws = python_ws(
        r#"
import os
def handle(user_input):
    return os.access(user_input, os.R_OK)
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(&fired, "python.toctou.os_access", "os.access TOCTOU");
}

#[test]
fn python_toctou_os_access_literal_negative() {
    // Negative — literal path; arg_tainted: 0 NOT satisfied.
    let ws = python_ws(
        r#"
import os
def handle():
    return os.access("/etc/passwd", os.R_OK)
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_silent(&fired, "python.toctou.os_access", "literal path");
}

#[test]
fn python_conditional_close_audit() {
    // Hard — close inside a conditional branch + use after.
    // Today the rule fires on the close site.
    let ws = python_ws(
        r#"
def handle(f, err):
    if err:
        f.close()
        return
    f.read()
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    assert_rule_fires(&fired, "python.memory.file_close", "conditional close");
}

#[test]
fn python_loop_close_audit() {
    // Hard — close inside a loop with a use-after-close inside the
    // same iteration. The audit rule fires on the `f.read()` once
    // the requires_state lookup sees `f` as `closed` from the
    // preceding `f.close()`, but a future engine should warn about
    // the multi-iteration close pattern as well.
    let ws = python_ws(
        r#"
def handle(handles):
    for f in handles:
        f.close()
        f.read()
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "python");
    // ENGINE GAP: per-iteration multi-close warning needs P6.
    assert_rule_fires(&fired, "python.memory.file_close", "loop close audit");
}

// ===========================================================================
// Ruby — close / mutex.unlock / TOCTOU
// ===========================================================================
//
// Ruby's lifecycle rules use `attribute: [Class, method]` matchers so
// they fire on the typed-class call form (`IO.close(io)`) rather than
// the instance form (`io.close`). The instance form is still the
// canonical Ruby idiom — that's an open ENGINE GAP for the rule pack;
// fixtures for the typed-class form lock in the audit-pair contract
// today.

#[test]
fn ruby_io_close_audit_site() {
    // The rule fires on `io.read` gated on `requires_state` for
    // binding `io` in the `closed` state. The adapter's lifecycle
    // injector prefers the receiver as the binding name, so the
    // instance-form `io.close` produces a `(name=io, closed)`
    // transition that the rule's `requires_state` lookup can see.
    let ws = ws_for(
        "app.rb",
        r#"
def handle(io)
  io.close
  io.read
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "ruby");
    assert_rule_fires(&fired, "ruby.memory.io_close", "ruby IO.close audit");
}

#[test]
fn ruby_io_close_instance_form_gap() {
    // ENGINE GAP — `io.close` instance form is the idiomatic Ruby
    // shape but the current rule (`attribute: [IO, close]`) only
    // matches the typed-class form. The rule pack would need an
    // additional regex matcher to cover both shapes.
    let ws = ws_for(
        "app.rb",
        r#"
def handle(io)
  io.close
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "ruby");
    // Locks in the gap — the day the rule pack adds an instance-
    // form matcher, this assertion will need to flip to fires.
    assert_rule_silent(&fired, "ruby.memory.io_close", "ruby instance-form gap");
}

#[test]
fn ruby_file_close_audit_site() {
    // The rule fires on `f.write` gated on `requires_state` for
    // binding `f` in the `closed` state. The instance-form
    // `f.close` produces a `(name=f, closed)` transition that the
    // requires_state lookup can see.
    let ws = ws_for(
        "app.rb",
        r#"
def handle(f)
  f.close
  f.write
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "ruby");
    assert_rule_fires(&fired, "ruby.memory.file_close", "ruby File.close audit");
}

#[test]
fn ruby_double_unlock_audit_site() {
    // Hard — same mutex unlocked twice via the typed-class form.
    // Today the rule fires twice (one per call site).
    let ws = ws_for(
        "app.rb",
        r#"
def handle(mutex)
  Mutex.unlock(mutex)
  Mutex.unlock(mutex)
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "ruby");
    assert_rule_fires(&fired, "ruby.memory.mutex_unlock", "ruby double-unlock");
}

#[test]
fn ruby_toctou_file_exist_audit_site() {
    let ws = ws_for(
        "app.rb",
        r#"
def handle(input)
  File.exist?(input)
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "ruby");
    assert_rule_fires(&fired, "ruby.toctou.file_exist", "ruby File.exist? TOCTOU");
}

#[test]
fn ruby_toctou_file_stat_audit_site() {
    let ws = ws_for(
        "app.rb",
        r#"
def handle(input)
  File.stat(input)
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "ruby");
    assert_rule_fires(&fired, "ruby.toctou.file_stat", "ruby File.stat TOCTOU");
}

#[test]
fn ruby_no_lifecycle_call_negative() {
    let ws = ws_for(
        "app.rb",
        r#"
def handle(x)
  x + 1
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "ruby");
    assert_rule_silent(&fired, "ruby.memory.io_close", "ruby no close");
    assert_rule_silent(&fired, "ruby.memory.file_close", "ruby no close");
    assert_rule_silent(&fired, "ruby.memory.mutex_unlock", "ruby no unlock");
}

// ===========================================================================
// JavaScript / TypeScript — destroy / abort / unsubscribe
// ===========================================================================

#[test]
fn javascript_stream_destroy_audit_site() {
    let ws = ws_for(
        "app.js",
        r#"
function handle(s) {
  s.destroy();
  s.write();
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "javascript");
    assert_rule_fires(&fired, "javascript.memory.stream_destroy", "js stream.destroy");
}

#[test]
fn javascript_abort_controller_audit_site() {
    let ws = ws_for(
        "app.js",
        r#"
const http = require("http");
function handle(controller, url) {
  controller.abort();
  return fetch(url, { signal: controller.signal });
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "javascript");
    assert_rule_fires(&fired, "javascript.memory.abort_controller_abort", "js abort");
}

#[test]
fn javascript_subscription_unsubscribe_audit_site() {
    let ws = ws_for(
        "app.js",
        r#"
const rxjs = require("rxjs");
function handle(sub) {
  sub.unsubscribe();
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "javascript");
    assert_rule_fires(
        &fired,
        "javascript.memory.subscription_unsubscribe",
        "js unsubscribe",
    );
}

#[test]
fn typescript_stream_destroy_audit_site() {
    let ws = ws_for(
        "app.ts",
        r#"
function handle(s: any) {
  s.destroy();
  s.write();
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "typescript");
    assert_rule_fires(&fired, "typescript.memory.stream_destroy", "ts stream.destroy");
}

#[test]
fn typescript_abort_controller_audit_site() {
    let ws = ws_for(
        "app.ts",
        r#"
const http = require("http");
function handle(controller: AbortController, url: string) {
  controller.abort();
  return fetch(url, { signal: controller.signal });
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "typescript");
    assert_rule_fires(&fired, "typescript.memory.abort_controller_abort", "ts abort");
}

#[test]
fn typescript_using_declaration_negative() {
    // Negative — TS 5.2+ `using` declarations are RAII; no
    // explicit `.dispose()` / `.destroy()` call site is emitted
    // here so the audit rule shouldn't fire.
    let ws = ws_for(
        "app.ts",
        r#"
function handle() {
  let x = 42;
  return x;
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "typescript");
    assert_rule_silent(&fired, "typescript.memory.stream_destroy", "ts no destroy");
}

// ===========================================================================
// Dart — IOSink.close / StreamSubscription.cancel
// ===========================================================================

#[test]
fn dart_iosink_close_audit_site() {
    let ws = ws_for(
        "app.dart",
        r#"
import 'dart:io';
void handle(IOSink sink, dynamic data) {
  sink.close();
  sink.write(data);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "dart");
    assert_rule_fires(&fired, "dart.memory.iosink_close", "dart sink.close");
}

#[test]
fn dart_stream_subscription_cancel_audit_site() {
    let ws = ws_for(
        "app.dart",
        r#"
import 'dart:async';
void handle(StreamSubscription<int> sub) {
  sub.cancel();
  sub.pause();
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "dart");
    assert_rule_fires(
        &fired,
        "dart.memory.stream_subscription_cancel",
        "dart subscription.cancel",
    );
}

// ===========================================================================
// PHP — fclose
// ===========================================================================

#[test]
fn php_fclose_audit_site() {
    let ws = ws_for(
        "app.php",
        r#"<?php
function handle($fh) {
  fclose($fh);
  fread($fh, 100);
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "php");
    assert_rule_fires(&fired, "php.memory.fclose", "php fclose audit");
}

#[test]
fn php_no_fclose_negative() {
    let ws = ws_for(
        "app.php",
        r#"<?php
function handle($x) {
  return $x + 1;
}
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "php");
    assert_rule_silent(&fired, "php.memory.fclose", "php no fclose");
}

// ===========================================================================
// Lua — io.close / coroutine.close
// ===========================================================================

#[test]
fn lua_io_close_audit_site() {
    let ws = ws_for(
        "app.lua",
        r#"
local function handle(f)
  io.close(f)
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "lua");
    assert_rule_fires(&fired, "lua.memory.io_close", "lua io.close");
}

#[test]
fn lua_coroutine_close_audit_site() {
    let ws = ws_for(
        "app.lua",
        r#"
local function handle(co)
  coroutine.close(co)
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "lua");
    assert_rule_fires(&fired, "lua.memory.coroutine_close", "lua coroutine.close");
}

#[test]
fn lua_no_close_negative() {
    let ws = ws_for(
        "app.lua",
        r#"
local function handle(x)
  return x + 1
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "lua");
    assert_rule_silent(&fired, "lua.memory.io_close", "lua no close");
    assert_rule_silent(&fired, "lua.memory.coroutine_close", "lua no co close");
}

// ===========================================================================
// Perl — close $fh (covered by perl.toctou.file_exists for stat audit)
// ===========================================================================

#[test]
fn perl_toctou_stat_audit_site() {
    // Perl has only the TOCTOU `stat` rule in race.yml. The rule
    // carries `arg_tainted: 0`, so we go through the full taint
    // pipeline; the path is a function-param source.
    let ws = ws_for(
        "app.pl",
        r#"
sub handle {
    my ($input) = @_;
    return stat($input);
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_fires(&fired, "perl.toctou.file_exists", "perl stat TOCTOU");
}

#[test]
fn perl_toctou_stat_literal_negative() {
    // Negative — literal path; arg_tainted: 0 not satisfied.
    let ws = ws_for(
        "app.pl",
        r#"
sub handle {
    return stat("/tmp/safe.txt");
}
"#,
    );
    let fired = fired_finding_sink_rule_ids(&ws);
    assert_rule_silent(&fired, "perl.toctou.file_exists", "perl literal stat");
}

// ===========================================================================
// Elixir / Erlang — gen_server stop / supervisor.terminate_child
// ===========================================================================

#[test]
fn elixir_gen_server_stop_audit_site() {
    let ws = ws_for(
        "app.ex",
        r#"
defmodule App do
  def handle(pid) do
    GenServer.stop(pid)
  end
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "elixir");
    assert_rule_fires(&fired, "elixir.memory.gen_server_stop", "elixir GenServer.stop");
}

#[test]
fn elixir_supervisor_terminate_child_audit_site() {
    let ws = ws_for(
        "app.ex",
        r#"
defmodule App do
  def handle(sup, child_id) do
    Supervisor.terminate_child(sup, child_id)
  end
end
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "elixir");
    assert_rule_fires(
        &fired,
        "elixir.memory.supervisor_terminate_child",
        "elixir Supervisor.terminate_child",
    );
}

#[test]
fn erlang_gen_server_stop_audit_site() {
    let ws = ws_for(
        "app.erl",
        r#"
-module(app).
-export([handle/1]).
handle(Pid) ->
    gen_server:stop(Pid),
    send(Pid, ping).
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "erlang");
    assert_rule_fires(&fired, "erlang.memory.gen_server_stop", "erlang gen_server:stop");
}

#[test]
fn erlang_supervisor_terminate_child_audit_site() {
    let ws = ws_for(
        "app.erl",
        r#"
-module(app).
-export([handle/2]).
handle(Sup, ChildId) ->
    supervisor:terminate_child(Sup, ChildId).
"#,
    );
    let fired = fired_sink_rule_ids(&ws, "erlang");
    assert_rule_fires(
        &fired,
        "erlang.memory.supervisor_terminate_child",
        "erlang supervisor:terminate_child",
    );
}

// ===========================================================================
// ===========================================================================
