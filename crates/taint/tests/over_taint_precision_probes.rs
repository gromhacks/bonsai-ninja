//! Precision probes that complement `over_taint_per_language.rs` and
//! `over_taint_matrix.rs`. These cases target subtle over-taint
//! surfaces:
//!
//! * Attribute-syntax field-distinct reads (`obj.cmd = x; sink(obj.user)`).
//!   `transfer.rs::bridge_read` falls back to the base writer when a
//!   field-distinct read has no explicit writer; this probe verifies
//!   the fallback doesn't surface as a sink-arg false positive.
//! * Cross-method field-distinct writes/reads through the same class
//!   instance — `stitch_receiver_field_flow` is keyed by canonical
//!   field name, so writers and readers of distinct fields must NOT
//!   be paired.
//! * Unrelated class with the same method name — `B.process` is the
//!   only call target, so `A.process`'s sink must not light up.
//! * Super-chain bridging — `Derived.run → super.run` legitimately
//!   reaches `Base.run`'s sink, but `Base.other` (never called)
//!   must stay clean even though it reads the same `self.cmd`.
//! * Sibling subscript keys, clean overwrites — sanity baselines
//!   that overlap with the matrix tests for an extra signal at the
//!   precision probe layer.

mod common;
use bonsai_lang_api::AdapterArc;
use bonsai_taint::interprocedural_taint;
use common::*;
use std::sync::Arc;

#[test]
fn probe_python_attribute_field_distinct_read() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
class Obj:
    pass

def entry(args):
    obj = Obj()
    obj.cmd = args
    sink(obj.user)
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, "sink", "obj.user"),
        "python attribute distinct-field read over-tainted; calls: {:?}",
        result.tainted_calls,
    );
}

#[test]
fn probe_python_cross_method_field_distinct() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
class Repo:
    def store(self, data):
        self.buffer = data

    def run(self):
        sink(self.command)

def entry(args):
    r = Repo()
    r.store(args)
    r.run()
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "python cross-method distinct-field write→read over-tainted; calls: {:?}",
        result.tainted_calls,
    );
}

#[test]
fn probe_python_unrelated_class_same_method_name() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
class A:
    def process(self, x):
        self.cmd = x
        sink_a(self.cmd)

class B:
    def process(self, x):
        sink_b('hardcoded')

def entry(args):
    b = B()
    b.process(args)
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    // sink_a is in A.process which is NEVER called (only B.process is called).
    // Even though A.process reads self.cmd, no taint should reach sink_a.
    assert!(
        !sink_reached(&result, "sink_a"),
        "unrelated class with same method name was over-tainted; calls: {:?}",
        result.tainted_calls,
    );
}

#[test]
fn probe_python_clean_overwrite_kills_taint() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
def entry(args):
    x = args
    x = 'safe_constant'
    sink(x)
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, "sink", "x"),
        "clean overwrite must kill taint; calls: {:?}",
        result.tainted_calls,
    );
}

#[test]
fn probe_python_sibling_subscript_keys_stay_distinct() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
def entry(args):
    d = {}
    d['a'] = args
    d['b'] = 'hardcoded'
    sink(d['b'])
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, "sink", "d['b']"),
        "subscript sibling key was over-tainted; calls: {:?}",
        result.tainted_calls,
    );
}

#[test]
fn probe_python_super_chain_does_not_taint_unrelated_method() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
class Base:
    def run(self):
        sink_base(self.cmd)

    def other(self):
        sink_other(self.cmd)

class Derived(Base):
    def run(self):
        super().run()

def entry(args):
    d = Derived()
    d.cmd = args
    d.run()
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    // d.run() → super().run() → Base.run() which calls sink_base.
    // But Base.other() is NEVER called. The fact that Base.other reads self.cmd
    // should not make sink_other appear in results.
    assert!(
        !sink_reached(&result, "sink_other"),
        "super-chain spread taint to unrelated method; calls: {:?}",
        result.tainted_calls,
    );
}

#[test]
fn probe_ruby_block_param_uses_callee_yield_not_call_args() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_ruby::RubyAdapter::new());
    let src = "
def helper(args)
  yield 'safe'
end

def entry(args)
  helper(args) do |value|
    sink(value)
  end
end
";
    let db = build_db(adapter, &[("a.rb", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "ruby block param was tainted from call args instead of yielded value; calls: {:?}",
        result.tainted_calls,
    );
}

#[test]
fn probe_ruby_call_result_uses_return_not_yield() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_ruby::RubyAdapter::new());
    let src = "
def helper(args)
  yield args
  'safe'
end

def entry(args)
  out = helper(args) do |value|
    'ignored'
  end
  sink(out)
end
";
    let db = build_db(adapter, &[("a.rb", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "ruby call result was tainted by a yielded value instead of the returned value; calls: {:?}",
        result.tainted_calls,
    );
}

#[test]
fn probe_ruby_call_result_still_uses_return_after_yield() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_ruby::RubyAdapter::new());
    let src = "
def helper(args)
  yield 'safe'
  args
end

def entry(args)
  out = helper(args) do |value|
    'ignored'
  end
  sink(out)
end
";
    let db = build_db(adapter, &[("a.rb", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        sink_reached(&result, "sink"),
        "ruby call result must still follow the method's returned value after a yield; calls: {:?}",
        result.tainted_calls,
    );
}
