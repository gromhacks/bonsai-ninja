//! Deep per-language chain tests ("hell chains").
//!
//! Each language gets ONE multi-file fixture that threads a single flow
//! from a source to a sink. Every intermediate hop lives in its own
//! module, is imported with its own import statement, and places its
//! call-to-next inside a DIFFERENT grammar construct (if / for / while /
//! foreach / try / catch / finally / using-with / assign / return /
//! yield / await / throw). Then `enumerate_chains` must walk the entire
//! chain end-to-end and `calls_contains` must confirm the call lands
//! inside the right enclosing function.
//!
//! Lambdas are intentionally excluded from the main chain: the walker
//! skips lambda bodies so a call nested in a lambda never surfaces in
//! the enclosing function's flow events. That is a design invariant
//! (nested lambdas are separate scopes), not a test target here.

#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

/// Walk `chain` step by step and assert every consecutive pair is a
/// caller→callee edge. Catches "the chain reached the sink but skipped
/// some construct in the middle" regressions.
///
/// Uses the same caller-map that `enumerate_chains` relies on so that
/// import-alias remaps are honored: `from x import y as z; z()` stores
/// the Call event under `z`, but the caller-map indexes it under BOTH
/// `z` and `y` via `per_file_symbol_aliases`.
#[track_caller]
fn assert_every_hop_is_captured(ws: &bonsai_workspace::Workspace, chain: &[&str]) {
    let callers = build_callers_map(ws);
    for pair in chain.windows(2) {
        let caller = pair[0];
        let callee = pair[1];
        let edge_exists = callers
            .get(callee)
            .is_some_and(|parents| parents.iter().any(|p| p == caller));
        assert!(
            edge_exists,
            "hop `{caller} -> {callee}` missing from caller map; \
             full chain = {chain:?}. \
             callers[{callee}] = {:?}",
            callers.get(callee)
        );
    }
}

/// Run a multi-file workspace through a chain and assert every hop + that
/// every named function is indexed. Cuts ~30 lines of boilerplate per lang.
#[track_caller]
fn run_chain(adapter: bonsai_lang_api::AdapterArc, files: &[(&str, &str)], chain: &[&str]) {
    let w = ws_multi(adapter, files);
    assert_every_hop_is_captured(&w, chain);
    if let (Some(entry), Some(sink)) = (chain.first(), chain.last()) {
        assert_chain_from_to(&w, entry, sink);
    }
    for name in chain {
        assert_function_named(&w, name);
    }
}

// ===========================================================================
// Python
// ===========================================================================

#[test]
fn python_hell_chain() {
    // Each hop uses a DIFFERENT Python import variation:
    //   entry  :  from m01_if import step_if              (named import)
    //   m01_if :  import m02_for                          (plain module import)
    //   m02_for:  import m03_while as W                   (module aliased)
    //   m03_while: from m04_foreach import step_foreach as F  (symbol aliased)
    //   m04_foreach: from m05_try import *                (wildcard import)
    //   m05_try:  from m06_catch import step_catch        (named import, reused shape)
    //   m06_catch: import m07_finally                     (plain module)
    //   m07_finally: from m08_with import (step_with,)    (parenthesized list)
    //   m08_with: from m09_assign import *                (wildcard)
    //   m09_assign: from m10_return import step_return as SR  (symbol aliased)
    //   m10_return: import m11_yield as Y                 (module aliased)
    //   m11_yield: from m12_await import step_await       (named)
    //   m12_await: import m13_throw                       (plain)
    //   m13_throw: from m14_sink import sink              (named)
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let files = [
        (
            "/w/m00_entry.py",
            "from m01_if import step_if\n\
             def entry():\n    return step_if('tok')\n",
        ),
        (
            "/w/m01_if.py",
            "import m02_for\n\
             def step_if(x):\n    if x:\n        return m02_for.step_for(x)\n    return None\n",
        ),
        (
            "/w/m02_for.py",
            "import m03_while as W\n\
             def step_for(x):\n    for _ in [1]:\n        return W.step_while(x)\n    return None\n",
        ),
        (
            "/w/m03_while.py",
            "from m04_foreach import step_foreach as F\n\
             def step_while(x):\n    i = 0\n    while i < 1:\n        i += 1\n        return F(x)\n    return None\n",
        ),
        (
            "/w/m04_foreach.py",
            "from m05_try import *\n\
             def step_foreach(x):\n    for y in [x]:\n        return step_try(y)\n    return None\n",
        ),
        (
            "/w/m05_try.py",
            "from m06_catch import step_catch\n\
             def step_try(x):\n    try:\n        return step_catch(x)\n    except Exception:\n        return None\n",
        ),
        (
            "/w/m06_catch.py",
            "import m07_finally\n\
             def step_catch(x):\n    try:\n        raise ValueError('boom')\n    except ValueError:\n        return m07_finally.step_finally(x)\n",
        ),
        (
            "/w/m07_finally.py",
            "from m08_with import (step_with,)\n\
             def step_finally(x):\n    try:\n        return None\n    finally:\n        return step_with(x)\n",
        ),
        (
            "/w/m08_with.py",
            "from m09_assign import *\n\
             def step_with(x):\n    with open('/dev/null') as f:\n        return step_assign(x)\n",
        ),
        (
            "/w/m09_assign.py",
            "from m10_return import step_return as SR\n\
             def step_assign(x):\n    y = SR(x)\n    return y\n",
        ),
        (
            "/w/m10_return.py",
            "import m11_yield as Y\n\
             def step_return(x):\n    return Y.step_yield(x)\n",
        ),
        (
            "/w/m11_yield.py",
            "from m12_await import step_await\n\
             def step_yield(x):\n    def g(v):\n        yield v\n    list(g(step_await(x)))\n    return None\n",
        ),
        (
            "/w/m12_await.py",
            "import asyncio\n\
             import m13_throw\n\
             async def step_await(x):\n    await asyncio.sleep(0)\n    return m13_throw.step_throw(x)\n",
        ),
        (
            "/w/m13_throw.py",
            "from m14_sink import sink\n\
             class Bomb(Exception):\n    pass\n\
             def step_throw(x):\n    raise Bomb(sink(x))\n",
        ),
        (
            "/w/m14_sink.py",
            "import os\n\
             def sink(x):\n    os.system('echo ' + x)\n    return x\n",
        ),
    ];
    let chain = [
        "entry",
        "step_if",
        "step_for",
        "step_while",
        "step_foreach",
        "step_try",
        "step_catch",
        "step_finally",
        "step_with",
        "step_assign",
        "step_return",
        "step_yield",
        "step_await",
        "step_throw",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// JavaScript
// ===========================================================================

#[test]
fn javascript_hell_chain() {
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    // Each hop uses a distinct JS import/export variation:
    //   entry    : named import             — `import { stepIf } from 'x'`
    //   stepIf   : default import           — `import stepFor from 'x'`
    //   stepFor  : namespace import         — `import * as M from 'x'`
    //   stepWhile: renamed named import     — `import { stepForOf as S } from 'x'`
    //   stepForOf: CommonJS destructured    — `const { stepTry } = require('x')`
    //   stepTry  : CommonJS default         — `const stepCatch = require('x')`
    //   stepCatch: CommonJS renamed         — `const { stepFinally: SF } = require('x')`
    //   stepFinally: named + multiple       — `import { stepAssign, OTHER } from 'x'`
    //   stepAssign: dynamic import (regular require used as sync proxy in this test)
    //   stepReturn: namespace CommonJS      — `const M = require('x')`
    //   stepAwait : renamed named           — `import { stepYield as SY } from 'x'`
    //   stepYield : side-effect + separate re-export
    //   stepThrow : named import
    //   sink (leaf): external module import
    let files = [
        (
            "/w/m00_entry.js",
            "import { stepIf } from './m01_if.js';\n\
             export function entry() { return stepIf('tok'); }\n",
        ),
        (
            "/w/m01_if.js",
            "import stepFor from './m02_for.js';\n\
             export function stepIf(x) { if (x) { return stepFor(x); } return null; }\n\
             export { stepIf };\n",
        ),
        (
            "/w/m02_for.js",
            "import * as M from './m03_while.js';\n\
             function stepFor(x) { for (let i=0; i<1; i++) { return M.stepWhile(x); } return null; }\n\
             export default stepFor;\n",
        ),
        (
            "/w/m03_while.js",
            "import { stepForOf as S } from './m04_forof.js';\n\
             export function stepWhile(x) { let i=0; while (i<1) { i++; return S(x); } return null; }\n",
        ),
        (
            "/w/m04_forof.js",
            "const { stepTry } = require('./m05_try.js');\n\
             function stepForOf(x) { for (const y of [x]) { return stepTry(y); } return null; }\n\
             module.exports = { stepForOf };\n",
        ),
        (
            "/w/m05_try.js",
            "const stepCatch = require('./m06_catch.js');\n\
             function stepTry(x) { try { return stepCatch(x); } catch (e) { return null; } }\n\
             module.exports = stepTry;\n\
             module.exports.stepTry = stepTry;\n",
        ),
        (
            "/w/m06_catch.js",
            "const { stepFinally: SF } = require('./m07_finally.js');\n\
             function stepCatch(x) { try { throw new Error('boom'); } catch (e) { return SF(x); } }\n\
             module.exports = stepCatch;\n\
             module.exports.stepCatch = stepCatch;\n",
        ),
        (
            "/w/m07_finally.js",
            "import { stepAssign, HELPER } from './m08_assign.js';\n\
             export function stepFinally(x) { try { return null; } finally { return stepAssign(x); } }\n",
        ),
        (
            "/w/m08_assign.js",
            "import { stepReturn } from './m09_return.js';\n\
             export const HELPER = 1;\n\
             export function stepAssign(x) { const y = stepReturn(x); return y; }\n",
        ),
        (
            "/w/m09_return.js",
            "const Aw = require('./m10_await.js');\n\
             function stepReturn(x) { return Aw.stepAwait(x); }\n\
             module.exports = { stepReturn };\n",
        ),
        (
            "/w/m10_await.js",
            "import { stepYield as SY } from './m11_yield.js';\n\
             export async function stepAwait(x) { await Promise.resolve(); return SY(x); }\n",
        ),
        (
            "/w/m11_yield.js",
            "import './m12_throw.js';\n\
             import { stepThrow } from './m12_throw.js';\n\
             export function* stepYield(x) { yield stepThrow(x); }\n",
        ),
        (
            "/w/m12_throw.js",
            "import { sink } from './m13_sink.js';\n\
             export function stepThrow(x) { throw new Error(sink(x)); }\n",
        ),
        (
            "/w/m13_sink.js",
            "import { execSync } from 'child_process';\n\
             export function sink(x) { execSync('echo ' + x); return x; }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepForOf",
        "stepTry",
        "stepCatch",
        "stepFinally",
        "stepAssign",
        "stepReturn",
        "stepAwait",
        "stepYield",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// TypeScript — mirrors JS with type annotations.
// ===========================================================================

#[test]
fn typescript_hell_chain() {
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    // Each hop uses a distinct TypeScript import/export variation.
    let files = [
        (
            "/w/m00_entry.ts",
            "import { stepIf } from './m01_if';\n\
             export function entry(): string { return stepIf('tok'); }\n",
        ),
        (
            "/w/m01_if.ts",
            // default import
            "import stepFor from './m02_for';\n\
             export function stepIf(x: string): string { if (x) { return stepFor(x); } return ''; }\n",
        ),
        (
            "/w/m02_for.ts",
            // namespace import
            "import * as M from './m03_while';\n\
             function stepFor(x: string): string { for (let i=0; i<1; i++) { return M.stepWhile(x); } return ''; }\n\
             export default stepFor;\n",
        ),
        (
            "/w/m03_while.ts",
            // renamed named import
            "import { stepForOf as S } from './m04_forof';\n\
             export function stepWhile(x: string): string { let i=0; while (i<1) { i++; return S(x); } return ''; }\n",
        ),
        (
            "/w/m04_forof.ts",
            // CommonJS destructured
            "const { stepTry } = require('./m05_try');\n\
             function stepForOf(x: string): string { for (const y of [x]) { return stepTry(y); } return ''; }\n\
             module.exports = { stepForOf };\n",
        ),
        (
            "/w/m05_try.ts",
            // CommonJS default binding
            "const stepCatch = require('./m06_catch');\n\
             function stepTry(x: string): string { try { return stepCatch(x); } catch (e) { return ''; } }\n\
             module.exports = stepTry;\n\
             module.exports.stepTry = stepTry;\n",
        ),
        (
            "/w/m06_catch.ts",
            // CommonJS renamed destructure
            "const { stepFinally: SF } = require('./m07_finally');\n\
             function stepCatch(x: string): string { try { throw new Error('boom'); } catch (e) { return SF(x); } }\n\
             module.exports = stepCatch;\n\
             module.exports.stepCatch = stepCatch;\n",
        ),
        (
            "/w/m07_finally.ts",
            // named + multiple
            "import { stepAssign, HELPER } from './m08_assign';\n\
             export function stepFinally(x: string): string { try { return ''; } finally { return stepAssign(x); } }\n",
        ),
        (
            "/w/m08_assign.ts",
            // TypeScript `import X = require('y')` (legacy CommonJS-in-TS)
            "import R = require('./m09_return');\n\
             export const HELPER = 1;\n\
             export function stepAssign(x: string): string { const y = R.stepReturn(x); return y; }\n",
        ),
        (
            "/w/m09_return.ts",
            // CommonJS namespace
            "const Aw = require('./m10_await');\n\
             function stepReturn(x: string): Promise<string> { return Aw.stepAwait(x); }\n\
             module.exports = { stepReturn };\n",
        ),
        (
            "/w/m10_await.ts",
            // renamed named
            "import { stepYield as SY } from './m11_yield';\n\
             export async function stepAwait(x: string): Promise<string> { await Promise.resolve(); return SY(x); }\n",
        ),
        (
            "/w/m11_yield.ts",
            // side-effect + named
            "import './m12_throw';\n\
             import { stepThrow } from './m12_throw';\n\
             export function* stepYield(x: string): Generator<string> { yield stepThrow(x); }\n",
        ),
        (
            "/w/m12_throw.ts",
            "import { sink } from './m13_sink';\n\
             export function stepThrow(x: string): string { throw new Error(sink(x)); }\n",
        ),
        (
            "/w/m13_sink.ts",
            "import { execSync } from 'child_process';\n\
             export function sink(x: string): string { execSync('echo ' + x); return x; }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepForOf",
        "stepTry",
        "stepCatch",
        "stepFinally",
        "stepAssign",
        "stepReturn",
        "stepAwait",
        "stepYield",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Java
// ===========================================================================

#[test]
fn java_hell_chain() {
    // Varies: single-type import, wildcard import, static single import,
    // static wildcard import, and fully-qualified (no-import) calls.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let files = [
        (
            "/w/M00Entry.java",
            // static single import
            "package w.m00;\nimport static w.m01.M01If.stepIf;\n\
             public class M00Entry { public static String entry() { return stepIf(\"tok\"); } }\n",
        ),
        (
            "/w/M01If.java",
            // single type import
            "package w.m01;\nimport w.m02.M02For;\n\
             public class M01If { public static String stepIf(String x) { if (x != null) { return M02For.stepFor(x); } return null; } }\n",
        ),
        (
            "/w/M02For.java",
            // wildcard package import
            "package w.m02;\nimport w.m03.*;\n\
             public class M02For { public static String stepFor(String x) { for (int i=0; i<1; i++) { return M03While.stepWhile(x); } return null; } }\n",
        ),
        (
            "/w/M03While.java",
            // static wildcard import
            "package w.m03;\nimport static w.m04.M04ForEach.*;\n\
             public class M03While { public static String stepWhile(String x) { int i=0; while (i<1) { i++; return stepForEach(x); } return null; } }\n",
        ),
        (
            "/w/M04ForEach.java",
            // single import + standard library import
            "package w.m04;\nimport java.util.List;\nimport w.m05.M05Try;\n\
             public class M04ForEach { public static String stepForEach(String x) { for (String y : List.of(x)) { return M05Try.stepTry(y); } return null; } }\n",
        ),
        (
            "/w/M05Try.java",
            // fully qualified (no import for the chain call)
            "package w.m05;\n\
             public class M05Try { public static String stepTry(String x) { try { return w.m06.M06Catch.stepCatch(x); } catch (Exception e) { return null; } } }\n",
        ),
        (
            "/w/M06Catch.java",
            "package w.m06;\nimport w.m07.M07Finally;\n\
             public class M06Catch { public static String stepCatch(String x) { try { throw new RuntimeException(\"boom\"); } catch (RuntimeException e) { return M07Finally.stepFinally(x); } } }\n",
        ),
        (
            "/w/M07Finally.java",
            // static single import
            "package w.m07;\nimport static w.m08.M08Sync.stepSync;\n\
             public class M07Finally { public static String stepFinally(String x) { try { return null; } finally { return stepSync(x); } } }\n",
        ),
        (
            "/w/M08Sync.java",
            "package w.m08;\nimport w.m09.M09Assign;\n\
             public class M08Sync { public static String stepSync(String x) { synchronized(M08Sync.class) { return M09Assign.stepAssign(x); } } }\n",
        ),
        (
            "/w/M09Assign.java",
            // wildcard
            "package w.m09;\nimport w.m10.*;\n\
             public class M09Assign { public static String stepAssign(String x) { String y = M10Return.stepReturn(x); return y; } }\n",
        ),
        (
            "/w/M10Return.java",
            "package w.m10;\nimport w.m11.M11Throw;\n\
             public class M10Return { public static String stepReturn(String x) { return M11Throw.stepThrow(x); } }\n",
        ),
        (
            "/w/M11Throw.java",
            // static wildcard
            "package w.m11;\nimport static w.m12.M12Sink.*;\n\
             public class M11Throw { public static String stepThrow(String x) { throw new RuntimeException(sink(x)); } }\n",
        ),
        (
            "/w/M12Sink.java",
            "package w.m12;\nimport java.lang.Runtime;\n\
             public class M12Sink { public static String sink(String x) { try { Runtime.getRuntime().exec(\"echo \" + x); } catch (Exception e) {} return x; } }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepForEach",
        "stepTry",
        "stepCatch",
        "stepFinally",
        "stepSync",
        "stepAssign",
        "stepReturn",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Kotlin
// ===========================================================================

#[test]
fn kotlin_hell_chain() {
    // Varies: single import, wildcard `*`, `as`-alias, multiple single imports.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let files = [
        (
            "/w/m00_entry.kt",
            // aliased import
            "package w.m00\nimport w.m01.stepIf as SI\n\
             fun entry(): String? = SI(\"tok\")\n",
        ),
        (
            "/w/m01_if.kt",
            // wildcard
            "package w.m01\nimport w.m02.*\n\
             fun stepIf(x: String): String? { if (x.isNotEmpty()) { return stepFor(x) } ; return null }\n",
        ),
        (
            "/w/m02_for.kt",
            // single
            "package w.m02\nimport w.m03.stepWhile\n\
             fun stepFor(x: String): String? { for (i in 0..0) { return stepWhile(x) } ; return null }\n",
        ),
        (
            "/w/m03_while.kt",
            // aliased
            "package w.m03\nimport w.m04.stepForEach as FE\n\
             fun stepWhile(x: String): String? { var i = 0; while (i < 1) { i++; return FE(x) } ; return null }\n",
        ),
        (
            "/w/m04_foreach.kt",
            // wildcard
            "package w.m04\nimport w.m05.*\n\
             fun stepForEach(x: String): String? { for (y in listOf(x)) { return stepTry(y) } ; return null }\n",
        ),
        (
            "/w/m05_try.kt",
            "package w.m05\nimport w.m06.stepCatch\n\
             fun stepTry(x: String): String? { return try { stepCatch(x) } catch (e: Exception) { null } }\n",
        ),
        (
            "/w/m06_catch.kt",
            // aliased
            "package w.m06\nimport w.m07.stepFinally as SF\n\
             fun stepCatch(x: String): String? { return try { throw RuntimeException(\"boom\") } catch (e: RuntimeException) { SF(x) } }\n",
        ),
        (
            "/w/m07_finally.kt",
            // wildcard
            "package w.m07\nimport w.m08.*\n\
             fun stepFinally(x: String): String? { try { return null } finally { return stepAssign(x) } }\n",
        ),
        (
            "/w/m08_assign.kt",
            "package w.m08\nimport w.m09.stepReturn\n\
             fun stepAssign(x: String): String? { val y = stepReturn(x); return y }\n",
        ),
        (
            "/w/m09_return.kt",
            // aliased
            "package w.m09\nimport w.m10.stepThrow as ST\n\
             fun stepReturn(x: String): String? = ST(x)\n",
        ),
        (
            "/w/m10_throw.kt",
            "package w.m10\nimport w.m11.sink\n\
             fun stepThrow(x: String): String? { throw RuntimeException(sink(x)) }\n",
        ),
        (
            "/w/m11_sink.kt",
            "package w.m11\n\
             fun sink(x: String): String { Runtime.getRuntime().exec(\"echo \" + x); return x }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepForEach",
        "stepTry",
        "stepCatch",
        "stepFinally",
        "stepAssign",
        "stepReturn",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// C#
// ===========================================================================

#[test]
fn csharp_hell_chain() {
    // Varies: namespace `using`, `using static`, and `using Alias = ...`.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let files = [
        (
            "/w/M00Entry.cs",
            // `using static` — StepIf callable without class qualifier
            "using static W.M01.M01If;\nnamespace W.M00 { public static class M00Entry { public static string Entry() { return StepIf(\"tok\"); } } }\n",
        ),
        (
            "/w/M01If.cs",
            // namespace using
            "using W.M02;\nnamespace W.M01 { public static class M01If { public static string StepIf(string x) { if (x != null) { return M02For.StepFor(x); } return null; } } }\n",
        ),
        (
            "/w/M02For.cs",
            // alias using
            "using F = W.M03.M03While;\nnamespace W.M02 { public static class M02For { public static string StepFor(string x) { for (int i=0; i<1; i++) { return F.StepWhile(x); } return null; } } }\n",
        ),
        (
            "/w/M03While.cs",
            "using W.M04;\nnamespace W.M03 { public static class M03While { public static string StepWhile(string x) { int i=0; while (i<1) { i++; return M04ForEach.StepForEach(x); } return null; } } }\n",
        ),
        (
            "/w/M04ForEach.cs",
            // using static
            "using static W.M05.M05Try;\nusing System.Collections.Generic;\nnamespace W.M04 { public static class M04ForEach { public static string StepForEach(string x) { foreach (var y in new List<string>{x}) { return StepTry(y); } return null; } } }\n",
        ),
        (
            "/w/M05Try.cs",
            // namespace using
            "using W.M06;\nusing System;\nnamespace W.M05 { public static class M05Try { public static string StepTry(string x) { try { return M06Catch.StepCatch(x); } catch (Exception) { return null; } } } }\n",
        ),
        (
            "/w/M06Catch.cs",
            // alias using for the type
            "using Fin = W.M07.M07Finally;\nusing System;\nnamespace W.M06 { public static class M06Catch { public static string StepCatch(string x) { try { throw new Exception(\"boom\"); } catch (Exception) { return Fin.StepFinally(x); } } } }\n",
        ),
        (
            "/w/M07Finally.cs",
            // using static
            "using static W.M08.M08Using;\nnamespace W.M07 { public static class M07Finally { public static string StepFinally(string x) { try { return null; } finally { StepUsing(x); } } } }\n",
        ),
        (
            "/w/M08Using.cs",
            "using W.M09;\nusing System.IO;\nnamespace W.M08 { public static class M08Using { public static string StepUsing(string x) { using (var sw = new StringWriter()) { return M09Await.StepAwait(x).Result; } } } }\n",
        ),
        (
            "/w/M09Await.cs",
            // alias for type
            "using Asg = W.M10.M10Assign;\nusing System.Threading.Tasks;\nnamespace W.M09 { public static class M09Await { public static async Task<string> StepAwait(string x) { await Task.Yield(); return Asg.StepAssign(x); } } }\n",
        ),
        (
            "/w/M10Assign.cs",
            "using W.M11;\nnamespace W.M10 { public static class M10Assign { public static string StepAssign(string x) { string y = M11Return.StepReturn(x); return y; } } }\n",
        ),
        (
            "/w/M11Return.cs",
            // using static
            "using static W.M12.M12Throw;\nnamespace W.M11 { public static class M11Return { public static string StepReturn(string x) { return StepThrow(x); } } }\n",
        ),
        (
            "/w/M12Throw.cs",
            "using W.M13;\nusing System;\nnamespace W.M12 { public static class M12Throw { public static string StepThrow(string x) { throw new Exception(M13Sink.Sink(x)); } } }\n",
        ),
        (
            "/w/M13Sink.cs",
            "using System.Diagnostics;\nnamespace W.M13 { public static class M13Sink { public static string Sink(string x) { Process.Start(\"echo\", x); return x; } } }\n",
        ),
    ];
    let chain = [
        "Entry",
        "StepIf",
        "StepFor",
        "StepWhile",
        "StepForEach",
        "StepTry",
        "StepCatch",
        "StepFinally",
        "StepUsing",
        "StepAwait",
        "StepAssign",
        "StepReturn",
        "StepThrow",
        "Sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Scala
// ===========================================================================

#[test]
fn scala_hell_chain() {
    // Varies: straight single, `._` wildcard, `{A}` braced, `{A => B}` rename.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_scala::ScalaAdapter::new());
    let files = [
        (
            "/w/m00_entry.scala",
            // straight single
            "package w.m00\nimport w.m01.M01If.stepIf\nobject M00Entry { def entry(): String = stepIf(\"tok\") }\n",
        ),
        (
            "/w/m01_if.scala",
            // wildcard `_`
            "package w.m01\nimport w.m02.M02For._\nobject M01If { def stepIf(x: String): String = { if (x.nonEmpty) { return stepFor(x) } ; null } }\n",
        ),
        (
            "/w/m02_for.scala",
            // rename
            "package w.m02\nimport w.m03.M03While.{stepWhile => SW}\nobject M02For { def stepFor(x: String): String = { for (i <- 0 to 0) { return SW(x) } ; null } }\n",
        ),
        (
            "/w/m03_while.scala",
            // straight
            "package w.m03\nimport w.m04.M04Try.stepTry\nobject M03While { def stepWhile(x: String): String = { var i = 0; while (i < 1) { i += 1; return stepTry(x) } ; null } }\n",
        ),
        (
            "/w/m04_try.scala",
            // wildcard
            "package w.m04\nimport w.m05.M05Catch._\nobject M04Try { def stepTry(x: String): String = { try { return stepCatch(x) } catch { case _: Throwable => null } } }\n",
        ),
        (
            "/w/m05_catch.scala",
            // rename
            "package w.m05\nimport w.m06.M06Finally.{stepFinally => SF}\nobject M05Catch { def stepCatch(x: String): String = { try { throw new RuntimeException(\"boom\") } catch { case _: RuntimeException => SF(x) } } }\n",
        ),
        (
            "/w/m06_finally.scala",
            // straight
            "package w.m06\nimport w.m07.M07Assign.stepAssign\nobject M06Finally { def stepFinally(x: String): String = { try { null } finally { stepAssign(x) } } }\n",
        ),
        (
            "/w/m07_assign.scala",
            // wildcard
            "package w.m07\nimport w.m08.M08Return._\nobject M07Assign { def stepAssign(x: String): String = { val y = stepReturn(x); y } }\n",
        ),
        (
            "/w/m08_return.scala",
            // rename
            "package w.m08\nimport w.m09.M09Throw.{stepThrow => ST}\nobject M08Return { def stepReturn(x: String): String = { return ST(x) } }\n",
        ),
        (
            "/w/m09_throw.scala",
            // straight
            "package w.m09\nimport w.m10.M10Sink.sink\nobject M09Throw { def stepThrow(x: String): String = { throw new RuntimeException(sink(x)) } }\n",
        ),
        (
            "/w/m10_sink.scala",
            // wildcard
            "package w.m10\nimport sys.process._\nobject M10Sink { def sink(x: String): String = { (\"echo \" + x).!; x } }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepTry",
        "stepCatch",
        "stepFinally",
        "stepAssign",
        "stepReturn",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Swift
// ===========================================================================

#[test]
fn swift_hell_chain() {
    // Varies: plain, `import func`, `import struct`, `import class`,
    // `import enum`, `import protocol`, `import typealias`, `@testable`.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let files = [
        (
            "/w/m00_entry.swift",
            // plain
            "import M01If\nfunc entry() -> String? { return stepIf(\"tok\") }\n",
        ),
        (
            "/w/m01_if.swift",
            // import func
            "import func M02For.stepFor\nfunc stepIf(_ x: String) -> String? { if x.count > 0 { return stepFor(x) } ; return nil }\n",
        ),
        (
            "/w/m02_for.swift",
            // import struct
            "import struct M03While.Runner\nimport M03While\nfunc stepFor(_ x: String) -> String? { for _ in 0..<1 { return stepWhile(x) } ; return nil }\n",
        ),
        (
            "/w/m03_while.swift",
            // import class
            "import class M04Guard.Helper\nimport M04Guard\nfunc stepWhile(_ x: String) -> String? { var i = 0; while i < 1 { i += 1; return stepGuard(x) } ; return nil }\n",
        ),
        (
            "/w/m04_guard.swift",
            // @testable
            "@testable import M05Try\nfunc stepGuard(_ x: String) -> String? { guard !x.isEmpty else { return nil } ; return stepTry(x) }\n",
        ),
        (
            "/w/m05_try.swift",
            // import enum
            "import enum M06Catch.Kind\nimport M06Catch\nfunc stepTry(_ x: String) -> String? { do { return try stepCatch(x) } catch { return nil } }\n",
        ),
        (
            "/w/m06_catch.swift",
            // import protocol
            "import protocol M07Defer.P\nimport M07Defer\nenum E: Error { case boom }\nfunc stepCatch(_ x: String) throws -> String? { do { throw E.boom } catch { return stepDefer(x) } }\n",
        ),
        (
            "/w/m07_defer.swift",
            // plain
            "import M08Assign\nfunc stepDefer(_ x: String) -> String? { defer { _ = stepAssign(x) } ; return nil }\n",
        ),
        (
            "/w/m08_assign.swift",
            // import typealias
            "import typealias M09Return.Tok\nimport M09Return\nfunc stepAssign(_ x: String) -> String? { let y = stepReturn(x); return y }\n",
        ),
        (
            "/w/m09_return.swift",
            // import func (direct symbol)
            "import func M10Throw.stepThrow\nfunc stepReturn(_ x: String) -> String? { return stepThrow(x) }\n",
        ),
        (
            "/w/m10_throw.swift",
            // plain
            "import M11Sink\nenum E2: Error { case bad }\nfunc stepThrow(_ x: String) -> String? { let r = sink(x); return r }\n",
        ),
        (
            "/w/m11_sink.swift",
            "import Foundation\nfunc sink(_ x: String) -> String { let p = Process(); p.launchPath = \"/bin/echo\"; p.arguments = [x]; try? p.run(); return x }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepGuard",
        "stepTry",
        "stepCatch",
        "stepDefer",
        "stepAssign",
        "stepReturn",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Ruby
// ===========================================================================

#[test]
fn ruby_hell_chain() {
    // Varies: `require`, `require_relative`, `load`, `autoload`.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_ruby::RubyAdapter::new());
    let files = [
        (
            "/w/m00_entry.rb",
            "require_relative 'm01_if'\ndef entry\n  step_if('tok')\nend\n",
        ),
        (
            "/w/m01_if.rb",
            // require (absolute-ish)
            "require 'm02_for'\ndef step_if(x)\n  if x\n    return step_for(x)\n  end\n  nil\nend\n",
        ),
        (
            "/w/m02_for.rb",
            // load
            "load 'm03_while.rb'\ndef step_for(x)\n  for _ in [1]\n    return step_while(x)\n  end\n  nil\nend\n",
        ),
        (
            "/w/m03_while.rb",
            // require_relative
            "require_relative 'm04_until'\ndef step_while(x)\n  i = 0\n  while i < 1\n    i += 1\n    return step_until(x)\n  end\n  nil\nend\n",
        ),
        (
            "/w/m04_until.rb",
            // autoload
            "autoload :M05Case, 'm05_case'\ndef step_until(x)\n  i = 0\n  until i >= 1\n    i += 1\n    return step_case(x)\n  end\n  nil\nend\n",
        ),
        (
            "/w/m05_case.rb",
            "require 'm06_begin'\ndef step_case(x)\n  case x\n  when String then return step_begin(x)\n  end\nend\n",
        ),
        (
            "/w/m06_begin.rb",
            "require_relative 'm07_rescue'\ndef step_begin(x)\n  begin\n    return step_rescue(x)\n  rescue\n    nil\n  end\nend\n",
        ),
        (
            "/w/m07_rescue.rb",
            "load 'm08_ensure.rb'\ndef step_rescue(x)\n  begin\n    raise 'boom'\n  rescue\n    return step_ensure(x)\n  end\nend\n",
        ),
        (
            "/w/m08_ensure.rb",
            "require_relative 'm09_assign'\ndef step_ensure(x)\n  begin\n    nil\n  ensure\n    return step_assign(x)\n  end\nend\n",
        ),
        (
            "/w/m09_assign.rb",
            "autoload :M10Return, 'm10_return'\ndef step_assign(x)\n  y = step_return(x)\n  y\nend\n",
        ),
        (
            "/w/m10_return.rb",
            "require 'm11_yield'\ndef step_return(x)\n  return step_yield(x)\nend\n",
        ),
        (
            "/w/m11_yield.rb",
            "require_relative 'm12_raise'\ndef step_yield(x)\n  yield step_raise(x) if block_given?\n  step_raise(x)\nend\n",
        ),
        (
            "/w/m12_raise.rb",
            "load 'm13_sink.rb'\ndef step_raise(x)\n  raise RuntimeError, sink(x)\nend\n",
        ),
        (
            "/w/m13_sink.rb",
            "def sink(x)\n  `echo #{x}`\n  x\nend\n",
        ),
    ];
    let chain = [
        "entry",
        "step_if",
        "step_for",
        "step_while",
        "step_until",
        "step_case",
        "step_begin",
        "step_rescue",
        "step_ensure",
        "step_assign",
        "step_return",
        "step_yield",
        "step_raise",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// PHP
// ===========================================================================

#[test]
fn php_hell_chain() {
    // Varies: `require`, `require_once`, `include`, `include_once`.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_php::PhpAdapter::new());
    let files = [
        (
            "/w/m00_entry.php",
            "<?php\nrequire_once 'm01_if.php';\nfunction entry() { return stepIf('tok'); }\n",
        ),
        (
            "/w/m01_if.php",
            "<?php\nrequire 'm02_for.php';\nfunction stepIf($x) { if ($x) { return stepFor($x); } return null; }\n",
        ),
        (
            "/w/m02_for.php",
            "<?php\ninclude 'm03_while.php';\nfunction stepFor($x) { for ($i=0; $i<1; $i++) { return stepWhile($x); } return null; }\n",
        ),
        (
            "/w/m03_while.php",
            "<?php\ninclude_once 'm04_foreach.php';\nfunction stepWhile($x) { $i=0; while ($i<1) { $i++; return stepForEach($x); } return null; }\n",
        ),
        (
            "/w/m04_foreach.php",
            "<?php\nrequire_once 'm05_try.php';\nfunction stepForEach($x) { foreach ([$x] as $y) { return stepTry($y); } return null; }\n",
        ),
        (
            "/w/m05_try.php",
            "<?php\nrequire 'm06_catch.php';\nfunction stepTry($x) { try { return stepCatch($x); } catch (\\Exception $e) { return null; } }\n",
        ),
        (
            "/w/m06_catch.php",
            "<?php\ninclude 'm07_finally.php';\nfunction stepCatch($x) { try { throw new \\RuntimeException('boom'); } catch (\\RuntimeException $e) { return stepFinally($x); } }\n",
        ),
        (
            "/w/m07_finally.php",
            "<?php\ninclude_once 'm08_assign.php';\nfunction stepFinally($x) { try { return null; } finally { return stepAssign($x); } }\n",
        ),
        (
            "/w/m08_assign.php",
            "<?php\nrequire_once 'm09_return.php';\nfunction stepAssign($x) { $y = stepReturn($x); return $y; }\n",
        ),
        (
            "/w/m09_return.php",
            "<?php\nrequire 'm10_throw.php';\nfunction stepReturn($x) { return stepThrow($x); }\n",
        ),
        (
            "/w/m10_throw.php",
            "<?php\ninclude 'm11_sink.php';\nfunction stepThrow($x) { throw new \\RuntimeException(sink($x)); }\n",
        ),
        (
            "/w/m11_sink.php",
            "<?php\nfunction sink($x) { shell_exec('echo ' . $x); return $x; }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepForEach",
        "stepTry",
        "stepCatch",
        "stepFinally",
        "stepAssign",
        "stepReturn",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Dart
// ===========================================================================

#[test]
fn dart_hell_chain() {
    // Varies: plain relative, `as`, `show`, `hide`, plus `dart:` system
    // import at the sink leaf.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_dart::DartAdapter::new());
    let files = [
        (
            "/w/m00_entry.dart",
            "import 'm01_if.dart' show stepIf;\nString? entry() { return stepIf('tok'); }\n",
        ),
        (
            "/w/m01_if.dart",
            "import 'm02_for.dart' as F;\nString? stepIf(String x) { if (x.isNotEmpty) { return F.stepFor(x); } return null; }\n",
        ),
        (
            "/w/m02_for.dart",
            "import 'm03_while.dart' show stepWhile;\nString? stepFor(String x) { for (var i = 0; i < 1; i++) { return stepWhile(x); } return null; }\n",
        ),
        (
            "/w/m03_while.dart",
            "import 'm04_foreach.dart' hide unused;\nString? stepWhile(String x) { var i = 0; while (i < 1) { i++; return stepForEach(x); } return null; }\n",
        ),
        (
            "/w/m04_foreach.dart",
            "import 'm05_try.dart' as T;\nString? stepForEach(String x) { for (var y in [x]) { return T.stepTry(y); } return null; }\n",
        ),
        (
            "/w/m05_try.dart",
            "import 'm06_catch.dart';\nString? stepTry(String x) { try { return stepCatch(x); } catch (e) { return null; } }\n",
        ),
        (
            "/w/m06_catch.dart",
            "import 'm07_finally.dart' show stepFinally;\nString? stepCatch(String x) { try { throw Exception('boom'); } catch (e) { return stepFinally(x); } return null; }\n",
        ),
        (
            "/w/m07_finally.dart",
            "import 'm08_assign.dart' as A;\nString? stepFinally(String x) { try { return null; } finally { return A.stepAssign(x); } }\n",
        ),
        (
            "/w/m08_assign.dart",
            "import 'm09_return.dart' hide other;\nString? stepAssign(String x) { var y = stepReturn(x); return y; }\n",
        ),
        (
            "/w/m09_return.dart",
            "import 'm10_throw.dart';\nString? stepReturn(String x) { return stepThrow(x); }\n",
        ),
        (
            "/w/m10_throw.dart",
            "import 'm11_sink.dart' show sink;\nString? stepThrow(String x) { throw Exception(sink(x)); }\n",
        ),
        (
            "/w/m11_sink.dart",
            "import 'dart:io';\nString sink(String x) { Process.run('echo', [x]); return x; }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepForEach",
        "stepTry",
        "stepCatch",
        "stepFinally",
        "stepAssign",
        "stepReturn",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Rust — no try/catch/throw; match is a branch; lots of loops.
// ===========================================================================

#[test]
fn rust_hell_chain() {
    // Varies: `use X;`, `use X::{a,b};`, `use X::a as b;`, `use X::*;`,
    // `use self::X;`, `use crate::X;`, `use super::X;`.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let files = [
        (
            "/w/m00_entry.rs",
            // `use crate::X::Y;`
            "use crate::m01_if::step_if;\npub fn entry() -> String { step_if(\"tok\".to_string()) }\n",
        ),
        (
            "/w/m01_if.rs",
            // `use X::Y as Z;`
            "use crate::m02_match::step_match as SM;\npub fn step_if(x: String) -> String { if !x.is_empty() { return SM(x); } String::new() }\n",
        ),
        (
            "/w/m02_match.rs",
            // grouped `use X::{a, b};`
            "use crate::m03_for::{step_for, OTHER};\npub fn step_match(x: String) -> String { match x.as_str() { \"\" => String::new(), _ => step_for(x) } }\n",
        ),
        (
            "/w/m03_for.rs",
            // wildcard `use X::*;`
            "use crate::m04_while::*;\npub const OTHER: u32 = 0;\npub fn step_for(x: String) -> String { for _ in 0..1 { return step_while(x); } String::new() }\n",
        ),
        (
            "/w/m04_while.rs",
            // rename
            "use crate::m05_loop::step_loop as SL;\npub fn step_while(x: String) -> String { let mut i = 0; while i < 1 { i += 1; return SL(x); } String::new() }\n",
        ),
        (
            "/w/m05_loop.rs",
            // grouped rename
            "use crate::m06_assign::{step_assign as SA};\npub fn step_loop(x: String) -> String { loop { return SA(x); } }\n",
        ),
        (
            "/w/m06_assign.rs",
            // plain crate path
            "use crate::m07_return::step_return;\npub fn step_assign(x: String) -> String { let y = step_return(x); y }\n",
        ),
        (
            "/w/m07_return.rs",
            // rename
            "use crate::m08_await::step_await as SW;\npub async fn step_return(x: String) -> String { return SW(x).await; }\n",
        ),
        (
            "/w/m08_await.rs",
            // wildcard
            "use crate::m09_sink::*;\npub async fn step_await(x: String) -> String { futures::future::ready(()).await; sink(x) }\n",
        ),
        (
            "/w/m09_sink.rs",
            "pub fn sink(x: String) -> String { std::process::Command::new(\"echo\").arg(&x).spawn().ok(); x }\n",
        ),
    ];
    let chain = [
        "entry",
        "step_if",
        "step_match",
        "step_for",
        "step_while",
        "step_loop",
        "step_assign",
        "step_return",
        "step_await",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Go — no try/catch/throw, but has defer; switch/type-switch; for; goroutines.
// ===========================================================================

#[test]
fn go_hell_chain() {
    // Varies: plain, aliased, dot, blank, grouped, stdlib.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_go::GoAdapter::new());
    let files = [
        (
            "/w/m00_entry.go",
            // aliased
            "package m00\nimport M01 \"w/m01\"\nfunc Entry() string { return M01.StepIf(\"tok\") }\n",
        ),
        (
            "/w/m01_if.go",
            // plain
            "package m01\nimport \"w/m02\"\nfunc StepIf(x string) string { if x != \"\" { return m02.StepSwitch(x) } ; return \"\" }\n",
        ),
        (
            "/w/m02_switch.go",
            // dot-import (symbols merged into this package's scope)
            "package m02\nimport . \"w/m03\"\nfunc StepSwitch(x string) string { switch x { case \"\": return \"\" ; default: return StepFor(x) } }\n",
        ),
        (
            "/w/m03_for.go",
            // grouped (two imports)
            "package m03\nimport (\n\t\"w/m04\"\n\t_ \"w/unused\"\n)\nfunc StepFor(x string) string { for i := 0; i < 1; i++ { return m04.StepRange(x) } ; return \"\" }\n",
        ),
        (
            "/w/m04_range.go",
            // aliased
            "package m04\nimport D \"w/m05\"\nfunc StepRange(x string) string { for _, y := range []string{x} { return D.StepDefer(y) } ; return \"\" }\n",
        ),
        (
            "/w/m05_defer.go",
            // blank + named (grouped)
            "package m05\nimport (\n\t_ \"w/m99_init\"\n\t\"w/m06\"\n)\nfunc StepDefer(x string) string { defer m06.StepAssign(x); return \"\" }\n",
        ),
        (
            "/w/m06_assign.go",
            "package m06\nimport \"w/m07\"\nfunc StepAssign(x string) string { y := m07.StepReturn(x); return y }\n",
        ),
        (
            "/w/m07_return.go",
            // aliased
            "package m07\nimport S \"w/m08\"\nfunc StepReturn(x string) string { return S.Sink(x) }\n",
        ),
        (
            "/w/m08_sink.go",
            // stdlib
            "package m08\nimport \"os/exec\"\nfunc Sink(x string) string { exec.Command(\"echo\", x).Run(); return x }\n",
        ),
    ];
    let chain = [
        "Entry",
        "StepIf",
        "StepSwitch",
        "StepFor",
        "StepRange",
        "StepDefer",
        "StepAssign",
        "StepReturn",
        "Sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// C — no try/catch/throw/foreach; has if, for, while, do-while, assign, return.
// ===========================================================================

#[test]
fn c_hell_chain() {
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_c::CAdapter::new());
    let files = [
        (
            "/w/m00_entry.c",
            "#include <m01_if.h>\nchar* entry(void) { return step_if(\"tok\"); }\n",
        ),
        (
            "/w/m01_if.h",
            "char* step_if(const char* x);\n",
        ),
        (
            "/w/m01_if.c",
            "#include <m01_if.h>\n#include \"m02_for.h\"\nchar* step_if(const char* x) { if (x) { return step_for(x); } return 0; }\n",
        ),
        (
            "/w/m02_for.h",
            "char* step_for(const char* x);\n",
        ),
        (
            "/w/m02_for.c",
            "#include \"m02_for.h\"\n#include \"m03_while.h\"\nchar* step_for(const char* x) { for (int i=0; i<1; i++) { return step_while(x); } return 0; }\n",
        ),
        (
            "/w/m03_while.h",
            "char* step_while(const char* x);\n",
        ),
        (
            "/w/m03_while.c",
            "#include \"m03_while.h\"\n#include \"m04_do.h\"\nchar* step_while(const char* x) { int i=0; while (i<1) { i++; return step_do(x); } return 0; }\n",
        ),
        (
            "/w/m04_do.h",
            "char* step_do(const char* x);\n",
        ),
        (
            "/w/m04_do.c",
            "#include \"m04_do.h\"\n#include \"m05_switch.h\"\nchar* step_do(const char* x) { do { return step_switch(x); } while (0); }\n",
        ),
        (
            "/w/m05_switch.h",
            "char* step_switch(const char* x);\n",
        ),
        (
            "/w/m05_switch.c",
            "#include \"m05_switch.h\"\n#include \"m06_assign.h\"\nchar* step_switch(const char* x) { switch (*x) { default: return step_assign(x); } }\n",
        ),
        (
            "/w/m06_assign.h",
            "char* step_assign(const char* x);\n",
        ),
        (
            "/w/m06_assign.c",
            "#include \"m06_assign.h\"\n#include \"m07_return.h\"\nchar* step_assign(const char* x) { char* y = step_return(x); return y; }\n",
        ),
        (
            "/w/m07_return.h",
            "char* step_return(const char* x);\n",
        ),
        (
            "/w/m07_return.c",
            "#include \"m07_return.h\"\n#include \"m08_sink.h\"\nchar* step_return(const char* x) { return sink(x); }\n",
        ),
        (
            "/w/m08_sink.h",
            "char* sink(const char* x);\n",
        ),
        (
            "/w/m08_sink.c",
            "#include <stdlib.h>\n#include \"m08_sink.h\"\nchar* sink(const char* x) { system(x); return (char*)x; }\n",
        ),
    ];
    let chain = [
        "entry",
        "step_if",
        "step_for",
        "step_while",
        "step_do",
        "step_switch",
        "step_assign",
        "step_return",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// C++ — C constructs + try/catch/throw/lambda/foreach.
// ===========================================================================

#[test]
fn cpp_hell_chain() {
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_cpp::CppAdapter::new());
    let files = [
        (
            "/w/m00_entry.cpp",
            "#include <m01_if.h>\nstd::string entry() { return stepIf(\"tok\"); }\n",
        ),
        (
            "/w/m01_if.h",
            "#include <string>\nstd::string stepIf(const std::string& x);\n",
        ),
        (
            "/w/m01_if.cpp",
            "#include <m01_if.h>\n#include \"m02_for.h\"\nstd::string stepIf(const std::string& x) { if (!x.empty()) { return stepFor(x); } return {}; }\n",
        ),
        (
            "/w/m02_for.h",
            "#include <string>\nstd::string stepFor(const std::string& x);\n",
        ),
        (
            "/w/m02_for.cpp",
            "#include \"m02_for.h\"\n#include \"m03_while.h\"\nstd::string stepFor(const std::string& x) { for (int i=0; i<1; i++) { return stepWhile(x); } return {}; }\n",
        ),
        (
            "/w/m03_while.h",
            "#include <string>\nstd::string stepWhile(const std::string& x);\n",
        ),
        (
            "/w/m03_while.cpp",
            "#include \"m03_while.h\"\n#include \"m04_foreach.h\"\nstd::string stepWhile(const std::string& x) { int i=0; while (i<1) { i++; return stepForEach(x); } return {}; }\n",
        ),
        (
            "/w/m04_foreach.h",
            "#include <string>\nstd::string stepForEach(const std::string& x);\n",
        ),
        (
            "/w/m04_foreach.cpp",
            "#include \"m04_foreach.h\"\n#include \"m05_try.h\"\n#include <vector>\nstd::string stepForEach(const std::string& x) { for (const auto& y : std::vector<std::string>{x}) { return stepTry(y); } return {}; }\n",
        ),
        (
            "/w/m05_try.h",
            "#include <string>\nstd::string stepTry(const std::string& x);\n",
        ),
        (
            "/w/m05_try.cpp",
            "#include \"m05_try.h\"\n#include \"m06_catch.h\"\nstd::string stepTry(const std::string& x) { try { return stepCatch(x); } catch (...) { return {}; } }\n",
        ),
        (
            "/w/m06_catch.h",
            "#include <string>\nstd::string stepCatch(const std::string& x);\n",
        ),
        (
            "/w/m06_catch.cpp",
            "#include \"m06_catch.h\"\n#include \"m07_assign.h\"\n#include <stdexcept>\nstd::string stepCatch(const std::string& x) { try { throw std::runtime_error(\"boom\"); } catch (const std::runtime_error&) { return stepAssign(x); } }\n",
        ),
        (
            "/w/m07_assign.h",
            "#include <string>\nstd::string stepAssign(const std::string& x);\n",
        ),
        (
            "/w/m07_assign.cpp",
            "#include \"m07_assign.h\"\n#include \"m08_return.h\"\nstd::string stepAssign(const std::string& x) { std::string y = stepReturn(x); return y; }\n",
        ),
        (
            "/w/m08_return.h",
            "#include <string>\nstd::string stepReturn(const std::string& x);\n",
        ),
        (
            "/w/m08_return.cpp",
            "#include \"m08_return.h\"\n#include \"m09_throw.h\"\nstd::string stepReturn(const std::string& x) { return stepThrow(x); }\n",
        ),
        (
            "/w/m09_throw.h",
            "#include <string>\nstd::string stepThrow(const std::string& x);\n",
        ),
        (
            "/w/m09_throw.cpp",
            "#include \"m09_throw.h\"\n#include \"m10_sink.h\"\n#include <stdexcept>\nstd::string stepThrow(const std::string& x) { throw std::runtime_error(sink(x)); }\n",
        ),
        (
            "/w/m10_sink.h",
            "#include <string>\nstd::string sink(const std::string& x);\n",
        ),
        (
            "/w/m10_sink.cpp",
            "#include \"m10_sink.h\"\n#include <cstdlib>\nstd::string sink(const std::string& x) { std::system(x.c_str()); return x; }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepForEach",
        "stepTry",
        "stepCatch",
        "stepAssign",
        "stepReturn",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Objective-C — C constructs + Obj-C try/catch/finally/throw/autorelease/@sync.
// ===========================================================================

#[test]
fn objc_hell_chain() {
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_objc::ObjCAdapter::new());
    let files = [
        (
            "/w/m00_entry.m",
            "#import \"m01_if.m\"\nNSString* entry(void) { return stepIf(@\"tok\"); }\n",
        ),
        (
            "/w/m01_if.m",
            "#import \"m02_for.m\"\nNSString* stepIf(NSString* x) { if (x) { return stepFor(x); } return nil; }\n",
        ),
        (
            "/w/m02_for.m",
            "#import \"m03_while.m\"\nNSString* stepFor(NSString* x) { for (int i=0; i<1; i++) { return stepWhile(x); } return nil; }\n",
        ),
        (
            "/w/m03_while.m",
            "#import \"m04_foreach.m\"\nNSString* stepWhile(NSString* x) { int i=0; while (i<1) { i++; return stepForEach(x); } return nil; }\n",
        ),
        (
            "/w/m04_foreach.m",
            "#import \"m05_try.m\"\nNSString* stepForEach(NSString* x) { for (NSString* y in @[x]) { return stepTry(y); } return nil; }\n",
        ),
        (
            "/w/m05_try.m",
            "#import \"m06_catch.m\"\nNSString* stepTry(NSString* x) { @try { return stepCatch(x); } @catch (NSException* e) { return nil; } }\n",
        ),
        (
            "/w/m06_catch.m",
            "#import \"m07_finally.m\"\nNSString* stepCatch(NSString* x) { @try { @throw [NSException exceptionWithName:@\"B\" reason:@\"r\" userInfo:nil]; } @catch (NSException* e) { return stepFinally(x); } }\n",
        ),
        (
            "/w/m07_finally.m",
            "#import \"m08_sync.m\"\nNSString* stepFinally(NSString* x) { @try { return nil; } @finally { return stepSync(x); } }\n",
        ),
        (
            "/w/m08_sync.m",
            "#import \"m09_autorelease.m\"\nNSString* stepSync(NSString* x) { @synchronized(x) { return stepAutorelease(x); } }\n",
        ),
        (
            "/w/m09_autorelease.m",
            "#import \"m10_assign.m\"\nNSString* stepAutorelease(NSString* x) { @autoreleasepool { return stepAssign(x); } }\n",
        ),
        (
            "/w/m10_assign.m",
            "#import \"m11_return.m\"\nNSString* stepAssign(NSString* x) { NSString* y = stepReturn(x); return y; }\n",
        ),
        (
            "/w/m11_return.m",
            "#import \"m12_throw.m\"\nNSString* stepReturn(NSString* x) { return stepThrow(x); }\n",
        ),
        (
            "/w/m12_throw.m",
            "#import \"m13_sink.m\"\nNSString* stepThrow(NSString* x) { NSString* r = sink(x); return r; }\n",
        ),
        (
            "/w/m13_sink.m",
            "#import <stdlib.h>\nNSString* sink(NSString* x) { system([x UTF8String]); return x; }\n",
        ),
    ];
    let chain = [
        "entry",
        "stepIf",
        "stepFor",
        "stepWhile",
        "stepForEach",
        "stepTry",
        "stepCatch",
        "stepFinally",
        "stepSync",
        "stepAutorelease",
        "stepAssign",
        "stepReturn",
        "stepThrow",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Perl — if/unless/for/while/until/eval block (try-analogue)/die (throw).
// ===========================================================================

#[test]
fn perl_hell_chain() {
    // Varies: `use Mod;`, `use Mod qw(sym);`, `use Mod ();`, `require Mod;`,
    // `require 'file.pm';`. Each hop picks a different shape.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_perl::PerlAdapter::new());
    let files = [
        (
            "/w/m00_entry.pl",
            // plain `use`
            "use M01If;\nsub entry { return M01If::step_if('tok'); }\n1;\n",
        ),
        (
            "/w/M01If.pm",
            // `use Mod qw(...)` — explicit export list
            "package M01If;\nuse M02For qw(step_for);\nsub step_if { my $x = shift; if ($x) { return M02For::step_for($x); } return undef; }\n1;\n",
        ),
        (
            "/w/M02For.pm",
            // `use Mod ();` — import nothing (suppress default exports)
            "package M02For;\nuse M03While ();\nsub step_for { my $x = shift; for (my $i=0; $i<1; $i++) { return M03While::step_while($x); } return undef; }\n1;\n",
        ),
        (
            "/w/M03While.pm",
            // `require Mod;` — runtime require
            "package M03While;\nrequire M04Until;\nsub step_while { my $x = shift; my $i=0; while ($i < 1) { $i++; return M04Until::step_until($x); } return undef; }\n1;\n",
        ),
        (
            "/w/M04Until.pm",
            // `require 'file.pm'` — string path form
            "package M04Until;\nrequire 'M05Foreach.pm';\nsub step_until { my $x = shift; my $i=0; until ($i >= 1) { $i++; return M05Foreach::step_foreach($x); } return undef; }\n1;\n",
        ),
        (
            "/w/M05Foreach.pm",
            // plain `use`
            "package M05Foreach;\nuse M06Eval;\nsub step_foreach { my $x = shift; foreach my $y (($x)) { return M06Eval::step_eval($y); } return undef; }\n1;\n",
        ),
        (
            "/w/M06Eval.pm",
            // `use Mod qw(...)`
            "package M06Eval;\nuse M07Assign qw(step_assign);\nsub step_eval { my $x = shift; my $r = eval { M07Assign::step_assign($x) }; return $r; }\n1;\n",
        ),
        (
            "/w/M07Assign.pm",
            // `require`
            "package M07Assign;\nrequire M08Return;\nsub step_assign { my $x = shift; my $y = M08Return::step_return($x); return $y; }\n1;\n",
        ),
        (
            "/w/M08Return.pm",
            // `use Mod ();`
            "package M08Return;\nuse M09Die ();\nsub step_return { my $x = shift; return M09Die::step_die($x); }\n1;\n",
        ),
        (
            "/w/M09Die.pm",
            // `require 'file'`
            "package M09Die;\nrequire 'M10Sink.pm';\nsub step_die { my $x = shift; my $r = M10Sink::sink($x); die $r; }\n1;\n",
        ),
        (
            "/w/M10Sink.pm",
            "package M10Sink;\nsub sink { my $x = shift; system(\"echo $x\"); return $x; }\n1;\n",
        ),
    ];
    let chain = [
        "entry",
        "step_if",
        "step_for",
        "step_while",
        "step_until",
        "step_foreach",
        "step_eval",
        "step_assign",
        "step_return",
        "step_die",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Lua — if/for/while/repeat/pcall (try-analogue)/assign/return.
// ===========================================================================

#[test]
fn lua_hell_chain() {
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_lua::LuaAdapter::new());
    let files = [
        (
            "/w/m00_entry.lua",
            "local if_mod = require('m01_if')\nfunction entry() return if_mod.step_if('tok') end\n",
        ),
        (
            "/w/m01_if.lua",
            "local for_mod = require('m02_for')\nlocal M = {}\nfunction M.step_if(x) if x then return for_mod.step_for(x) end ; return nil end\nreturn M\n",
        ),
        (
            "/w/m02_for.lua",
            "local while_mod = require('m03_while')\nlocal M = {}\nfunction M.step_for(x) for i=1,1 do return while_mod.step_while(x) end ; return nil end\nreturn M\n",
        ),
        (
            "/w/m03_while.lua",
            "local forin_mod = require('m04_forin')\nlocal M = {}\nfunction M.step_while(x) local i=0 while i < 1 do i=i+1 return forin_mod.step_forin(x) end ; return nil end\nreturn M\n",
        ),
        (
            "/w/m04_forin.lua",
            "local repeat_mod = require('m05_repeat')\nlocal M = {}\nfunction M.step_forin(x) for _, y in ipairs({x}) do return repeat_mod.step_repeat(y) end ; return nil end\nreturn M\n",
        ),
        (
            "/w/m05_repeat.lua",
            "local pcall_mod = require('m06_pcall')\nlocal M = {}\nfunction M.step_repeat(x) repeat return pcall_mod.step_pcall(x) until true end\nreturn M\n",
        ),
        (
            "/w/m06_pcall.lua",
            "local assign_mod = require('m07_assign')\nlocal M = {}\nfunction M.step_pcall(x) local r = assign_mod.step_assign(x) ; pcall(function() return nil end) ; return r end\nreturn M\n",
        ),
        (
            "/w/m07_assign.lua",
            "local return_mod = require('m08_return')\nlocal M = {}\nfunction M.step_assign(x) local y = return_mod.step_return(x) ; return y end\nreturn M\n",
        ),
        (
            "/w/m08_return.lua",
            "local sink_mod = require('m09_sink')\nlocal M = {}\nfunction M.step_return(x) return sink_mod.sink(x) end\nreturn M\n",
        ),
        (
            "/w/m09_sink.lua",
            "local M = {}\nfunction M.sink(x) os.execute('echo ' .. x) ; return x end\nreturn M\n",
        ),
    ];
    let chain = [
        "entry",
        "step_if",
        "step_for",
        "step_while",
        "step_forin",
        "step_repeat",
        "step_pcall",
        "step_assign",
        "step_return",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Elixir — case/cond/for-comp/try+rescue+after/raise/assign.
// ===========================================================================

#[test]
fn elixir_hell_chain() {
    // Varies: `alias`, `alias ..., as:`, `import`, `require`, `use`.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let files = [
        (
            "/w/m00_entry.ex",
            // alias
            "defmodule Entry do\n  alias M01If\n  def entry, do: M01If.step_if(\"tok\")\nend\n",
        ),
        (
            "/w/m01_if.ex",
            // alias ..., as:
            "defmodule M01If do\n  alias M02Case, as: CaseMod\n  def step_if(x) do\n    if x != nil do\n      CaseMod.step_case(x)\n    end\n  end\nend\n",
        ),
        (
            "/w/m02_case.ex",
            // import
            "defmodule M02Case do\n  import M03Cond\n  def step_case(x) do\n    case x do\n      nil -> nil\n      _ -> step_cond(x)\n    end\n  end\nend\n",
        ),
        (
            "/w/m03_cond.ex",
            // require
            "defmodule M03Cond do\n  require M04For\n  def step_cond(x) do\n    cond do\n      x == nil -> nil\n      true -> M04For.step_for(x)\n    end\n  end\nend\n",
        ),
        (
            "/w/m04_for.ex",
            // use
            "defmodule M04For do\n  use M05Try\n  alias M05Try\n  def step_for(x) do\n    for _ <- [1] do\n      M05Try.step_try(x)\n    end |> List.first()\n  end\nend\n",
        ),
        (
            "/w/m05_try.ex",
            // alias ..., as:
            "defmodule M05Try do\n  defmacro __using__(_), do: nil\n  alias M06Rescue, as: R\n  def step_try(x) do\n    try do\n      R.step_rescue(x)\n    rescue\n      _ -> nil\n    end\n  end\nend\n",
        ),
        (
            "/w/m06_rescue.ex",
            // import
            "defmodule M06Rescue do\n  import M07After\n  def step_rescue(x) do\n    try do\n      raise \"boom\"\n    rescue\n      _ -> step_after(x)\n    end\n  end\nend\n",
        ),
        (
            "/w/m07_after.ex",
            // require
            "defmodule M07After do\n  require M08Assign\n  def step_after(x) do\n    try do\n      nil\n    after\n      M08Assign.step_assign(x)\n    end\n  end\nend\n",
        ),
        (
            "/w/m08_assign.ex",
            // alias
            "defmodule M08Assign do\n  alias M09Raise\n  def step_assign(x) do\n    y = M09Raise.step_raise(x)\n    y\n  end\nend\n",
        ),
        (
            "/w/m09_raise.ex",
            // alias ..., as:
            "defmodule M09Raise do\n  alias M10Sink, as: Sk\n  def step_raise(x) do\n    r = Sk.sink(x)\n    raise r\n  end\nend\n",
        ),
        (
            "/w/m10_sink.ex",
            "defmodule M10Sink do\n  def sink(x) do\n    System.cmd(\"echo\", [x])\n    x\n  end\nend\n",
        ),
    ];
    let chain = [
        "entry",
        "step_if",
        "step_case",
        "step_cond",
        "step_for",
        "step_try",
        "step_rescue",
        "step_after",
        "step_assign",
        "step_raise",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}

// ===========================================================================
// Erlang — case/if/try/catch/list-comp/assign (match_expr).
// ===========================================================================

#[test]
fn erlang_hell_chain() {
    // Varies: `-import(Mod, [f/n]).`, plain `Mod:fn/1` remote call,
    // `-include("x.hrl").`, `-include_lib("app/include/x.hrl").`.
    let adapter: bonsai_lang_api::AdapterArc = Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let files = [
        (
            "/w/m00_entry.erl",
            // -import + explicit Mod:call
            "-module(m00_entry).\n-export([entry/0]).\n-import(m01_if, [step_if/1]).\nentry() -> m01_if:step_if(\"tok\").\n",
        ),
        (
            "/w/m01_if.erl",
            // include a header
            "-module(m01_if).\n-export([step_if/1]).\n-include(\"m02_case_hdr.hrl\").\nstep_if(X) ->\n  if X =/= undefined -> m02_case:step_case(X); true -> undefined end.\n",
        ),
        (
            "/w/m02_case_hdr.hrl",
            "-define(M02_HDR, ok).\n",
        ),
        (
            "/w/m02_case.erl",
            // -import
            "-module(m02_case).\n-export([step_case/1]).\n-import(m03_lc, [step_lc/1]).\nstep_case(X) ->\n  case X of\n    undefined -> undefined;\n    _ -> step_lc(X)\n  end.\n",
        ),
        (
            "/w/m03_lc.erl",
            // include_lib
            "-module(m03_lc).\n-export([step_lc/1]).\n-include_lib(\"stdlib/include/assert.hrl\").\nstep_lc(X) ->\n  Rs = [m04_try:step_try(Y) || Y <- [X]],\n  hd(Rs).\n",
        ),
        (
            "/w/m04_try.erl",
            // plain (no explicit import — rely on Mod:fn/1)
            "-module(m04_try).\n-export([step_try/1]).\nstep_try(X) ->\n  try m05_catch:step_catch(X) of\n    R -> R\n  catch\n    _:_ -> undefined\n  end.\n",
        ),
        (
            "/w/m05_catch.erl",
            // -import
            "-module(m05_catch).\n-export([step_catch/1]).\n-import(m06_after, [step_after/1]).\nstep_catch(X) ->\n  try erlang:error(boom) of\n    _ -> undefined\n  catch\n    _:_ -> step_after(X)\n  end.\n",
        ),
        (
            "/w/m06_after.erl",
            // include
            "-module(m06_after).\n-export([step_after/1]).\n-include(\"m07_match_hdr.hrl\").\nstep_after(X) ->\n  try undefined\n  after\n    m07_match:step_match(X)\n  end.\n",
        ),
        (
            "/w/m07_match_hdr.hrl",
            "-define(M07_HDR, ok).\n",
        ),
        (
            "/w/m07_match.erl",
            // plain
            "-module(m07_match).\n-export([step_match/1]).\nstep_match(X) ->\n  Y = m08_throw:step_throw(X),\n  Y.\n",
        ),
        (
            "/w/m08_throw.erl",
            // -import
            "-module(m08_throw).\n-export([step_throw/1]).\n-import(m09_sink, [sink/1]).\nstep_throw(X) ->\n  R = sink(X),\n  throw(R).\n",
        ),
        (
            "/w/m09_sink.erl",
            "-module(m09_sink).\n-export([sink/1]).\nsink(X) ->\n  os:cmd(\"echo \" ++ X),\n  X.\n",
        ),
    ];
    let chain = [
        "entry",
        "step_if",
        "step_case",
        "step_lc",
        "step_try",
        "step_catch",
        "step_after",
        "step_match",
        "step_throw",
        "sink",
    ];
    run_chain(adapter, &files, &chain);
}
