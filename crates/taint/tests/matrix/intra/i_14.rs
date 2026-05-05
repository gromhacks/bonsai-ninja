//! I_14 — Catch param propagates further.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_14_python() {
    run_positive_cell("I_14", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def entry(args):\n    try:\n        raise Exception(args)\n    except Exception as e:\n        copy = e\n        sink(copy)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_javascript() {
    run_positive_cell("I_14", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function entry(args) { try { throw new Error(args); } catch (e) { const copy = e; sink(copy); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_typescript() {
    run_positive_cell("I_14", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function entry(args: string) { try { throw new Error(args); } catch (e) { const copy = e; sink(copy); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_kotlin() {
    run_positive_cell("I_14", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun entry(args: String) { try { throw RuntimeException(args) } catch (e: Exception) { val copy = e; sink(copy) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_scala() {
    run_positive_cell("I_14", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def entry(args: String): Unit = { try { throw new RuntimeException(args) } catch { case e: Exception => val copy = e; sink(copy) } } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_php() {
    run_positive_cell("I_14", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction entry($args) { try { throw new Exception($args); } catch (Exception $e) { $copy = $e; sink($copy); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
