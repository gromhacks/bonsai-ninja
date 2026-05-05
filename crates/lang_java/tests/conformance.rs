use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("A.java", "class A { public static void main(String[] s) {} }")]
    );
}
