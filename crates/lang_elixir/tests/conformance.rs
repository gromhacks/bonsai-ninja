use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> =
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [(
            "main.ex",
            "defmodule Main do\n  def main do\n    helper()\n  end\n  def helper do\n    :ok\n  end\nend\n"
        )]
    );
}
