//! Conformance suite (spec §30).
//!
//! Language adapters run the `run_language_suite!` macro in their test
//! module. The macro expands to a set of smoke tests every adapter must
//! pass: workspace ingestion, declaration extraction, resolution, HIR
//! lowering, CFG construction, and trace emission.

use bonsai_lang_api::LanguageAdapter;
use bonsai_testkit::workspace_with;
use bonsai_workspace::Workspace;
use std::sync::Arc;

/// The conformance runner takes an adapter + a set of sample files and
/// exercises the workspace through each pipeline stage.
pub struct ConformanceRunner {
    pub adapter: Arc<dyn LanguageAdapter>,
    pub fixtures: Vec<(String, String)>,
}

impl ConformanceRunner {
    /// Bundle an adapter with fixtures the conformance harness will
    /// ingest before each smoke / trace assertion runs.
    #[must_use]
    pub fn new(adapter: Arc<dyn LanguageAdapter>, fixtures: Vec<(String, String)>) -> Self {
        Self { adapter, fixtures }
    }

    /// Build a fresh workspace with this adapter registered and every
    /// fixture written into the VFS.
    #[must_use]
    pub fn workspace(&self) -> Workspace {
        let owned: Vec<(&str, &str)> = self
            .fixtures
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        workspace_with(vec![self.adapter.clone()], &owned)
    }

    /// Sanity check: parse every fixture, extract decls, and assert
    /// at least one decl was produced. Catches the common adapter bug
    /// where `FN_KINDS` doesn't match real tree-sitter node names.
    pub fn run_smoke(&self) {
        let ws = self.workspace();
        assert!(
            !ws.vfs().all_files().is_empty(),
            "conformance fixture has no files"
        );
        let mut total_decls = 0usize;
        for f in ws.vfs().all_files() {
            let parsed = ws
                .db()
                .parse(f)
                .unwrap_or_else(|e| panic!("parse failed for {f:?}: {e:?}"));
            assert!(
                parsed.tree.root_node().kind_id() > 0,
                "parsed tree has no root for {f:?}"
            );
            let decls = ws
                .db()
                .decl_index(f)
                .unwrap_or_else(|| panic!("decl_index returned None for {f:?}"));
            total_decls += decls.defs.len();
        }
        assert!(
            total_decls > 0,
            "adapter extracted zero declarations across the whole fixture — \
             this would make traces trivially empty. Ensure the adapter's FN_KINDS match \
             the real tree-sitter node names for this language."
        );
    }

    /// Run the smoke suite and additionally assert that `function_name` is
    /// extracted from at least one fixture, that it lowers to a CFG (even if
    /// the CFG only has an unreachable block — we are gating on
    /// adapter wiring, not semantic depth), and that a trace yields at least
    /// one `EnterFunction` step. Adapters should graduate from `run_smoke`
    /// to this once they have their declaration extraction right.
    pub fn run_traced(&self, function_name: &str) {
        self.run_smoke();
        let ws = self.workspace();
        let func = ws
            .lookup_function(function_name)
            .unwrap_or_else(|| panic!("function `{function_name}` not found in fixture"));
        let cfg = ws.db().cfg(func);
        assert!(!cfg.blocks.is_empty(), "cfg for `{function_name}` is empty");
        let trace = ws.db().trace_function(func, Default::default());
        assert!(
            !trace.steps.is_empty(),
            "trace from `{function_name}` produced no steps"
        );
    }
}

/// Declare a conformance suite for an adapter.
///
/// ```no_run
/// # use std::sync::Arc;
/// # use bonsai_conformance::run_language_suite;
/// # struct StubAdapter;
/// # impl bonsai_lang_api::LanguageAdapter for StubAdapter {
/// #     fn language_id(&self) -> bonsai_lang_api::LanguageId { bonsai_lang_api::LanguageId::new("stub") }
/// #     fn display_name(&self) -> &'static str { "stub" }
/// #     fn file_extensions(&self) -> &'static [&'static str] { &["stub"] }
/// #     fn tree_sitter_language(&self) -> Result<tree_sitter::Language, bonsai_lang_api::AdapterError> {
/// #         Err(bonsai_lang_api::AdapterError::GrammarUnavailable("stub".into()))
/// #     }
/// #     fn capabilities(&self) -> bonsai_lang_api::LanguageCapabilities { bonsai_lang_api::LanguageCapabilities::unsupported() }
/// #     fn extract_declarations(&self, _: bonsai_common::FileId, _: &bonsai_lang_api::AdapterContext<'_>) -> bonsai_lang_api::DeclIndex { Default::default() }
/// #     fn extract_imports(&self, _: bonsai_common::FileId, _: &bonsai_lang_api::AdapterContext<'_>) -> bonsai_lang_api::ImportIndex { Default::default() }
/// # }
/// # let adapter = Arc::new(StubAdapter);
/// run_language_suite!(adapter, []);
/// ```
#[macro_export]
macro_rules! run_language_suite {
    ($adapter:expr, [ $( ($path:expr, $text:expr) ),* $(,)? ]) => {{
        let adapter: ::std::sync::Arc<dyn $crate::reexport::LanguageAdapter> = $adapter;
        let runner = $crate::ConformanceRunner::new(
            adapter,
            vec![ $( (String::from($path), String::from($text)), )* ],
        );
        runner.run_smoke();
    }};
    ($adapter:expr, trace_from = $fname:expr, [ $( ($path:expr, $text:expr) ),* $(,)? ]) => {{
        let adapter: ::std::sync::Arc<dyn $crate::reexport::LanguageAdapter> = $adapter;
        let runner = $crate::ConformanceRunner::new(
            adapter,
            vec![ $( (String::from($path), String::from($text)), )* ],
        );
        runner.run_traced($fname);
    }};
}

/// Re-exports that the macro relies on.
pub mod reexport {
    pub use bonsai_lang_api::LanguageAdapter;
}
