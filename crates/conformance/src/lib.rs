//! Conformance suite (spec §30).
//!
//! Language adapters run the `run_language_suite!` macro in their test
//! module. The macro expands to a set of smoke tests every adapter must
//! pass: workspace ingestion, declaration extraction, resolution, HIR
//! lowering, CFG construction, and trace emission.

pub mod capability_matrix;

use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    AdapterContext, AdapterError, Decl, DeclIndex, FileSnapshot, FlowEvent, FragmentParseContext,
    ImportIndex, LanguageAdapter, LanguageCapabilities, LanguageId, LanguageOwnershipEvidence,
    LanguageRegistry, ParseRecoveryEdit, SourceFileRepresentation, SyntaxTree, TreeProvider,
    UnsupportedConstruct, Vfs, WorkspaceRoot,
};
use bonsai_testkit::workspace_with;
use bonsai_workspace::{Workspace, WorkspaceOpenOptions};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

fn isolated_cache_environment(cache: &Path) -> (MutexGuard<'static, ()>, ScopedEnvironmentRestore) {
    static CACHE_ENVIRONMENT: Mutex<()> = Mutex::new(());
    let lock = CACHE_ENVIRONMENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = std::env::var_os("BONSAI_WORKSPACE_DIR");
    std::env::set_var("BONSAI_WORKSPACE_DIR", cache);
    (
        lock,
        ScopedEnvironmentRestore {
            key: "BONSAI_WORKSPACE_DIR",
            previous,
        },
    )
}

struct ScopedEnvironmentRestore {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl Drop for ScopedEnvironmentRestore {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

/// Transparent frontend probe used by the shared adapter suite.
///
/// Every optional frontend hook delegates to the real adapter so the probe
/// cannot accidentally simplify grammar selection or recovery. Only the two
/// canonical lowering entry points are counted. The semantic replay test can
/// therefore prove that linkage, callgraph, and IDG phases consume persisted
/// compiler IR without silently invoking a language adapter again.
struct CountingAdapter {
    inner: Arc<dyn LanguageAdapter>,
    declaration_calls: AtomicUsize,
    import_calls: AtomicUsize,
}

/// Counts syntax-tree acquisitions made inside one adapter lowering entry
/// point while delegating the actual parse/cache semantics to the analyzer.
/// A cache hit is still an acquisition: repeatedly reopening the same tree
/// duplicates snapshot/cache work and permits custom passes to drift apart.
struct CountingTreeProvider<'a> {
    inner: &'a dyn TreeProvider,
    calls: AtomicUsize,
}

impl<'a> CountingTreeProvider<'a> {
    fn new(inner: &'a dyn TreeProvider) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl TreeProvider for CountingTreeProvider<'_> {
    fn tree_for_snapshot(&self, pack_name: &str, snapshot: &FileSnapshot) -> Option<Arc<SyntaxTree>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.tree_for_snapshot(pack_name, snapshot)
    }
}

impl CountingAdapter {
    fn new(inner: Arc<dyn LanguageAdapter>) -> Self {
        Self {
            inner,
            declaration_calls: AtomicUsize::new(0),
            import_calls: AtomicUsize::new(0),
        }
    }

    fn lowering_calls(&self) -> (usize, usize) {
        (
            self.declaration_calls.load(Ordering::SeqCst),
            self.import_calls.load(Ordering::SeqCst),
        )
    }
}

impl LanguageAdapter for CountingAdapter {
    fn language_id(&self) -> LanguageId {
        self.inner.language_id()
    }

    fn display_name(&self) -> &'static str {
        self.inner.display_name()
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        self.inner.file_extensions()
    }

    fn source_file_representation(&self, path: &Path) -> SourceFileRepresentation {
        self.inner.source_file_representation(path)
    }

    fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError> {
        self.inner.tree_sitter_language()
    }

    fn source_syntax_proves_language(
        &self,
        snapshot: &FileSnapshot,
        tree: &SyntaxTree,
    ) -> LanguageOwnershipEvidence {
        self.inner.source_syntax_proves_language(snapshot, tree)
    }

    fn grammar_name_for_path(&self, path: &Path) -> &'static str {
        self.inner.grammar_name_for_path(path)
    }

    fn tree_sitter_language_for_path(&self, path: &Path) -> Result<tree_sitter::Language, AdapterError> {
        self.inner.tree_sitter_language_for_path(path)
    }

    fn parse_normalization_edits(
        &self,
        snapshot: &FileSnapshot,
        vfs: &bonsai_vfs::Vfs,
    ) -> Vec<ParseRecoveryEdit> {
        self.inner.parse_normalization_edits(snapshot, vfs)
    }

    fn parse_context_fingerprint(&self, snapshot: &FileSnapshot, vfs: &Vfs) -> u64 {
        self.inner.parse_context_fingerprint(snapshot, vfs)
    }

    fn parse_recovery_edits(
        &self,
        snapshot: &FileSnapshot,
        vfs: &bonsai_vfs::Vfs,
        tree: &SyntaxTree,
    ) -> Vec<ParseRecoveryEdit> {
        self.inner.parse_recovery_edits(snapshot, vfs, tree)
    }

    fn parse_recovery_edit_batches(
        &self,
        snapshot: &FileSnapshot,
        vfs: &bonsai_vfs::Vfs,
        tree: &SyntaxTree,
    ) -> Vec<Vec<ParseRecoveryEdit>> {
        self.inner.parse_recovery_edit_batches(snapshot, vfs, tree)
    }

    fn fragment_parse_context(&self) -> FragmentParseContext {
        self.inner.fragment_parse_context()
    }

    fn capabilities(&self) -> LanguageCapabilities {
        self.inner.capabilities()
    }

    fn grammar_handler(&self) -> Option<&'static bonsai_lang_api::GrammarHandler> {
        self.inner.grammar_handler()
    }

    fn grammar_handler_for_path(&self, path: &Path) -> Option<&'static bonsai_lang_api::GrammarHandler> {
        self.inner.grammar_handler_for_path(path)
    }

    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        self.inner.additional_grammar_node_kinds()
    }

    fn additional_grammar_node_kinds_for_path(&self, path: &Path) -> &'static [(&'static str, &'static str)] {
        self.inner.additional_grammar_node_kinds_for_path(path)
    }

    fn discover_workspace_roots(&self, files: &[FileId], ctx: &AdapterContext<'_>) -> Vec<WorkspaceRoot> {
        self.inner.discover_workspace_roots(files, ctx)
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        self.declaration_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.extract_declarations(file, ctx)
    }

    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        self.import_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.extract_imports(file, ctx)
    }

    fn unsupported_constructs(&self, file: FileId, ctx: &AdapterContext<'_>) -> Vec<UnsupportedConstruct> {
        self.inner.unsupported_constructs(file, ctx)
    }
}

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

    /// Sanity check every adapter-owned compiler boundary.
    ///
    /// This intentionally validates more than "the parser returned a tree":
    /// valid fixtures must parse without recovery diagnostics, repeated
    /// lowering must be deterministic, declaration metadata must be
    /// internally consistent, and every serialized compiler span must refer
    /// to a UTF-8 boundary in the exact parsed source snapshot. Keeping these
    /// checks here makes them mandatory for every adapter using
    /// [`run_language_suite!`].
    pub fn run_smoke(&self) {
        validate_grammar_contract(self.adapter.as_ref());
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
            assert_eq!(
                parsed.adapter_id,
                self.adapter.language_id(),
                "registry selected the wrong adapter for {f:?}"
            );
            assert!(
                !parsed.tree.root_node().has_error(),
                "valid conformance fixture has Tree-sitter errors for {f:?}: {:?}",
                parsed.diagnostics
            );
            assert!(
                parsed.diagnostics.is_empty(),
                "valid conformance fixture emitted parser diagnostics for {f:?}: {:?}",
                parsed.diagnostics
            );
            let reparsed = ws
                .db()
                .parse(f)
                .unwrap_or_else(|e| panic!("repeat parse failed for {f:?}: {e:?}"));
            assert_eq!(parsed.adapter_id, reparsed.adapter_id);
            assert_eq!(parsed.grammar_name, reparsed.grammar_name);
            assert_eq!(parsed.source_text(), reparsed.source_text());
            assert_eq!(
                parsed.tree.root_node().to_sexp(),
                reparsed.tree.root_node().to_sexp(),
                "repeat parse changed the syntax tree for {f:?}"
            );
            let decls = ws
                .db()
                .decl_index(f)
                .unwrap_or_else(|| panic!("decl_index returned None for {f:?}"));
            let repeated_decls = ws
                .db()
                .decl_index(f)
                .unwrap_or_else(|| panic!("repeat decl_index returned None for {f:?}"));
            assert_eq!(
                decls, repeated_decls,
                "declaration lowering is nondeterministic for {f:?}"
            );
            validate_decl_index(f, parsed.source_text(), &decls);
            let imports = ws
                .db()
                .import_index(f)
                .unwrap_or_else(|| panic!("import_index returned None for {f:?}"));
            let repeated_imports = ws
                .db()
                .import_index(f)
                .unwrap_or_else(|| panic!("repeat import_index returned None for {f:?}"));
            assert_eq!(
                imports, repeated_imports,
                "import lowering is nondeterministic for {f:?}"
            );
            assert_eq!(imports.file, f, "import index is attached to the wrong file");
            for import in &imports.imports {
                validate_span(f, parsed.source_text(), import.span, "import");
                assert!(
                    !import.module.trim().is_empty(),
                    "adapter emitted an empty import module"
                );
            }
            total_decls += decls.defs.len();
        }
        assert!(
            total_decls > 0,
            "adapter extracted zero declarations across the whole fixture — \
             this would make traces trivially empty. Ensure the adapter's FN_KINDS match \
             the real tree-sitter node names for this language."
        );
        self.validate_single_tree_acquisition(&ws);
        self.run_semantic_replay();
    }

    /// Every canonical adapter entry point gets one immutable syntax tree and
    /// performs all of its projections from that tree. This executable check
    /// catches indirect helper reparsing that a source-level architecture
    /// invariant cannot see.
    fn validate_single_tree_acquisition(&self, workspace: &Workspace) {
        for file in workspace.vfs().all_files() {
            let declarations = CountingTreeProvider::new(workspace.db());
            let diagnostics = parking_lot::RwLock::new(bonsai_diagnostics::DiagnosticSink::default());
            let ctx = AdapterContext {
                vfs: workspace.vfs(),
                diagnostics: &diagnostics,
                tree_provider: Some(&declarations),
                workspace_root: None,
            };
            let index = self.adapter.extract_declarations(file, &ctx);
            assert_eq!(index.file, file);
            assert_eq!(
                declarations.calls(),
                1,
                "{}: declaration lowering must acquire one exact Tree-sitter tree for {file:?}",
                self.adapter.language_id().as_str()
            );

            let imports = CountingTreeProvider::new(workspace.db());
            let diagnostics = parking_lot::RwLock::new(bonsai_diagnostics::DiagnosticSink::default());
            let ctx = AdapterContext {
                vfs: workspace.vfs(),
                diagnostics: &diagnostics,
                tree_provider: Some(&imports),
                workspace_root: None,
            };
            let index = self.adapter.extract_imports(file, &ctx);
            assert_eq!(index.file, file);
            assert_eq!(
                imports.calls(),
                1,
                "{}: import lowering must acquire one exact Tree-sitter tree for {file:?}",
                self.adapter.language_id().as_str()
            );
        }
    }

    /// Prove that the complete semantic pipeline reuses one exact frontend
    /// generation for this language.
    ///
    /// The first compiler-object pass must invoke each adapter lowering once.
    /// Re-saving the unchanged generation, decoding its independent headers,
    /// building workspace linkage, resolving the callgraph, and constructing
    /// the IDG must not invoke either lowering entry point again. This catches
    /// accidental reparsing/re-lowering in every supported language rather
    /// than relying on the dedicated Python counter fixture alone.
    fn run_semantic_replay(&self) {
        let probe = Arc::new(CountingAdapter::new(Arc::clone(&self.adapter)));
        let adapter: Arc<dyn LanguageAdapter> = probe.clone();
        let root = tempfile::tempdir().expect("semantic replay tempdir");
        let cache = root.path().join("cache");
        let (_environment_lock, _environment_restore) = isolated_cache_environment(&cache);
        for (path, text) in &self.fixtures {
            let path = root.path().join(path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create semantic replay fixture parent");
            }
            std::fs::write(path, text).expect("write semantic replay fixture");
        }
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(adapter);
        let ws = Workspace::open_with_options(
            root.path(),
            registry,
            WorkspaceOpenOptions::sidecar_validation_only(),
        )
        .expect("open complete semantic replay workspace");
        let files = ws.vfs().all_files();
        assert!(!files.is_empty(), "semantic replay fixture has no files");

        let written = ws
            .save_compiler_object_sidecar(root.path())
            .expect("persist exact compiler objects");
        assert_eq!(written, files.len());
        assert_eq!(
            probe.lowering_calls(),
            (files.len(), files.len()),
            "the canonical compiler-object pass must lower declarations and imports exactly once per file"
        );

        let rewritten = ws
            .save_compiler_object_sidecar(root.path())
            .expect("reuse exact compiler objects");
        assert_eq!(rewritten, files.len());
        for file in &files {
            assert!(
                ws.db().compiler_import_index_uncached(*file).is_some(),
                "persisted import header is missing for {file:?}"
            );
            assert!(
                ws.db().compiler_syntax_header_uncached(*file).is_some(),
                "persisted syntax header is missing for {file:?}"
            );
            assert!(
                ws.db().compiler_file_object_uncached(*file).is_some(),
                "persisted compiler body is missing for {file:?}"
            );
        }
        assert_eq!(
            probe.lowering_calls(),
            (files.len(), files.len()),
            "unchanged compiler objects and independent headers must replay without adapter lowering"
        );

        let linkage = ws.compiler_linkage_index();
        assert_eq!(linkage.all_files().count(), files.len());
        let callgraph = ws.cached_resolved_call_graph();
        assert!(callgraph.nodes().iter().all(|node| {
            linkage
                .decl_of(SymbolId::new(node.func.raw()))
                .is_some_and(|decl| decl.span.file == node.file)
        }));
        let _idg = ws.build_and_seed_idg_service();
        assert_eq!(
            probe.lowering_calls(),
            (files.len(), files.len()),
            "linkage, callgraph, and IDG phases must stream persisted compiler IR without reparsing or re-lowering"
        );

        let _ = std::fs::remove_dir_all(bonsai_common::workspace_bonsai_dir(root.path()));
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
        assert!(
            cfg.analysis_complete,
            "CFG for `{function_name}` is incomplete: {:?}",
            cfg.analysis_incomplete_reasons
        );
        assert!(cfg.analysis_incomplete_reasons.is_empty());
        assert!(cfg.block(cfg.entry).is_some(), "CFG entry block is invalid");
        assert!(cfg.block(cfg.exit).is_some(), "CFG exit block is invalid");
        for (index, block) in cfg.blocks.iter().enumerate() {
            assert_eq!(
                usize::try_from(block.id.raw()).expect("block id fits usize"),
                index,
                "CFG block ids must be dense and stable"
            );
            for successor in &block.successors {
                assert!(
                    cfg.block(*successor).is_some(),
                    "CFG block {:?} has dangling successor {successor:?}",
                    block.id
                );
            }
            let snapshot = ws
                .vfs()
                .snapshot(block.span.file)
                .unwrap_or_else(|error| panic!("CFG block refers to a missing file: {error}"));
            validate_span(block.span.file, &snapshot.text, block.span, "CFG block");
            for event in &block.events {
                validate_span(block.span.file, &snapshot.text, event.span(), "CFG event");
            }
        }
        let trace = ws.db().trace_function(func, Default::default());
        assert!(
            !trace.steps.is_empty(),
            "trace from `{function_name}` produced no steps"
        );
        assert!(
            trace
                .steps
                .iter()
                .any(|step| step.kind == bonsai_trace::TraceStepKind::EnterFunction),
            "trace from `{function_name}` has no EnterFunction step"
        );
        assert_eq!(trace.summary.total_steps, trace.steps.len());
        for (index, step) in trace.steps.iter().enumerate() {
            assert_eq!(step.id, index as u64, "trace step ids must be dense");
            assert_eq!(step.order, index as u64 + 1, "trace order must be one-based");
            assert!(step.span.start_byte <= step.span.end_byte);
        }
        let step_ids: BTreeSet<u64> = trace.steps.iter().map(|step| step.id).collect();
        for edge in &trace.edges {
            assert!(
                step_ids.contains(&edge.from_step),
                "trace edge has dangling source"
            );
            assert!(step_ids.contains(&edge.to_step), "trace edge has dangling target");
        }
        let state_ids: BTreeSet<u32> = trace.states.iter().map(|state| state.id).collect();
        for step in &trace.steps {
            for state in [step.state_before, step.state_after].into_iter().flatten() {
                assert!(
                    state_ids.contains(&state),
                    "trace step refers to missing state {state}"
                );
            }
        }
    }
}

fn validate_grammar_contract(adapter: &dyn LanguageAdapter) {
    adapter.grammar_handler().unwrap_or_else(|| {
        panic!(
            "{}: production adapter does not expose its GrammarHandler to conformance",
            adapter.language_id().as_str()
        )
    });
    let additional = adapter.additional_grammar_node_kinds();
    assert!(
        !additional.is_empty(),
        "{}: adapter-specific Tree-sitter consumers have no executable node-kind inventory",
        adapter.language_id().as_str()
    );
    let mut grammar_names = BTreeSet::new();
    let mut grammars = Vec::new();
    for extension in adapter.file_extensions() {
        let path = std::path::PathBuf::from(format!("conformance.{extension}"));
        let grammar_name = adapter.grammar_name_for_path(&path);
        if !grammar_names.insert(grammar_name) {
            continue;
        }
        let language = adapter
            .tree_sitter_language_for_path(&path)
            .unwrap_or_else(|error| {
                panic!(
                    "{}: load grammar {grammar_name}: {error}",
                    adapter.language_id().as_str()
                )
            });
        grammars.push((grammar_name, path, language));
    }
    assert!(
        !grammar_names.is_empty(),
        "{}: adapter declares no file extension/grammar variant",
        adapter.language_id().as_str()
    );

    let mut missing = Vec::new();
    for (grammar_name, path, grammar) in &grammars {
        let handler = adapter.grammar_handler_for_path(path).unwrap_or_else(|| {
            panic!(
                "{}: production adapter does not expose a GrammarHandler for {grammar_name}",
                adapter.language_id().as_str()
            )
        });
        let mut declared = handler.declared_node_kinds();
        declared.extend_from_slice(adapter.additional_grammar_node_kinds_for_path(path));
        assert!(
            !declared.is_empty(),
            "{}: compiler grammar contract declares no Tree-sitter node kinds for {grammar_name}",
            adapter.language_id().as_str()
        );

        let mut seen_declarations = BTreeSet::new();
        let mut duplicate_declarations = Vec::new();
        let mut empty_declarations = Vec::new();
        for (field, kind) in &declared {
            if kind.trim().is_empty() {
                empty_declarations.push(*field);
            }
            if !seen_declarations.insert((*field, *kind)) {
                duplicate_declarations.push(format!("{field}={kind}"));
            }
            if !grammar_declares_kind(grammar, kind) {
                missing.push(format!("{field}={kind} missing from {grammar_name}"));
            }
        }
        assert!(
            empty_declarations.is_empty(),
            "{}: empty node kind in {grammar_name} inventory {:?}",
            adapter.language_id().as_str(),
            empty_declarations
        );
        assert!(
            duplicate_declarations.is_empty(),
            "{}: duplicate node kinds inside {grammar_name} inventory: {:?}",
            adapter.language_id().as_str(),
            duplicate_declarations
        );

        let declared_fields = handler.declared_field_names();
        let mut seen_fields = BTreeSet::new();
        let mut duplicate_fields = Vec::new();
        let mut empty_fields = Vec::new();
        for (owner, field) in declared_fields {
            if field.trim().is_empty() {
                empty_fields.push(owner);
            }
            if !seen_fields.insert((owner, field)) {
                duplicate_fields.push(format!("{owner}={field}"));
            }
            if grammar.field_id_for_name(field).is_none() {
                missing.push(format!("{owner}={field} field missing from {grammar_name}"));
            }
        }
        assert!(
            empty_fields.is_empty(),
            "{}: empty field name in {grammar_name} inventory {:?}",
            adapter.language_id().as_str(),
            empty_fields
        );
        assert!(
            duplicate_fields.is_empty(),
            "{}: duplicate field names inside {grammar_name} inventory: {:?}",
            adapter.language_id().as_str(),
            duplicate_fields
        );
    }
    assert!(
        missing.is_empty(),
        "{}: compiler lowering contains node kinds absent from an owned Tree-sitter grammar {:?}:\n{}",
        adapter.language_id().as_str(),
        grammar_names,
        missing.join("\n")
    );
}

/// Tree-sitter aliases can be valid emitted node names without appearing in
/// the contiguous `node_kind_count()` symbol enumeration. Query by the exact
/// adapter-declared spelling instead, and verify the reverse mapping so the
/// sentinel id returned for an unknown name cannot satisfy the contract.
fn grammar_declares_kind(grammar: &tree_sitter::Language, kind: &str) -> bool {
    [true, false].into_iter().any(|named| {
        let id = grammar.id_for_node_kind(kind, named);
        id != 0 && grammar.node_kind_for_id(id) == Some(kind)
    })
}

fn validate_decl_index(file: FileId, source: &str, index: &DeclIndex) {
    assert_eq!(
        index.file, file,
        "declaration index is attached to the wrong file"
    );
    validate_all_serialized_spans(file, source, index);
    let round_trip: DeclIndex =
        serde_json::from_value(serde_json::to_value(index).expect("DeclIndex must remain serializable"))
            .expect("DeclIndex must remain deserializable");
    assert_eq!(
        &round_trip, index,
        "DeclIndex serialization changed compiler facts"
    );

    let mut symbols = BTreeSet::new();
    for decl in &index.defs {
        assert!(
            symbols.insert(decl.symbol),
            "adapter emitted duplicate symbol {:?} in {file:?}",
            decl.symbol
        );
        validate_decl(file, source, decl);
    }
    for reference in &index.refs {
        assert!(
            !reference.name.trim().is_empty(),
            "adapter emitted an empty reference name at {:?}",
            reference.span
        );
    }
    validate_cross_fact_integrity(index);
}

type SpanKey = (u32, u64, u64);

fn span_key(span: Span) -> SpanKey {
    (span.file.raw(), span.start, span.end)
}

fn collect_control_and_call_facts<'a>(
    events: &'a [FlowEvent],
    calls: &mut BTreeMap<SpanKey, (&'a str, &'a [bonsai_lang_api::CallArg])>,
    conditional_branches: &mut BTreeSet<SpanKey>,
) {
    for event in events {
        match event {
            FlowEvent::Call { span, name, args, .. } => {
                let previous = calls.insert(span_key(*span), (name, args));
                assert!(
                    previous.is_none(),
                    "adapter emitted two semantic calls at {span:?}: previous={previous:?}, new={name}"
                );
                assert!(
                    args.windows(2)
                        .all(|pair| pair[0].span.start <= pair[1].span.start),
                    "call arguments are not in source order at {span:?}: {args:?}"
                );
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => {
                if condition.is_some() {
                    conditional_branches.insert(span_key(*span));
                }
                collect_control_and_call_facts(then_events, calls, conditional_branches);
                collect_control_and_call_facts(else_events, calls, conditional_branches);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_control_and_call_facts(body, calls, conditional_branches);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_control_and_call_facts(body, calls, conditional_branches);
                collect_control_and_call_facts(catch_events, calls, conditional_branches);
                collect_control_and_call_facts(finally_events, calls, conditional_branches);
            }
            _ => {}
        }
    }
}

fn validate_cross_fact_integrity(index: &DeclIndex) {
    let mut calls = BTreeMap::new();
    let mut conditional_branches = BTreeSet::new();
    for decl in &index.defs {
        collect_control_and_call_facts(&decl.flow_events, &mut calls, &mut conditional_branches);
    }

    let mut argument_facts = BTreeMap::new();
    for fact in &index.call_argument_values {
        let call_key = span_key(fact.call_span);
        let (_, args) = calls.get(&call_key).unwrap_or_else(|| {
            panic!(
                "call-argument value fact references missing semantic call {:?}",
                fact.call_span
            )
        });
        assert!(
            fact.argument_index < args.len(),
            "call-argument value index {} is outside {} args at {:?}",
            fact.argument_index,
            args.len(),
            fact.call_span
        );
        assert_eq!(
            fact.argument_span, args[fact.argument_index].span,
            "call-argument value span disagrees with FlowEvent::Call at {:?}",
            fact.call_span
        );
        assert!(
            argument_facts
                .insert((call_key, fact.argument_index), fact)
                .is_none(),
            "duplicate call-argument value fact at {:?} arg {}",
            fact.call_span,
            fact.argument_index
        );
    }
    for (call_span, (_, args)) in &calls {
        for argument_index in 0..args.len() {
            assert!(
                argument_facts.contains_key(&(*call_span, argument_index)),
                "semantic call {call_span:?} arg {argument_index} has no compiler value-shape fact; \
                 args={args:#?}; emitted facts={:#?}",
                index.call_argument_values
            );
        }
    }

    let mut receiver_calls = BTreeSet::new();
    for fact in &index.call_receivers {
        let key = span_key(fact.call_span);
        assert!(
            calls.contains_key(&key),
            "receiver fact references missing semantic call {:?}",
            fact.call_span
        );
        assert!(
            receiver_calls.insert(key),
            "duplicate receiver fact for {:?}",
            fact.call_span
        );
    }

    let mut branch_facts = BTreeSet::new();
    for fact in &index.branch_conditions {
        let key = span_key(fact.branch_span);
        assert!(
            conditional_branches.contains(&key),
            "condition fact references missing conditional branch {:?}",
            fact.branch_span
        );
        assert!(
            branch_facts.insert(key),
            "duplicate condition fact for {:?}",
            fact.branch_span
        );
    }
    assert_eq!(
        branch_facts, conditional_branches,
        "every conditional FlowEvent::Branch must have one compiler condition fact"
    );
}

fn validate_decl(file: FileId, source: &str, decl: &Decl) {
    assert!(
        !decl.name.trim().is_empty(),
        "adapter emitted an empty declaration name at {:?}",
        decl.span
    );
    assert_span_contains(decl.span, decl.name_span, "declaration name");
    if let Some(body) = decl.body_span {
        assert_span_contains(decl.span, body, "declaration body");
    }
    if !decl.param_annotations.is_empty() {
        assert_eq!(
            decl.param_annotations.len(),
            decl.params.len(),
            "parameter annotations are not parallel to params for `{}`",
            decl.name
        );
    }
    if !decl.param_default_calls.is_empty() {
        assert_eq!(
            decl.param_default_calls.len(),
            decl.params.len(),
            "parameter default calls are not parallel to params for `{}`",
            decl.name
        );
    }
    if let Some(receiver) = decl.receiver_param_index {
        assert!(
            receiver < decl.params.len(),
            "receiver parameter index {receiver} is outside {} params for `{}`",
            decl.params.len(),
            decl.name
        );
    }
    validate_event_tree(
        file,
        source,
        &decl.flow_events,
        decl.body_span.or(Some(decl.span)),
    );
}

fn validate_event_tree(file: FileId, source: &str, events: &[FlowEvent], owner: Option<Span>) {
    for event in events {
        let span = event.span();
        validate_span(file, source, span, "flow event");
        if let Some(owner) = owner {
            assert_span_contains(owner, span, "flow event");
        }
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                validate_event_tree(file, source, then_events, Some(span));
                validate_event_tree(file, source, else_events, Some(span));
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                validate_event_tree(file, source, body, Some(span));
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                validate_event_tree(file, source, body, Some(span));
                validate_event_tree(file, source, catch_events, Some(span));
                validate_event_tree(file, source, finally_events, Some(span));
            }
            _ => {}
        }
    }
}

fn assert_span_contains(owner: Span, nested: Span, what: &str) {
    assert_eq!(owner.file, nested.file, "{what} belongs to a different file");
    assert!(
        owner.start <= nested.start && nested.end <= owner.end,
        "{what} span {nested:?} escapes owner {owner:?}"
    );
}

fn validate_span(file: FileId, source: &str, span: Span, what: &str) {
    assert_eq!(span.file, file, "{what} belongs to the wrong file");
    assert!(span.start <= span.end, "{what} has an inverted span: {span:?}");
    let start = usize::try_from(span.start).expect("span start fits usize");
    let end = usize::try_from(span.end).expect("span end fits usize");
    assert!(end <= source.len(), "{what} escapes source bytes: {span:?}");
    assert!(
        source.is_char_boundary(start) && source.is_char_boundary(end),
        "{what} splits a UTF-8 code point: {span:?}"
    );
}

fn validate_all_serialized_spans(file: FileId, source: &str, index: &DeclIndex) {
    let value = serde_json::to_value(index).expect("DeclIndex must remain serializable");
    let expected_file = serde_json::to_value(file).expect("FileId must remain serializable");
    visit_serialized_value(&value, &expected_file, file, source, "decl_index");
}

fn visit_serialized_value(value: &Value, expected_file: &Value, file: FileId, source: &str, path: &str) {
    match value {
        Value::Object(object)
            if object.contains_key("file") && object.contains_key("start") && object.contains_key("end") =>
        {
            assert_eq!(
                object.get("file"),
                Some(expected_file),
                "serialized span at {path} belongs to the wrong file"
            );
            let start = object["start"]
                .as_u64()
                .unwrap_or_else(|| panic!("non-u64 span start at {path}"));
            let end = object["end"]
                .as_u64()
                .unwrap_or_else(|| panic!("non-u64 span end at {path}"));
            validate_span(file, source, Span::new(file, start, end), path);
        }
        Value::Object(object) => {
            for (key, child) in object {
                visit_serialized_value(child, expected_file, file, source, &format!("{path}.{key}"));
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                visit_serialized_value(child, expected_file, file, source, &format!("{path}[{index}]"));
            }
        }
        _ => {}
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
