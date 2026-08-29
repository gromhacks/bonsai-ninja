//! Extension surface for language adapters (spec §5).
//!
//! A new language is added by implementing [`LanguageAdapter`] in a
//! `lang_<name>` crate and registering it on a [`LanguageRegistry`]. Core
//! crates must depend only on `lang_api`, never on concrete adapters.

pub mod capabilities;
pub mod kit;
mod parse_recovery;
pub mod registry;
mod storage;
pub mod taxonomy;
pub mod types;

pub use capabilities::{
    callable_reference_variants, CallTextPrefilter, CallableDeclarationFamily, CallableReferenceSyntax,
    CapabilityLevel, LanguageCapabilities, ModulePathSyntax, ReceiverTypeSyntax, NO_CONSTRUCTOR_METHOD_NAMES,
};
pub use kit::{
    alias_map_from_import_specs, alias_map_from_imports, apply_assign_call_result_types,
    apply_assignment_type_aliases, apply_call_receiver_types, apply_call_receiver_types_with_language_syntax,
    apply_call_receiver_types_with_super_tokens, apply_class_field_type_aliases,
    apply_constructor_result_type_aliases, apply_expression_value_kinds, apply_file_stem_semantic_identity,
    apply_local_closure_captures, apply_module_path_semantic_identity, assignment_trace_message,
    c_family_preproc_imports, collect_assign_targets, collect_constructor_result_type_aliases,
    collect_modifier_visibility, collect_param_type_aliases, collect_receiver_field_initializers,
    collect_return_spans, decl_index_from_tree_with_handler, decl_index_with_handler,
    extend_alias_map_with_flow_events, extract_assignment_value_facts, extract_branch_condition_facts,
    extract_call_argument_value_facts, extract_call_receiver_facts, extract_imports_via,
    extract_runtime_type_narrowing_facts, for_each_flow_event, mark_namespace_call_receivers,
    module_local_binding, normalize_call_result_assignment_sources, normalize_decl_event_evaluation_order,
    populate_decl_return_types, qualify_implicit_member_assign_targets,
    qualify_implicit_member_reads_in_index, qualify_receiver_field_expression_flows,
    rewrite_implicit_member_reads, tuple_result_projection_index, AliasTarget, AssignmentNodeSemantics,
    CallTargetExtraction, ExpressionPlaceExtraction, FunctionDefinitionExtraction, GrammarHandler,
    ImplicitMemberReadCall, ModifierVocabulary, PatternBindingSite, PatternSourceProjection,
    ProjectedPatternBindingSite, SyntaxSpecialForm, TypeAliasVocabulary, EMPTY_HANDLER, MODULE_DECL_NAME,
    WILDCARD_IMPORT_ALIAS_PREFIX,
};
pub use parse_recovery::{
    branch_free_conditional_recovery_edits, c_family_declaration_macro_recovery_edits,
    c_family_preprocessor_context_fingerprint, syntax_damage_score, ConditionalDirectiveSyntax,
    ParseRecoveryEdit,
};
pub use registry::{AdapterArc, LanguageRegistry};
pub use taxonomy::{flow_edge_spec, FlowEdgeKind, FlowEdgeSpec, FlowEdgeSupport, FLOW_EDGE_TAXONOMY};
pub use types::{
    assignment_value_fact_for_span, assignment_value_rendering, branch_condition_fact_for_span,
    call_argument_value_fact, call_receiver_fact_for_span, character_constraints_from_substitutions,
    finite_literal_selection_for_assignment, operations_from_flow_events, AggregateLayout,
    ArgumentPassingMode, AssignValueKind, AssignmentValueFact, AssignmentValueIndex, BranchConditionFact,
    BranchConditionPolarity, CallArg, CallArgumentValueFact, CallKind, CallReceiverFact, CallReceiverRole,
    CatchArmFact, CharacterClass, CharacterConstraintDomain, CharacterConstraintFact,
    CharacterConstraintOutput, CharacterConstraintProof, CharacterSubstitutionDomain,
    CharacterSubstitutionFact, Comment, CommentKind, CompilerAssignmentAlias, CompilerAttribution,
    CompilerBrowseHeader, CompilerBrowseTermGroup, CompilerCallArgumentAttribution, CompilerCallAttribution,
    CompilerCallHeader, CompilerFactoryCallAssignment, CompilerFunctionAttribution, CompilerGuardFact,
    CompilerReceiverTypeHeader, CompilerReturnHeader, CompilerSyntaxHeader, CompilerWriteAttribution,
    ConditionEquality, ConditionExpressionFact, ConditionOperandFact, Decl, DeclIndex, DeclKind,
    DynamicKeyFilterFact, ExpressionField, ExpressionFlow, ExpressionProjection, FieldWrite,
    FiniteLiteralSelectionFact, FlowEvent, GuardedValueFilterFact, ImportIndex, ImportScope, ImportSpec,
    InlineAggregateCallbackFact, LanguageId, LoopKind, MembershipConditionFact, ModulePath, Operation,
    OperationKind, OperationOperand, OperationOperandRole, PredicateReturnFact, ReceiverFieldInitializer,
    Ref, RefKind, RuntimeTypeNarrowingFact, SameOriginPathConstraintFact, StaticAggregateFieldValue,
    StaticScalarValue, StaticStringMapEntry, StaticStringMapFact, StringCategory, StringCompositionFact,
    StringCompositionPart, StringLiteral, TypeAliasBinding, UnsupportedConstruct, Visibility, WorkspaceRoot,
    COMPILER_GUARD_RELATIVE_PATH_BOUNDARY_REJECTION,
};

use bonsai_common::FileId;
use bonsai_diagnostics::DiagnosticSink;
pub use bonsai_vfs::{FileSnapshot, Vfs};
use parking_lot::RwLock;
use std::sync::Arc;
pub use tree_sitter::Tree as SyntaxTree;

/// Canonical tree-sitter tree provider used by adapters.
///
/// The analyzer database implements this with its versioned parser cache, so
/// every adapter pass over one file shares the same tree instead of creating
/// another parser and reparsing identical source. Standalone adapter tests may
/// omit the provider and use the direct fallback in `kit::parse_with`.
pub trait TreeProvider: Send + Sync {
    /// Return the tree for this exact immutable snapshot and grammar.
    ///
    /// `pack_name` is the adapter-selected grammar variant, not necessarily
    /// the adapter's public language id. Taking the snapshot rather than only a [`FileId`] is part of the
    /// correctness contract: a concurrent VFS write must never pair an older
    /// source snapshot with a newer syntax tree.
    fn tree_for_snapshot(&self, pack_name: &str, snapshot: &FileSnapshot) -> Option<Arc<SyntaxTree>>;
}

/// Read-only view of the pieces of the analyzer database that adapters need.
///
/// Adapters must not see query internals or other adapters; this struct is
/// the full surface area. Keep it minimal — if a new adapter needs something
/// it isn't here, add it here rather than giving adapters a `Db` handle.
pub struct AdapterContext<'a> {
    pub vfs: &'a Vfs,
    pub diagnostics: &'a RwLock<DiagnosticSink>,
    /// Versioned parser/tree cache supplied by the analyzer database.
    pub tree_provider: Option<&'a dyn TreeProvider>,
    /// Absolute path of the workspace root the adapter is running
    /// against. `None` for adapter unit tests that synthesize a Vfs
    /// without a workspace. Adapters use this to compute
    /// workspace-relative module paths for `Decl.qualified_name` and
    /// `Decl.module_path` — see
    /// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
    pub workspace_root: Option<&'a std::path::Path>,
}

impl<'a> AdapterContext<'a> {
    pub fn emit(&self, diag: bonsai_diagnostics::Diagnostic) {
        self.diagnostics.write().push(diag);
    }

    /// Workspace-relative path for `file`, or `None` when no
    /// workspace root is set or the file isn't under the root.
    /// Adapters use this in lieu of raw `vfs.path(file)` to derive
    /// stable module paths that match between CLI and SDK callers.
    #[must_use]
    pub fn workspace_relative_path(&self, file: bonsai_common::FileId) -> Option<std::path::PathBuf> {
        let path = self.vfs.path(file).ok()?;
        let root = self.workspace_root?;
        path.strip_prefix(root).ok().map(std::path::Path::to_path_buf)
    }
}

/// Grammar-owned wrapper for parsing a source fragment outside its original
/// file context. Most grammars accept fragments directly; adapters override
/// this only when their root grammar has a distinct host-language mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FragmentParseContext {
    /// Bytes inserted before the fragment solely for parsing.
    pub prefix: &'static str,
    /// Bytes inserted after the fragment solely for parsing.
    pub suffix: &'static str,
}

/// Adapter-owned proof for selecting among grammars that share a file
/// extension.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum LanguageOwnershipEvidence {
    /// This specialized grammar's distinguishing syntax is absent. A generic
    /// compatible grammar should own the ambiguous-extension file instead.
    Excluded,
    /// The grammar exposed no syntax unique to this language. Selection falls
    /// back to concrete syntax damage.
    #[default]
    Unproven,
    /// The concrete tree contains grammar-owned syntax that proves this
    /// language owns the file.
    Proven,
}

impl LanguageOwnershipEvidence {
    #[must_use]
    pub const fn selection_rank(self) -> u8 {
        match self {
            Self::Excluded => 0,
            Self::Unproven => 1,
            Self::Proven => 2,
        }
    }
}

/// Adapter-owned classification of a source file's representation.
///
/// Shared workspace and analysis crates consume this generic fact; they must
/// not recognize language ids, extensions, or minifier naming conventions on
/// their own. A file excluded by a workspace policy remains valid source and
/// can be admitted explicitly.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceFileRepresentation {
    #[default]
    Maintained,
    Minified,
}

/// The full contract an adapter must implement. See spec §5.5.
///
/// The trait is intentionally object-safe so a registry can store
/// `Arc<dyn LanguageAdapter>` values.
pub trait LanguageAdapter: Send + Sync + 'static {
    /// Short machine identifier (e.g. `"rust"`, `"python"`). Must match the
    /// key used by `tree-sitter-language-pack` where possible.
    fn language_id(&self) -> LanguageId;

    /// Human-readable display name.
    fn display_name(&self) -> &'static str;

    /// File extensions this adapter claims (lowercase, no leading dot).
    fn file_extensions(&self) -> &'static [&'static str];

    /// Classify a path using conventions owned by this language frontend.
    /// The default treats every supported source as maintained code.
    fn source_file_representation(&self, _path: &std::path::Path) -> SourceFileRepresentation {
        SourceFileRepresentation::Maintained
    }

    /// The Tree-sitter `Language` used for parsing. Most adapters fetch
    /// this from `tree_sitter_language_pack::get_language`.
    fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError>;

    /// Prove that an ambiguous-extension file belongs to this adapter from
    /// grammar-owned syntax in its concrete tree.
    ///
    /// This is a proof hook, not a filename or token-scoring heuristic. The
    /// database considers the adapter's evidence before comparing parse
    /// damage. A specialized superset grammar may return
    /// [`LanguageOwnershipEvidence::Excluded`] when its distinguishing syntax
    /// is absent and a generic compatible grammar should own the file. Most
    /// languages have unambiguous extensions and inherit
    /// [`LanguageOwnershipEvidence::Unproven`].
    fn source_syntax_proves_language(
        &self,
        _snapshot: &FileSnapshot,
        _tree: &SyntaxTree,
    ) -> LanguageOwnershipEvidence {
        LanguageOwnershipEvidence::Unproven
    }

    /// Select the exact Tree-sitter grammar pack for one source path.
    /// Most languages have one grammar and inherit their language id. An
    /// adapter that owns multiple grammar variants (TypeScript/TSX) selects
    /// here from file syntax metadata rather than asking the parser or shared
    /// analyzer to recognize an extension.
    fn grammar_name_for_path(&self, _path: &std::path::Path) -> &'static str {
        self.language_id().as_str()
    }

    /// Load the exact grammar selected for one source path. The default keeps
    /// existing single-grammar adapters on their normal constructor and loads
    /// a named variant only when `grammar_name_for_path` differs.
    fn tree_sitter_language_for_path(
        &self,
        path: &std::path::Path,
    ) -> Result<tree_sitter::Language, AdapterError> {
        let grammar = self.grammar_name_for_path(path);
        if grammar == self.language_id().as_str() {
            self.tree_sitter_language()
        } else {
            tree_sitter_language_pack::get_language(grammar)
                .map_err(|error| AdapterError::GrammarUnavailable(format!("{grammar}: {error}")))
        }
    }

    /// Return unconditional same-width parser-buffer normalizations for a
    /// source representation owned by this adapter.
    ///
    /// This is the frontend equivalent of lexing a host-language container:
    /// an ERB adapter, for example, masks HTML and delimiter bytes while
    /// retaining the embedded Ruby tokens. The normalized buffer is private
    /// to Tree-sitter; original source bytes and byte spans remain
    /// authoritative for every lowered fact. Unlike recovery edits, these
    /// edits are applied before the first parse because the container syntax
    /// is not intended to be parsed by the embedded language grammar at all.
    fn parse_normalization_edits(&self, _snapshot: &FileSnapshot, _vfs: &Vfs) -> Vec<ParseRecoveryEdit> {
        Vec::new()
    }

    /// Fingerprint external compiler context that can change this file's CST.
    ///
    /// Most grammars depend only on the source snapshot and inherit zero. A
    /// frontend whose exact recovery consumes other compiler inputs (for
    /// example reachable C-family preprocessor headers) returns a stable
    /// digest of those inputs. The parser cache then cannot reuse a tree after
    /// the external context changes while the source file itself stays fixed.
    /// Security/library names never belong in this fingerprint.
    fn parse_context_fingerprint(&self, _snapshot: &FileSnapshot, _vfs: &Vfs) -> u64 {
        0
    }

    /// Return same-width parser-buffer normalizations for a second,
    /// grammar-recovery parse.
    ///
    /// This hook is deliberately narrower than arbitrary source rewriting:
    /// adapters can only hide syntax whose role they have independently
    /// established from compiler facts and the raw CST (for example, a
    /// declaration macro reached through a C/C++ include, or qualification
    /// unsupported by an otherwise capable grammar production). The parser
    /// accepts the recovered tree only when it contains strictly fewer syntax
    /// errors, and all byte offsets continue to address the original source
    /// snapshot.
    fn parse_recovery_edits(
        &self,
        _snapshot: &FileSnapshot,
        _vfs: &Vfs,
        _tree: &SyntaxTree,
    ) -> Vec<ParseRecoveryEdit> {
        Vec::new()
    }

    /// Return independent recovery candidates for the current damaged tree.
    ///
    /// A frontend may own several unrelated recovery mechanisms (for
    /// example, preprocessor-region normalization and declaration-macro
    /// masking). Keeping those mechanisms in separate batches prevents one
    /// configuration-dependent candidate from rejecting an otherwise exact
    /// recovery. The parser evaluates every batch against the same current
    /// tree and accepts only the candidate with the strictly lowest syntax
    /// damage while preserving unrelated compiler nodes.
    ///
    /// Adapters with one recovery mechanism inherit the single-batch default.
    fn parse_recovery_edit_batches(
        &self,
        snapshot: &FileSnapshot,
        vfs: &Vfs,
        tree: &SyntaxTree,
    ) -> Vec<Vec<ParseRecoveryEdit>> {
        let edits = self.parse_recovery_edits(snapshot, vfs, tree);
        (!edits.is_empty()).then_some(edits).into_iter().collect()
    }

    /// Wrapper required to parse a standalone mid-file source fragment.
    /// Returned bytes are adapter grammar metadata and never appear in output.
    fn fragment_parse_context(&self) -> FragmentParseContext {
        FragmentParseContext::default()
    }

    /// What the adapter claims to support; unsupported constructs are
    /// surfaced as diagnostics by the pipeline.
    fn capabilities(&self) -> LanguageCapabilities;

    /// Return the adapter-owned Tree-sitter syntax contract used by the
    /// shared lowering kit.
    ///
    /// Production adapters override this so the common conformance suite can
    /// verify every declared node kind against the adapter's actual grammar.
    /// Multi-grammar adapters additionally override
    /// [`LanguageAdapter::grammar_handler_for_path`]. Test-only adapters that
    /// do not use the grammar-driven kit may retain the default.
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        None
    }

    /// Return the shared lowering contract for the grammar selected by
    /// `path`. Multi-grammar adapters override this when a construct is valid
    /// in only one representation; all other adapters inherit the common
    /// handler.
    fn grammar_handler_for_path(&self, _path: &std::path::Path) -> Option<&'static GrammarHandler> {
        self.grammar_handler()
    }

    /// Return adapter-owned Tree-sitter node kinds consumed outside the
    /// shared [`GrammarHandler`] lowering path.
    ///
    /// Custom post-processing (for example, language-specific scope or
    /// evaluation-order normalization) must declare every node spelling it
    /// inspects here. The common conformance suite validates this inventory
    /// against the exact grammar selected for a representative path, using
    /// [`LanguageAdapter::additional_grammar_node_kinds_for_path`] for
    /// representation-specific inventories, so an upstream grammar rename
    /// cannot silently disable compiler facts outside the shared handler.
    /// The first tuple element is a stable, human-readable use-site label.
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Return adapter-specific node kinds for the grammar selected by `path`.
    ///
    /// Most adapters own one grammar vocabulary and inherit this default.
    /// Multi-grammar adapters override it when a lowering path is genuinely
    /// representation-specific (for example JSX nodes in TSX but not plain
    /// TypeScript). Conformance validates the returned inventory against the
    /// exact grammar selected for the same representative path.
    fn additional_grammar_node_kinds_for_path(
        &self,
        _path: &std::path::Path,
    ) -> &'static [(&'static str, &'static str)] {
        self.additional_grammar_node_kinds()
    }

    /// Discover workspace roots (packages, modules) from the set of files.
    /// Default implementation treats the workspace as a single root.
    fn discover_workspace_roots(&self, _files: &[FileId], _ctx: &AdapterContext<'_>) -> Vec<WorkspaceRoot> {
        vec![WorkspaceRoot::default()]
    }

    /// Extract declarations and references from a single file.
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex;

    /// Extract imports / uses / includes from a single file.
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex;

    /// Report constructs the adapter saw but does not fully support.
    fn unsupported_constructs(&self, _file: FileId, _ctx: &AdapterContext<'_>) -> Vec<UnsupportedConstruct> {
        Vec::new()
    }
}

/// Helper alias for shared adapter references.
pub type DynAdapter = Arc<dyn LanguageAdapter>;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("grammar not available: {0}")]
    GrammarUnavailable(String),
    #[error("parser setup failed: {0}")]
    ParserSetup(String),
    #[error("parse error: {0}")]
    Parse(String),
}
