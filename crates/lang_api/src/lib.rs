//! Extension surface for language adapters (spec §5).
//!
//! A new language is added by implementing [`LanguageAdapter`] in a
//! `lang_<name>` crate and registering it on a [`LanguageRegistry`]. Core
//! crates must depend only on `lang_api`, never on concrete adapters.

pub mod capabilities;
pub mod kit;
pub mod registry;
pub mod types;

pub use capabilities::{CapabilityLevel, LanguageCapabilities};
pub use kit::{
    alias_map_from_import_specs, alias_map_from_imports, apply_assign_call_result_types,
    apply_assign_value_kind, apply_call_receiver_types, apply_class_field_type_aliases,
    apply_file_stem_semantic_identity, apply_module_path_semantic_identity, collect_modifier_visibility,
    collect_param_type_aliases, decl_index_with_handler, extend_alias_map_with_flow_events,
    extract_imports_via, inject_lifecycle_events, populate_decl_return_types, with_fn_kinds, AliasTarget,
    GrammarHandler, LifecycleTransition, ModifierVocabulary, TypeAliasVocabulary, GENERIC_HANDLER,
    WILDCARD_IMPORT_ALIAS_PREFIX,
};
pub use registry::{AdapterArc, LanguageRegistry};
pub use types::{
    AssignValueKind, CallArg, CallKind, Comment, CommentKind, Decl, DeclIndex, DeclKind, FieldWrite,
    FlowEvent, ImportIndex, ImportScope, ImportSpec, LanguageId, LoopKind, ModulePath, Ref, RefKind,
    StringCategory, StringLiteral, TypeAliasBinding, UnsupportedConstruct, Visibility, WorkspaceRoot,
};

use bonsai_common::FileId;
use bonsai_diagnostics::DiagnosticSink;
use bonsai_vfs::Vfs;
use parking_lot::RwLock;
use std::sync::Arc;

/// Read-only view of the pieces of the analyzer database that adapters need.
///
/// Adapters must not see query internals or other adapters; this struct is
/// the full surface area. Keep it minimal — if a new adapter needs something
/// it isn't here, add it here rather than giving adapters a `Db` handle.
pub struct AdapterContext<'a> {
    pub vfs: &'a Vfs,
    pub diagnostics: &'a RwLock<DiagnosticSink>,
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

    /// The Tree-sitter `Language` used for parsing. Most adapters fetch
    /// this from `tree_sitter_language_pack::get_language`.
    fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError>;

    /// What the adapter claims to support; unsupported constructs are
    /// surfaced as diagnostics by the pipeline.
    fn capabilities(&self) -> LanguageCapabilities;

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
