//! Per-language capability declarations.

use serde::{Deserialize, Serialize};

/// Empty constructor-name vocabulary for languages whose constructors are
/// represented exclusively by constructor grammar nodes or class identity.
///
/// This is an empty slice, not a sentinel spelling: downstream resolution
/// must never infer language semantics from an invented identifier.
pub const NO_CONSTRUCTOR_METHOD_NAMES: &[&str] = &[];

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    /// The adapter has a closed static model for this construct.
    Exact,
    /// The adapter emits proven static evidence for recognized forms;
    /// unrecognized forms stay diagnostic/incomplete and must not be
    /// widened into public findings.
    Partial,
    /// The adapter has no static model for this construct; rules that
    /// require it should be rejected or treated as not applicable.
    Unsupported,
}

/// How a language explains multiple same-named callable declarations.
///
/// The callgraph may emit more than one semantic edge only when the adapter
/// declares one of these source-language relationships.  Keeping the mode in
/// adapter metadata prevents the language-neutral resolver from recognizing
/// concrete language ids.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum CallableDeclarationFamily {
    /// Same-named declarations are not a compiler-proven family.
    #[default]
    None,
    /// Repeated declarations with the same signature denote one callable
    /// surface (for example a declaration and definition in one C TU).
    SameSignature,
    /// Same-name/arity clauses are alternative bodies of one callable.
    FunctionClauses,
}

/// Grammar shapes a candidate-only text prefilter may recognize without
/// excluding valid calls. Final call facts always come from the adapter AST;
/// `Disabled` keeps the optimization off for grammars whose surface forms are
/// not completely represented here.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum CallTextPrefilter {
    #[default]
    Disabled,
    Parenthesized,
    ParenthesizedOrCommand,
}

/// Source-level prefixes that qualify a name from a module or namespace
/// root. The compiler backend only strips values declared by the active
/// adapter; an empty declaration means no such syntax exists.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ModulePathSyntax {
    /// Prefixes consumed at most once (for example a global namespace mark).
    pub rooted_prefixes: &'static [&'static str],
    /// Prefixes that may repeat before one qualified path.
    pub repeatable_rooted_prefixes: &'static [&'static str],
}

impl ModulePathSyntax {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            rooted_prefixes: &[],
            repeatable_rooted_prefixes: &[],
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LanguageCapabilities {
    pub modules: CapabilityLevel,
    pub generics: CapabilityLevel,
    pub macros: CapabilityLevel,
    pub dynamic_dispatch: CapabilityLevel,
    pub exceptions: CapabilityLevel,
    pub async_await: CapabilityLevel,
    pub coroutines: CapabilityLevel,
    pub reflection: CapabilityLevel,
    pub ffi: CapabilityLevel,
    pub pattern_matching: CapabilityLevel,
    /// Adapter/index pipeline emits static receiver type facts for
    /// method-call receivers. This lets downstream resolution use
    /// semantic class/type identity instead of receiver-name lists.
    pub receiver_types: CapabilityLevel,
    /// Every source-level field/property projection is lowered to a concrete
    /// `Place` fact. Sink-oriented IDG builds may use those facts as complete
    /// sparse field-demand roots; adapters that leave call-shaped or pattern
    /// projections implicit must keep this false.
    pub field_places_complete: bool,
    /// Receiver names that the language treats as aliases for an
    /// export. Used by the call graph to expand an alias-tail to the
    /// set of fully-qualified callee shapes when resolving cross-file
    /// references. JS/TS expose `exports.<name>` and
    /// `module.exports.<name>`; most other languages declare nothing.
    /// Empty by default; an adapter that wants to participate in
    /// cross-module export resolution declares the full set.
    pub module_export_aliases: &'static [&'static str],
    /// Public declaration names emitted by this adapter for a module's
    /// callable default export. JavaScript/TypeScript adapters lower their
    /// export syntax to its canonical `default` declaration name; other
    /// languages leave this empty. IDG import stitching consumes this fact
    /// instead of recognizing language-specific export spellings.
    pub module_default_export_names: &'static [&'static str],
    /// Type spellings that mean "no useful static receiver/parameter
    /// narrowing" in this language. Callgraph overload selection consumes
    /// this adapter declaration instead of carrying a cross-language type
    /// name list.
    pub universal_type_names: &'static [&'static str],
    /// Adapter-owned source syntax for rooted qualified names. Resolver and
    /// callgraph code consume this declaration rather than recognizing Rust,
    /// C++, or PHP tokens in the shared compiler backend.
    pub module_path_syntax: ModulePathSyntax,
    /// Method names this language's grammar uses for constructors when the
    /// adapter cannot express the construct as [`crate::DeclKind::Constructor`].
    /// Empty means there is no method-name form. There is deliberately no
    /// cross-language fallback.
    pub constructor_method_names: &'static [&'static str],
    /// A bare call expression may denote construction when semantic name
    /// resolution proves that its callee is a class (for example Python's
    /// `Widget(...)`). The call graph still requires exact scoped class
    /// identity; this capability only describes the grammar ambiguity and
    /// never enables capitalization-based inference.
    pub bare_call_constructor_syntax: bool,
    /// Receiver spellings that the adapter's syntax lowering resolves to
    /// "the supertype's method" (e.g. JS `super`, PHP `parent`, or the
    /// normalized Python call receiver `super()`). Empty means the language
    /// has no such syntax; there is deliberately no cross-language fallback.
    pub super_receiver_tokens: &'static [&'static str],
    /// Receiver tokens that bind to the enclosing instance/class
    /// (e.g. Ruby `self`, Java `this`). Empty means the grammar has no
    /// implicit receiver token. Explicit receiver parameters such as
    /// Python's first method parameter, Go's receiver declaration, and Rust's
    /// `self_parameter` are represented by `Decl::receiver_param_index`, not
    /// by this inventory.
    pub implicit_receiver_tokens: &'static [&'static str],
    /// Unqualified top-level names may resolve to declarations in sibling
    /// files in the same directory. File-module languages leave this false
    /// and require an import/module fact.
    pub same_directory_unqualified_calls: bool,
    /// Checked-in native build-target membership may narrow otherwise
    /// ambiguous global call candidates for this language.
    pub build_target_linkage: bool,
    /// Adapter-declared relationship between repeated callable declarations.
    pub callable_declaration_family: CallableDeclarationFamily,
    /// A quoted literal can denote a statically resolvable callable value.
    pub quoted_callable_literals: bool,
    /// Safe candidate-only call-text grammar. This never creates call facts;
    /// it can only avoid parsing files that provably lack a rule's call shape.
    pub call_text_prefilter: CallTextPrefilter,
    /// Source suffixes considered when an extensionless/dotted relative
    /// import is resolved inside this language's module system.
    pub module_resolution_extensions: &'static [&'static str],
    /// Non-source template suffixes that share the language workspace's
    /// dependency manifest context.
    pub workspace_manifest_context_extensions: &'static [&'static str],
}

impl LanguageCapabilities {
    /// Useful baseline: no claims at all. Adapters can override individual
    /// fields by constructing from this and mutating.
    /// Adapter-owned constructor method spellings. The `effective_` name is
    /// retained for API compatibility; empty means no method-name form.
    #[must_use]
    pub fn effective_constructor_method_names(&self) -> &'static [&'static str] {
        self.constructor_method_names
    }

    /// Adapter-owned super-receiver spellings. The `effective_` name is kept
    /// for API compatibility; unlike constructor names, this never falls back
    /// to a cross-language spelling inventory.
    #[must_use]
    pub fn effective_super_receiver_tokens(&self) -> &'static [&'static str] {
        self.super_receiver_tokens
    }

    /// Adapter-owned implicit-receiver spellings, with empty meaning none.
    #[must_use]
    pub fn effective_implicit_receiver_tokens(&self) -> &'static [&'static str] {
        self.implicit_receiver_tokens
    }

    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            modules: CapabilityLevel::Unsupported,
            generics: CapabilityLevel::Unsupported,
            macros: CapabilityLevel::Unsupported,
            dynamic_dispatch: CapabilityLevel::Unsupported,
            exceptions: CapabilityLevel::Unsupported,
            async_await: CapabilityLevel::Unsupported,
            coroutines: CapabilityLevel::Unsupported,
            reflection: CapabilityLevel::Unsupported,
            ffi: CapabilityLevel::Unsupported,
            pattern_matching: CapabilityLevel::Unsupported,
            receiver_types: CapabilityLevel::Unsupported,
            field_places_complete: false,
            module_export_aliases: &[],
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: ModulePathSyntax::none(),
            constructor_method_names: &[],
            bare_call_constructor_syntax: false,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
            same_directory_unqualified_calls: false,
            build_target_linkage: false,
            callable_declaration_family: CallableDeclarationFamily::None,
            quoted_callable_literals: false,
            call_text_prefilter: CallTextPrefilter::Disabled,
            module_resolution_extensions: &[],
            workspace_manifest_context_extensions: &[],
        }
    }

    #[must_use]
    pub const fn partial_baseline() -> Self {
        Self {
            modules: CapabilityLevel::Partial,
            generics: CapabilityLevel::Partial,
            macros: CapabilityLevel::Unsupported,
            dynamic_dispatch: CapabilityLevel::Partial,
            exceptions: CapabilityLevel::Partial,
            async_await: CapabilityLevel::Partial,
            // The kit recognizes the six yield grammar shapes
            // (`yield`, `yield_statement`, `yield_expression`,
            // `yield_from_expression`, `co_yield_*`) and emits
            // `FlowEvent::Yield`. The interprocedural engine treats
            // yielded values as return-equivalent for summary
            // construction (see `summary_impl.rs::Yield` handler) so
            // taint flowing into a yielded expression is tracked.
            // Cross-process generator-state propagation is still out of
            // scope, so `Partial` (not `Exact`).
            coroutines: CapabilityLevel::Partial,
            reflection: CapabilityLevel::Unsupported,
            ffi: CapabilityLevel::Unsupported,
            pattern_matching: CapabilityLevel::Partial,
            receiver_types: CapabilityLevel::Unsupported,
            field_places_complete: false,
            module_export_aliases: &[],
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: ModulePathSyntax::none(),
            constructor_method_names: &[],
            bare_call_constructor_syntax: false,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
            same_directory_unqualified_calls: false,
            build_target_linkage: false,
            callable_declaration_family: CallableDeclarationFamily::None,
            quoted_callable_literals: false,
            call_text_prefilter: CallTextPrefilter::Disabled,
            module_resolution_extensions: &[],
            workspace_manifest_context_extensions: &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LanguageCapabilities;

    #[test]
    fn empty_receiver_capabilities_mean_no_receiver_syntax() {
        let capabilities = LanguageCapabilities::unsupported();
        assert!(capabilities.effective_super_receiver_tokens().is_empty());
        assert!(capabilities.effective_implicit_receiver_tokens().is_empty());
    }
}
