//! Rule schema — the in-memory shape of one
//! `sources/sinks/sanitizers/typing` YAML entry.
//!
//! Fields mirror `docs/security-spec.mdx § Rule schema` exactly. Unknown YAML
//! fields are rejected by the loader so rulepacks catch typos at load time
//! instead of silently failing to match.

use bonsai_lang_api::{AssignValueKind, DeclKind, StaticScalarValue, Visibility};
use serde::{de, Deserialize, Deserializer, Serialize};

/// Which of the four rule families a rule belongs to. Derived from the
/// directory the YAML file is loaded from (`sources/`, `sinks/`,
/// `sanitizers/`, `typing/`) — never declared inside the rule itself.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Source,
    Sink,
    Sanitizer,
    /// Typing-only rules (`typing/` dir). They declare external compiler
    /// models such as factory return types, callback parameter signatures,
    /// and library transfer semantics. They NEVER produce findings —
    /// `build_rulepack_typing` reads them via `all_rules()`, but they are
    /// excluded from every source/sink/sanitizer finding and inventory path,
    /// and from sink-only validation/conformance checks (CWE, severity,
    /// sink documentation, and SARIF).
    Typing,
}

impl Default for RuleKind {
    fn default() -> Self {
        // The loader always overwrites this from the containing
        // directory. Default exists only to make serde happy on the
        // `#[serde(skip)]` field.
        Self::Source
    }
}

impl RuleKind {
    /// Directory name under `langs/<lang>/` that holds this rule
    /// family on disk. The loader uses these to derive `kind` from
    /// the file path so YAML cannot lie about its family.
    #[must_use]
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Source => "sources",
            Self::Sink => "sinks",
            Self::Sanitizer => "sanitizers",
            Self::Typing => "typing",
        }
    }
}

/// Source trust classes per spec.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustClass {
    Remote,
    Local,
    Service,
    Ipc,
    Database,
    Library,
    Config,
    Physical,
}

impl TrustClass {
    /// Stable string label for rendered output. Matches the
    /// `serde(rename_all = "kebab-case")` shape so SDK rows and JSON
    /// rows agree without a serde round-trip.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::Local => "local",
            Self::Service => "service",
            Self::Ipc => "ipc",
            Self::Database => "database",
            Self::Library => "library",
            Self::Config => "config",
            Self::Physical => "physical",
        }
    }
}

/// Payload type vocabulary. Kept as a closed enum so rulepacks can't invent
/// ad-hoc values that nothing downstream understands.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadType {
    Query,
    Path,
    Header,
    Cookie,
    Form,
    Multipart,
    File,
    Json,
    Xml,
    Yaml,
    Graphql,
    Jwt,
    OauthToken,
    Protobuf,
    Msgpack,
    Csv,
    Text,
    Binary,
    Url,
    Hostname,
    Ip,
    Sql,
    Template,
    Event,
    QueueMessage,
    PubsubMessage,
    DbRow,
    ConfigValue,
    SensorFrame,
    HardwareRegister,
    Html,
}

impl PayloadType {
    /// Stable string label matching the `serde(rename_all =
    /// "kebab-case")` shape so SDK rows and JSON rows agree without
    /// a serde round-trip.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Path => "path",
            Self::Header => "header",
            Self::Cookie => "cookie",
            Self::Form => "form",
            Self::Multipart => "multipart",
            Self::File => "file",
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Yaml => "yaml",
            Self::Graphql => "graphql",
            Self::Jwt => "jwt",
            Self::OauthToken => "oauth-token",
            Self::Protobuf => "protobuf",
            Self::Msgpack => "msgpack",
            Self::Csv => "csv",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Url => "url",
            Self::Hostname => "hostname",
            Self::Ip => "ip",
            Self::Sql => "sql",
            Self::Template => "template",
            Self::Event => "event",
            Self::QueueMessage => "queue-message",
            Self::PubsubMessage => "pubsub-message",
            Self::DbRow => "db-row",
            Self::ConfigValue => "config-value",
            Self::SensorFrame => "sensor-frame",
            Self::HardwareRegister => "hardware-register",
            Self::Html => "html",
        }
    }
}

/// A match kind — the browse-fact family the rule narrows.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Call,
    /// Match an exact compiler-declared callable/interface type. This kind
    /// is consumed only by typing rules; it never emits a finding.
    Type,
    Read,
    Write,
    New,
    /// Match a function return expression. Useful for framework
    /// handlers that return raw response bodies directly.
    Return,
    /// Match a function declaration's parameter identifier. Useful for
    /// framework request-handler parameters (Express `req`, Flask
    /// `request`, Lambda `event`) when the adapter doesn't emit the
    /// per-field read as a ref.
    Param,
    /// Inverse-match: rule fires when no call to the declared target
    /// appears on any reachable path before a guarded sink. Used for
    /// CSRF-token-unvalidated, rate-limit-absent, auth-check-skipped,
    /// missing-output-escaping families. The matcher walks each
    /// entrypoint's reachable function set and checks for the
    /// `target` callee — if absent, emits a finding at the entry's
    /// declaration site with kind=Missing.
    Missing,
}

/// Compiler binding evidence required by an exact call target.
///
/// This is provider-neutral: the owning rule supplies the callable spelling,
/// while shared matching only checks import aliases or lexical absence.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleBindingOrigin {
    /// The call root must be an adapter-emitted import alias.
    Imported,
    /// The call root is supplied by the language runtime/host environment and
    /// therefore must have no competing lexical binding.
    RuntimeGlobal,
}

/// The match target — either a callee (for `call` / `new`) or a place/value
/// target (for `read` / `write` / `param` and optionally `return`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTarget {
    /// Unqualified name match (e.g. `system`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Dotted / `::`-joined attribute chain (e.g. `[flask, request, args]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<Vec<String>>,
    /// Regex on the qualified callee / target name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Exact compiler binding origin required for this callable or write
    /// target. Imported identities must resolve through an adapter-emitted
    /// import alias; runtime globals must have no compiler-proven lexical
    /// collision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_origin: Option<RuleBindingOrigin>,
    /// Optional receiver/base identifier filter for receiver-agnostic
    /// regexes. Example: `regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.execute$"`
    /// plus `base_name_in: [conn, db]` matches `conn.execute(...)` and
    /// `db.execute(...)` without hardcoding the receiver in the regex.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_name_in: Vec<String>,
    /// Optional inverse receiver/base identifier filter. Useful for
    /// receiver-shaped method rules that should not match module
    /// functions with the same tail (`raw.decode(...)` yes,
    /// `jsonpickle.decode(...)` no).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_name_not_in: Vec<String>,
    /// Match a parameter by an annotation/decorator name attached to it
    /// (Java `@RequestParam`, Python `@requires_admin`-style param
    /// decorators when the adapter surfaces them, C# `[FromBody]`).
    /// Only meaningful with `kind: param`. Reads
    /// `Decl.param_annotations` parallel-indexed with `params`. T204.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
    /// Match a parameter by the direct call used as its default value
    /// (Python `payload = fastapi.Body(...)`). Only meaningful with
    /// `kind: param`; reads the adapter-emitted
    /// `Decl.param_default_calls` syntax fact. API/framework names belong in
    /// this rule field, never in language adapters or shared analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_call: Option<String>,
    /// Restrict a rule match to declarations whose enclosing class
    /// equals or extends one of the given names. Lets rules like
    /// `WebSocketHandler.on_message(self, message)` and
    /// `RequestHandler.self.get_argument(...)` require the class
    /// shape so same-name helpers do not match every framework-
    /// importing file. Resolves through the adapter's `Decl.parent`
    /// link to the enclosing class decl. Case-sensitive — names are
    /// matched exactly against the class decl's `name` or `bases`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_class: Vec<String>,
    /// Restrict a rule match to declarations whose enclosing class name or
    /// one of its adapter-emitted base names ends with a declared suffix.
    /// This models generated base-class families without treating a
    /// conventional method or parameter name as semantic evidence. The
    /// suffix itself remains rule data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_class_suffix: Vec<String>,
    /// Restrict a declaration to an adapter-owned lexical owner that declares
    /// one of these direct bases, interfaces, traits, or runtime behaviours.
    /// Unlike `in_class`, this accepts any explicit owner kind (including a
    /// language module) and checks only its parsed base/behaviour inventory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_owner_base: Vec<String>,
    /// Restrict a rule match to declarations whose own name equals
    /// one of the given values (`on_message`, `resolve_field`,
    /// `dispatch`). Combined with `in_class`, this lets framework
    /// source rules pin the host signature precisely. Reads the
    /// enclosing decl's `name`. Case-sensitive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_method: Vec<String>,
    /// Restrict a rule match to declarations whose own name starts with
    /// one of the given prefixes. This keeps framework rules from
    /// enumerating generated handler names such as GraphQL `resolve_*`
    /// while preserving a simple, auditable string gate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_method_prefix: Vec<String>,
    /// Restrict a `kind: param` rule to zero-based parameter indexes.
    /// This keeps framework signature rules precise when the parameter
    /// name alone is common, e.g. GraphQL resolver `(parent, args, ...)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_index_in: Vec<u32>,
    /// Exclude exact zero-based parameter positions. This complements
    /// `param_index_in` for callback contracts with one syntax-proven
    /// receiver slot followed by an open-ended payload signature.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_index_not_in: Vec<u32>,
    /// Restrict a `kind: param` rule to declarations with one of these
    /// adapter-emitted parameter types at the matched index. The matcher
    /// reads `Decl.type_aliases`; it never infers a type from the parameter
    /// spelling. Both qualified and short type names are accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_type_in: Vec<String>,
    /// Restrict a `kind: param` rule to an exact adapter-emitted qualified
    /// parameter type. Unlike `param_type_in`, this never falls back to the
    /// terminal type segment, so independently owned types such as
    /// `left::Request` and `right::Request` cannot collide. Adapters must
    /// preserve the qualified compiler spelling in `Decl.type_aliases` for
    /// rules that use this constraint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_type_exact_in: Vec<String>,
    /// Additional typed positions required in the enclosing declaration's
    /// complete parameter signature. This is useful when the matched payload
    /// type is generated or application-specific, but a sibling runtime
    /// context parameter has a stable external type.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature_param_types: Vec<SignatureParamTypeRequirement>,
    /// Exact adapter-emitted parameter annotations required at sibling
    /// positions in the enclosing declaration. This completes compound
    /// selector/callback signatures whose individual parameter name and type
    /// are not sufficient to identify the boundary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature_param_annotations: Vec<SignatureParamAnnotationRequirement>,
    /// Restrict a `kind: param` rule to declarations with one of these
    /// grammar-declared parameter counts. This models runtime entry
    /// signatures without depending on conventional names such as `args`
    /// or `argv`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_count_in: Vec<u32>,
    /// Restrict receiver/base-shaped targets such as `args.filter` to
    /// cases where the base identifier is a formal parameter at one of
    /// these zero-based indexes in the enclosing declaration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_param_index_in: Vec<u32>,
    /// Restrict receiver/base-shaped read/write targets to cases where
    /// the base identifier has one of these adapter-emitted semantic
    /// receiver types in the enclosing declaration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receiver_type_in: Vec<String>,
    /// Restrict a `kind: param` rule to declarations with one of the
    /// adapter-emitted declaration kinds (`method`, `function`,
    /// `constructor`, ...). This is adapter metadata, not a source-text
    /// naming convention.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decl_kind_in: Vec<DeclKind>,
    /// Restrict a `kind: param` rule to declarations with one of the
    /// adapter-emitted visibilities (`public`, `private`, `crate`,
    /// `module`, `protected`, `internal`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visibility_in: Vec<Visibility>,
    /// Restrict a call-shaped rule to adapter-lowered call kinds. This is a
    /// compiler fact (for example an indexed write), not an API spelling.
    /// It lets rulepacks match source-language operations without teaching
    /// shared lowering or analysis a provider-specific pseudo-callee.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_kind_in: Vec<bonsai_lang_api::CallKind>,
}

impl RuleTarget {
    /// True when no match shape is set — used by the loader to reject
    /// rules that declare a kind but supply nothing for the matcher
    /// to look at.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.attribute.is_none()
            && self.regex.is_none()
            && self.annotation.is_none()
            && self.default_call.is_none()
            && self.base_name_in.is_empty()
            && self.base_name_not_in.is_empty()
            && self.in_class.is_empty()
            && self.in_class_suffix.is_empty()
            && self.in_owner_base.is_empty()
            && self.in_method.is_empty()
            && self.in_method_prefix.is_empty()
            && self.param_index_in.is_empty()
            && self.param_index_not_in.is_empty()
            && self.param_type_in.is_empty()
            && self.param_type_exact_in.is_empty()
            && self.signature_param_types.is_empty()
            && self.signature_param_annotations.is_empty()
            && self.param_count_in.is_empty()
            && self.base_param_index_in.is_empty()
            && self.receiver_type_in.is_empty()
            && self.decl_kind_in.is_empty()
            && self.visibility_in.is_empty()
            && self.call_kind_in.is_empty()
    }
}

/// One exact parameter-position/type requirement on an enclosing declaration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureParamTypeRequirement {
    pub index: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_in: Vec<String>,
}

/// One exact parameter-position/annotation requirement on an enclosing
/// declaration. Annotation strings come only from adapter-emitted compiler
/// facts; provider-specific selector/decorator names remain rulepack data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureParamAnnotationRequirement {
    pub index: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotation_in: Vec<String>,
}

/// Full match specification — the `match:` block in YAML.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    pub kind: MatchKind,
    /// Call / new callee target. Populated when `kind == Call | New`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callee: Option<RuleTarget>,
    /// Place/value target. Required for read/write/param, optional for return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<RuleTarget>,
}

/// Positional roles for a rule-matched selector whose receiver may be a
/// compiler-proven finite string map. The rule's ordinary `match.callee`
/// owns the selector spelling; this structure assigns only generic value
/// roles to the exact matcher-approved call span.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteLiteralMapSelectorSemantics {
    /// Positional argument carrying the finite map for namespace/static
    /// selectors. Omit for receiver-method selectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_argument_index: Option<usize>,
    pub key_argument_index: usize,
    pub fallback_argument_index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintSemantics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_output_overwrite: Option<CleanOutputOverwriteSemantics>,
    /// Sanitizer rules only: the matched call mutates its receiver into a
    /// clean value. The security matcher compiles the complete rule to exact
    /// call spans before IDG construction, so constraints remain authoritative
    /// and unrelated calls with the same operator/method spelling are never
    /// granted this transfer.
    #[serde(default, skip_serializing_if = "is_false")]
    pub clean_receiver_overwrite: bool,
    /// Sanitizer rules only: the matched call returns either one value from a
    /// complete local static string map or an exact literal fallback. The
    /// finding-time proof joins the exact matched call span to compiler facts
    /// and rejects ambiguous bindings, writes, aliases, and nonliteral values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finite_literal_map_selector: Option<FiniteLiteralMapSelectorSemantics>,
    /// Source rules only: argument indices that receive attacker-
    /// controlled output from the call. This covers C-style APIs such
    /// as `recv(fd, buf, len, flags)` and `SSL_read(ssl, buf, len)`
    /// where the return value is a byte count but the buffer argument
    /// becomes tainted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_output_args: Vec<usize>,
    /// Source rules only: the first argument in a variadic output tail.
    /// Every actual argument at or after this index receives untrusted
    /// output. This models compiler-visible shapes such as `scanf` and
    /// database `Scan` calls without imposing an arbitrary destination cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_output_args_from: Option<usize>,
    /// Source rules only: callback argument shapes whose callback
    /// parameters receive attacker-controlled data from the source call.
    /// This covers Node-style APIs such as
    /// `fs.readFile(path, (err, data) => ...)` and
    /// `process.stdin.on("data", chunk => ...)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_callback_args: Vec<SourceCallbackArgSemantics>,
    /// Source rules only: the call's return is registration/status state, not
    /// source data. Callback delivery parameters remain the only seeds. Leave
    /// false for hybrid APIs whose return and callback can both carry input.
    #[serde(default, skip_serializing_if = "is_false")]
    pub source_callback_only: bool,
    /// Sanitizer/passthrough rules only: argument indices whose value
    /// flows unchanged to the call result. This covers decode/unescape
    /// APIs that preserve attacker control while changing representation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_result_passthrough_args: Vec<usize>,
    /// Sanitizer/passthrough rules only: the first argument in a variadic
    /// input tail whose actual values all flow to the call result. Expansion
    /// uses the compiler-observed call arity, so the rule never needs an
    /// arbitrary maximum argument list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_result_passthrough_args_from: Option<usize>,
    /// Typing rules only: the matched runtime/library call invokes one
    /// compiler-resolved callable argument. Argument and return positions are
    /// structural roles; the owning rule supplies the callable identity and
    /// is compiled to exact call spans before graph construction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_invocation: Option<CallbackInvocationSemantics>,
    /// Sanitizer/passthrough rules only: the method receiver flows
    /// unchanged to the call result. This covers receiver transforms
    /// such as `value.removingPercentEncoding`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub call_result_passthrough_receiver: bool,
    /// Rulepack-declared transfer: tainted value arguments flow into
    /// an output argument. This covers buffer-format/copy APIs without
    /// baking API names into the engine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_arg_flows: Vec<OutputArgFlowSemantics>,
    /// Sink rules only: tainted arguments mutate the receiver's
    /// state. This covers APIs such as `Statement.addBatch(sql)` and
    /// `ProcessBuilder.command(cmd)`, where the dangerous operation
    /// happens later on the same receiver (`executeBatch()`,
    /// `start()`). The security layer derives the receiver type and
    /// method from the rule's structured callee target; the taint
    /// engine never owns a central method-name list.
    #[serde(default, skip_serializing_if = "is_false")]
    pub taint_receiver_from_args: bool,
}

/// Which compiler binding a rule-declared lifecycle call changes.
///
/// Provider and API identities stay in the typing rule's structured
/// `match` target. This enum describes only the language-neutral transfer:
/// a method changes its receiver, or a function changes one positional
/// argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleBindingTarget {
    Receiver,
    Argument { index: u32 },
}

/// Non-finding lifecycle transfer compiled from a `typing/` rule.
///
/// For example, a rule can match `close` and declare that its receiver moves
/// to `closed`, while a `free` rule declares argument zero `freed`. The
/// matcher consumes exact adapter-emitted call facts; neither adapters nor
/// shared analysis own provider API spellings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleTransitionSemantics {
    pub state: String,
    pub binding: LifecycleBindingTarget,
}

/// Language-independent semantic classes used only when selecting the
/// representative source for several proven flows that collapse into one
/// finding group. These are rulepack declarations, not names inferred from
/// rule ids, API spellings, or source text.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlowClass {
    /// Local process input such as argv, stdin, or an interactive CLI.
    ProcessInput,
    /// Remote HTTP/web request input.
    HttpInput,
    /// Input originating from the process environment.
    EnvironmentInput,
    /// A process execution or command-interpreter sink.
    ProcessExecution,
    /// A browser/HTML output sink.
    BrowserOutput,
}

/// Provenance of a rule/finding match inside the analysis pipeline.
///
/// Synthetic source classification is carried as data so consumers never
/// infer behavior from the spelling of a generated rule id.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchOrigin {
    #[default]
    Rulepack,
    InferredUnreferencedParameter,
    InferredFrameworkParameter,
    InferredClassField,
    Pattern,
    EngineSanitizer,
}

/// Structured guard recognizers implemented over compiler flow facts.
///
/// A sink opts into one profile declaratively. The recognizer still proves
/// the guard from [`bonsai_lang_api::FlowEvent`] branches, calls, and
/// assignments; this enum merely selects which proof to run.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardProfile {
    #[serde(alias = "python-path-containment")]
    CanonicalPathContainment,
    #[serde(
        rename = "path-consumer-containment",
        alias = "python-path-consumer-containment"
    )]
    PathConsumerContainment,
    RelativePathContainment,
}

/// Rule-selected compiler capability that clears a matched sink.
///
/// The adapter proves the syntax/runtime property and emits a typed
/// [`bonsai_lang_api::CompilerGuardFact`]. The shared engine only joins that
/// fact to the matched call; capability vocabulary and security labels stay
/// in rulepack data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerGuardSemantics {
    pub capability: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_evidence: Vec<String>,
    pub sanitizer_tag: String,
    pub category: String,
}

/// Rule-selected value roles for sanitizer calls that act as guards rather
/// than returning a replacement value. The engine joins these roles to exact
/// compiler call arguments and control flow without interpreting the tag.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizerGuardSemantics {
    #[serde(default)]
    pub use_receiver: bool,
    #[serde(default)]
    pub all_arguments: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argument_indices: Vec<usize>,
    #[serde(default)]
    pub require_terminal_rejection: bool,
    /// Value the matched predicate must have on the accepted path after a
    /// terminal rejection branch. `None` preserves the validator convention
    /// that a true predicate is safe; rejection predicates declare `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_predicate_value: Option<bool>,
}

/// Rulepack-owned callable roles used by the structured path-containment
/// proof. The engine consumes these as compiler match targets over call and
/// assignment facts; standard-library spellings never live in analysis code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathContainmentGuardSemantics {
    /// Call whose result canonicalizes the sink-produced path.
    pub canonicalizer: RuleTarget,
    /// Receiver call used to prove that the canonical path stays below the
    /// configured base directory.
    pub containment_check: RuleTarget,
    /// Positional argument that carries the canonical candidate when the
    /// containment API is a namespace/static function. When omitted, the
    /// candidate remains the call receiver for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_check_candidate_arg_index: Option<usize>,
    /// Positional argument that carries the trusted base.
    #[serde(default)]
    pub containment_check_base_arg_index: usize,
    /// Argument on the matched sink call that denotes the trusted base path.
    pub sink_base_arg_index: usize,
    /// AST-derived place operands that must accompany the base argument in
    /// the containment check (for example a platform path separator).
    pub boundary_places: Vec<String>,
}

/// Rule-owned construction of a boundary-safe containment operand.
///
/// Some APIs express `base + separator` as a method call rather than as a
/// compiler string-composition place (for example a receiver method taking a
/// literal separator). The frontend supplies the exact nested call, receiver,
/// argument place, and decoded scalar; this descriptor assigns those generic
/// facts their path-boundary meaning without embedding API names or separator
/// values in shared analysis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathBoundaryBuilderSemantics {
    pub call: RuleTarget,
    #[serde(default)]
    pub base_from_receiver: bool,
    #[serde(default)]
    pub base_arg_index: usize,
    pub boundary_arg_index: usize,
    pub accepted_boundary_values: Vec<StaticScalarValue>,
}

/// Rulepack-owned roles for proving that a value consumed by a later path
/// sink was canonicalized, built below a trusted base, and rejected on
/// containment failure before the consumer executes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathConsumerContainmentGuardSemantics {
    pub canonicalizer: RuleTarget,
    /// The canonicalizer consumes the value through its exact compiler
    /// receiver rather than positional argument zero.
    #[serde(default)]
    pub canonicalizer_input_from_receiver: bool,
    /// Canonicalizer used to establish the trusted base. When omitted, the
    /// candidate canonicalizer is used for both roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_canonicalizer: Option<RuleTarget>,
    /// Call that combines a trusted base with an untrusted child path.
    /// Omitted only when [`Self::path_constructor_is_string_composition`]
    /// selects the adapter's exact ordered string-composition fact instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_constructor: Option<RuleTarget>,
    /// The canonicalizer input is an adapter-lowered ordered string
    /// composition whose leading component is the trusted base and whose
    /// next component is a rule-declared segment boundary.
    #[serde(default)]
    pub path_constructor_is_string_composition: bool,
    /// Some runtimes model the trusted base as the path-constructor receiver
    /// (`base.resolve(child)`) rather than as a positional argument.
    #[serde(default)]
    pub path_constructor_base_from_receiver: bool,
    pub containment_check: RuleTarget,
    /// Optional runtime precondition whose selected argument must evaluate
    /// truthy for execution to continue. The frontend lowers the exact
    /// predicate expression; rule data owns the runtime call identity and
    /// continuation contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_guard: Option<RuleTarget>,
    /// Predicate argument on [`Self::acceptance_guard`].
    #[serde(default)]
    pub acceptance_guard_condition_arg_index: usize,
    /// Optional value projection applied to the canonical candidate before
    /// the containment predicate consumes it (for example a path object's
    /// string-valued property). The projection identity remains rule-owned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_candidate_projection: Option<RuleTarget>,
    /// Optional value projection applied to the trusted base before it is
    /// used in the containment operand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_base_projection: Option<RuleTarget>,
    /// Positional argument that carries the canonical candidate when the
    /// containment API is a namespace/static function. When omitted, the
    /// candidate remains the call receiver for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_check_candidate_arg_index: Option<usize>,
    /// Positional argument that carries the trusted base.
    #[serde(default)]
    pub containment_check_base_arg_index: usize,
    /// Exact compiler-decoded return values for which the containment check
    /// accepts the candidate. An empty list means the check itself is a
    /// boolean predicate and must evaluate truthy. This keeps APIs such as a
    /// numeric prefix/index routine entirely rule-owned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_containment_results: Vec<StaticScalarValue>,
    /// Factories whose result is a trusted base only when every argument is
    /// an exact compiler-decoded scalar. Runtime/API names stay in rule data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_base_factories: Vec<RuleTarget>,
    /// The matched consumer receives the guarded path through its compiler
    /// receiver rather than a positional argument.
    #[serde(default)]
    pub sink_path_from_receiver: bool,
    pub sink_path_arg_index: usize,
    pub path_constructor_base_arg_index: usize,
    /// The containment predicate is path-segment aware by runtime contract
    /// and therefore needs no textual separator operand.
    #[serde(default)]
    pub containment_check_is_segment_aware: bool,
    pub boundary_places: Vec<String>,
    /// Exact call shapes that construct a boundary operand from the trusted
    /// base and an adapter-decoded static separator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundary_builders: Vec<PathBoundaryBuilderSemantics>,
    /// Exact compiler-decoded literal suffixes that may be composed directly
    /// with the trusted base to form a segment boundary. Values and path API
    /// identities remain entirely rule-owned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_boundary_values: Vec<StaticScalarValue>,
}

/// Rulepack-owned roles for a canonical relative-path containment proof.
///
/// The engine proves the complete sequence from compiler facts:
/// canonicalized candidate → relative-path result → rejecting branch →
/// guarded construction/consumer. Callable names, argument conventions,
/// tuple-result position, and unsafe relative values all remain language
/// rulepack data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelativePathContainmentGuardSemantics {
    pub candidate_canonicalizer: RuleTarget,
    pub base_canonicalizer: RuleTarget,
    pub relative_path: RuleTarget,
    pub relative_path_result_index: usize,
    pub relative_base_arg_index: usize,
    pub relative_candidate_arg_index: usize,
    /// `Some(index)` guards a path consumer argument. `None` guards the
    /// canonicalized assignment containing the matched construction sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guarded_path_arg_index: Option<usize>,
    pub rejection_check: RuleTarget,
    pub rejection_check_arg_index: usize,
    /// Argument containing the rejected relative-path prefix, when the
    /// runtime exposes the boundary test as a separate call. The compiler
    /// must prove a complete string composition beginning with one of
    /// `rejected_exact_values` and ending in an allowed boundary wrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_prefix_arg_index: Option<usize>,
    /// Exact path-separator places accepted in the prefix composition.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejection_boundary_places: Vec<String>,
    /// Runtime conversions allowed to wrap a boundary place in the prefix
    /// composition. Names remain rulepack data; the engine only joins typed
    /// call and composition facts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejection_boundary_wrappers: Vec<RuleTarget>,
    pub rejected_exact_values: Vec<String>,
}

/// Rulepack-owned argument roles for a parameterized query API.
///
/// The engine proves from compiler facts that the query value contains only
/// literal or allowlisted structural fragments and that dynamic values travel
/// through the distinct bindings argument. Driver method names and argument
/// conventions therefore remain rulepack data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterizedQuerySemantics {
    pub query_arg_index: usize,
    pub bindings_arg_index: usize,
}

/// Rulepack-owned roles for a document-database filter.
///
/// The engine proves the filter's nested object shape from compiler facts.
/// Operator spellings and the API's filter-argument convention remain data in
/// the language rulepack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoSqlFilterSemantics {
    pub filter_arg_index: usize,
    pub literal_value_operators: Vec<String>,
    /// Exact frontend-owned runtime type names that cannot carry document
    /// operators when used as filter values. The engine still requires a
    /// dominating terminal-rejection proof for every dynamic value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_scalar_runtime_types: Vec<String>,
    /// Exact frontend-owned static types that cannot carry document
    /// operators when used as values in a compiler-proven literal-key
    /// filter. Unlike `safe_scalar_runtime_types`, these need no dynamic
    /// rejection branch because the language type system enforces them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_scalar_compiler_types: Vec<String>,
    /// Source rules whose matched call contract guarantees a scalar return.
    /// The engine still proves that the exact filter value derives from the
    /// matched source span; API identities remain rulepack data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_scalar_source_rules: Vec<String>,
}

/// Rulepack-owned roles for proving that a dynamic-key sink is protected by
/// an exact denylist. The language frontend supplies decoded literal values
/// and typed branch/call facts; the engine supplies only generic control-flow
/// proof and therefore carries no language, API, or forbidden-key inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicKeyDenylistGuardSemantics {
    /// Constructor used to materialize a static collection.
    pub collection_constructor: RuleTarget,
    /// Membership predicate invoked on that collection.
    pub membership_check: RuleTarget,
    /// Argument of `membership_check` that carries the dynamic key.
    pub membership_subject_arg_index: usize,
    /// Constructor argument holding the literal collection values.
    pub collection_values_arg_index: usize,
    /// Every value that must be rejected before a sink is safe.
    pub rejected_exact_values: Vec<String>,
    /// Sink argument containing a filtered dynamic property key/path. Omit
    /// for recursive write rules whose key is inherent in the matched write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_key_argument_index: Option<usize>,
    /// Require a helper summary proving nested values pass through the same
    /// filter before a recursive object-merge sink.
    #[serde(default)]
    pub require_recursive_filter: bool,
    /// Sink argument that must be the exact result of a compiler-proven
    /// recursive key-filter helper. Required when `require_recursive_filter`
    /// is true; omitted for inline dynamic-write guards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filtered_value_argument_index: Option<usize>,
}

/// Rulepack-owned factory roles that make a receiver safe for one sink rule.
///
/// The engine proves that the matched receiver's latest preceding assignment
/// is a direct call to one of these factories. Factory names remain language
/// rulepack data; the proof itself consumes only compiler assignment facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverFactoryGuardSemantics {
    pub factories: Vec<RuleTarget>,
    /// Calls that must occur inside the selected factory expression. This
    /// models safe constructor composition without teaching the shared
    /// engine any constructor or API spellings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_nested_factories: Vec<RuleTarget>,
    /// Exact scalar arguments required on the receiver's reaching factory
    /// assignment.  The frontend decodes the complete ordered argument
    /// vector; rule data owns argument roles and accepted values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_arguments: Vec<RequiredSequenceItemSpec>,
}

/// One exact argument-place requirement on a receiver configuration call.
///
/// The adapter supplies an addressable projection for the argument expression
/// (for example a constant member). The rulepack owns the accepted symbolic
/// places; shared analysis never parses the rendered argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCallArgumentSemantics {
    pub index: usize,
    /// Accept any exact adapter-decoded scalar at this position. This is
    /// useful when safety comes from keeping an executable/configuration
    /// selector static rather than from one enumerated literal.
    #[serde(default)]
    pub require_static_value: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_places: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_static_values: Vec<StaticScalarValue>,
}

/// One required, unconditional call that configures a sink receiver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredReceiverCallSemantics {
    pub call: RuleTarget,
    /// Arguments that identify the configured facet when several calls share
    /// one method (for example `setFeature(name, enabled)`). The latest call
    /// with the same exact identity wins; later writes to other facets do not
    /// erase this state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_argument_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_arguments: Vec<RequiredCallArgumentSemantics>,
}

/// Rulepack-owned safe state required on a sink receiver.
///
/// Shared analysis proves that all required calls unconditionally configure
/// the exact receiver either before the sink in the same declaration or in
/// every constructor of the receiver's containing type. Runtime/API names
/// and symbolic configuration values remain rulepack data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverConfigurationGuardSemantics {
    pub required_calls: Vec<RequiredReceiverCallSemantics>,
}

/// Rulepack-owned safe state for a receiver that is materialized into one
/// configured wrapper and then passed to a sink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredArgumentReceiverGuardSemantics {
    pub sink_argument_index: usize,
    pub wrapper_factory: RuleTarget,
    pub configured_receiver_argument_index: usize,
    pub provider_factory: RuleTarget,
    pub required_calls: Vec<RequiredReceiverCallSemantics>,
}

/// Rulepack-owned safe state configured by an immediately-invoked callback
/// whose implicit receiver is the value returned by a factory call.
///
/// Some languages expose standard-library scope/configuration calls whose
/// callback body invokes receiver methods without spelling the receiver. The
/// compiler supplies the exact assignment, nested provider call, callback
/// span, callback declaration, and unconditional call/argument facts. Rule
/// data owns every API identity and the callback/runtime role; shared analysis
/// never guesses a provider or method from source text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverCallbackConfigurationGuardSemantics {
    /// Call whose return value is configured and retained by the wrapper.
    pub provider_factory: RuleTarget,
    /// Immediately-invoked wrapper that executes the callback with the
    /// provider result as its implicit receiver.
    pub wrapper_call: RuleTarget,
    /// Positional wrapper argument containing the exact inline callback.
    pub callback_argument_index: usize,
    /// Call that derives the eventual sink receiver from the configured
    /// factory value.
    pub sink_receiver_builder: RuleTarget,
    /// Unconditional implicit-receiver calls required inside the callback.
    pub required_calls: Vec<RequiredReceiverCallSemantics>,
}

/// One exact named argument required on a configured factory call.
///
/// The owning language frontend decodes the scalar value from the parsed
/// argument node. The security engine compares that typed fact directly and
/// never interprets rendered source text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredNamedArgumentSemantics {
    pub name: String,
    pub value: StaticScalarValue,
}

/// Rulepack-owned roles for a sink argument made safe by a configured
/// factory.
///
/// The engine proves that the selected sink argument is an addressable value,
/// its latest preceding assignment is the declared direct factory call, and
/// every required named argument has the exact frontend-decoded scalar value.
/// Argument positions, factory identity, option names, and required values
/// therefore remain language rulepack data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredArgumentFactoryGuardSemantics {
    pub sink_argument_index: usize,
    pub factory: RuleTarget,
    /// Exact positional factory arguments required directly on the factory
    /// call. This supports factory-produced collections whose first element
    /// has security meaning while later elements may remain dynamic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_arguments: Vec<RequiredCallArgumentSemantics>,
    /// Exact named arguments required directly on the factory call.
    /// Empty is permitted when [`Self::required_aggregate_argument`] carries
    /// the complete configuration proof instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_named_arguments: Vec<RequiredNamedArgumentSemantics>,
    /// Exact fields required on one aggregate-valued factory argument. The
    /// frontend may carry these fields through a latest preceding local
    /// assignment, but only as compiler-owned structure; provider names,
    /// argument roles, field paths, and values remain rulepack data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_aggregate_argument: Option<ConfiguredFactoryAggregateArgumentSemantics>,
}

/// One aggregate configuration argument required on a factory call whose
/// result is later consumed by a sink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredFactoryAggregateArgumentSemantics {
    pub argument_index: usize,
    pub required_fields: Vec<RequiredAggregateFieldSemantics>,
}

/// One exact aggregate field required on a configuration argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredAggregateFieldSemantics {
    pub path: Vec<String>,
    pub value: StaticScalarValue,
}

/// Exact configured factory state required on a matched call receiver.
///
/// The language frontend supplies the immutable receiver assignment, direct
/// factory identity, and complete aggregate argument fields. Rule data owns
/// the factory, argument position, field paths, and values; the shared matcher
/// only joins those typed facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverFactoryArgumentFieldsSpec {
    pub factory: RuleTarget,
    pub configuration_argument_index: usize,
    pub required_fields: Vec<RequiredAggregateFieldSemantics>,
}

/// Exact scalar constructor/factory arguments required for the latest
/// reaching assignment of a matched receiver. The frontend owns scalar
/// decoding and assignment identity; the rulepack owns the factory and
/// accepted values.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverFactoryArgumentsSpec {
    pub factory: RuleTarget,
    pub items: Vec<RequiredSequenceItemSpec>,
}

/// Rulepack-owned safe configuration for a direct sink call.
///
/// The adapter decodes exact scalar fields from a structurally complete,
/// spread-free aggregate argument. Dynamic values in unrelated fields are
/// retained as unknown and cannot override the exact fields. The engine
/// compares typed field/value facts and credits only the explicitly listed
/// value arguments; neither layer reparses source text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredCallArgumentGuardSemantics {
    pub configuration_argument_index: usize,
    pub guarded_value_argument_indices: Vec<usize>,
    pub required_fields: Vec<RequiredAggregateFieldSemantics>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactStringMapping {
    pub input: String,
    pub output: String,
}

/// Required substitutions for a compiler-proven local character transform.
/// Helper/API names are irrelevant: the frontend proves the transform shape,
/// while the rulepack owns the security-specific mapping inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharacterEscapeSemantics {
    /// Sink arguments whose complete value must be escaped. Empty selects a
    /// matched return-expression value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value_arg_indices: Vec<usize>,
    pub required_mappings: Vec<ExactStringMapping>,
    /// Accepted runtime providers for provider-bound compiler facts. Legacy
    /// language-native substitution facts remain provider-independent; a
    /// provider-bound fact receives security meaning only through this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_providers: Vec<CharacterConstraintProviderSemantics>,
}

/// Security-specific forbidden characters for a compiler-proven local
/// alphabet constraint. Language frontends own transform syntax; this rule
/// metadata owns the boundary requirements for the selected sink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharacterConstraintSemantics {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_excluded_characters: Vec<String>,
    /// Complete exact substitution inventory required at this security
    /// boundary. Provider and mapping identities remain rulepack policy;
    /// adapters only lower the configured runtime transform from syntax.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_mappings: Vec<ExactStringMapping>,
    /// Optional delimiter that must compiler-provably enclose the constrained
    /// value in the final string composition. SQL sinks use this to
    /// distinguish a quote-safe string value from an unquoted identifier or
    /// expression, where an alphanumeric allowlist alone is not a sanitizer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_enclosing_literal_delimiter: Option<String>,
    /// Accepted runtime providers for a compiler-lowered candidate transform.
    /// The adapter records call identity without assigning security meaning;
    /// these rulepack targets decide which factory/operation pair has the
    /// required runtime semantics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_providers: Vec<CharacterConstraintProviderSemantics>,
    /// Source payload domains that may complete a compiler fact whose
    /// transform is exact but whose dynamic predicate receiver type is not.
    /// This vocabulary is rulepack policy: adapters never name frameworks or
    /// infer security meaning from source APIs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_untyped_source_payload_types: Vec<PayloadType>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharacterConstraintProviderSemantics {
    /// Optional factory identity for two-stage transforms such as a compiled
    /// regular expression or configured replacer. Direct language-runtime
    /// operations have no separate factory and bind only `operation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factory: Option<RuleTarget>,
    pub operation: RuleTarget,
}

/// Rule-owned meaning for one compiler-proven boolean predicate call.
///
/// Adapters emit only the call expression span and branch polarity. This
/// structure selects the runtime callable and exact scalar argument that make
/// that generic syntax fact relevant to a security boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardedPredicateRequirement {
    pub target: RuleTarget,
    #[serde(default)]
    pub argument_index: usize,
    pub argument_value: StaticScalarValue,
    pub required_result: bool,
}

/// Required facets of a compiler-proven same-origin path helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SameOriginPathConstraintSemantics {
    pub require_scheme_rejection: bool,
    pub require_authority_rejection: bool,
    pub require_absolute_path: bool,
    pub require_scheme_relative_rejection: bool,
    /// Runtime providers accepted for provider-bound compiler facts. Empty
    /// means the proof is entirely syntax-defined and provider-independent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_providers: Vec<RuleTarget>,
    /// Runtime predicate meanings required by the proof. Callable and literal
    /// vocabulary belongs here rather than in language adapters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_predicates: Vec<GuardedPredicateRequirement>,
    /// Exact compiler facts required by this security proof. Literal values
    /// and provider-result field names live in rule data, never adapters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_accepted_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_rejected_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_rejected_components: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_static_fallbacks: Vec<String>,
    /// Exact tainted sink argument that must receive the constrained path.
    /// Header-style APIs use argument one while direct redirect APIs use zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_argument_index: Option<usize>,
    /// Optional exact, rulepack-owned context argument. This lets a generic
    /// header API credit same-origin proof only for a Location header without
    /// changing the semantics of unrelated headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_context_argument: Option<StaticContextArgumentSemantics>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticContextArgumentSemantics {
    pub index: usize,
    pub accepted_renderings: Vec<String>,
}

/// Where the guarded parsed URL value appears at the matched sink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum UrlGuardRootSemantics {
    SinkReceiver,
    SinkAssignmentTarget,
    /// The sink consumes a parsed URL value directly. The exact argument
    /// place must be the target of a preceding assignment containing the
    /// rule-declared parser call; component guards are proven on that place.
    SinkArgumentParsedValue {
        argument_index: usize,
    },
    /// The sink consumes the original URL value while a preceding parser
    /// assignment validates that same value. Both argument roles and parser
    /// identity are rulepack data.
    SinkArgumentParserInput {
        sink_argument_index: usize,
        parser_argument_index: usize,
    },
    SinkArgumentAccessor {
        argument_index: usize,
        accessor: Box<RuleTarget>,
    },
}

/// A URL component represented either by an exact projected field or by a
/// rulepack-owned accessor call on the parsed URL value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlComponentSemantics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessor: Option<RuleTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlSchemeGuardSemantics {
    pub component: UrlComponentSemantics,
    /// Optional comparison predicate such as a language/platform string
    /// equality method. When absent, adapters must lower an exact equality
    /// expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_predicate: Option<RuleTarget>,
    pub allowed_values: Vec<String>,
    /// Exact scheme strings accepted in the rebuilt URL. Some runtimes expose
    /// a parsed protocol with punctuation (`https:`) while source syntax
    /// reconstructs the RFC scheme without it (`https://`). When omitted, the
    /// comparison values are also the reconstruction values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reconstructed_values: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlHostAllowlistSemantics {
    pub component: UrlComponentSemantics,
    /// Optional predicate such as a collection `contains` method. When absent,
    /// the adapter must emit typed membership syntax.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_predicate: Option<RuleTarget>,
    /// Factories allowed to construct a static finite collection. Literal
    /// aggregate initializers need no factory entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_collection_factories: Vec<RuleTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlAddressParserSemantics {
    pub target: RuleTarget,
    pub argument_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlDnsGuardSemantics {
    pub resolver: RuleTarget,
    /// Optional provider that converts one resolver result into the value
    /// consumed by the private-address predicates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_parser: Option<UrlAddressParserSemantics>,
    pub private_address_predicates: Vec<RuleTarget>,
}

/// Redirect hardening required at an outbound-request boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum UrlRedirectGuardSemantics {
    ReceiverFieldExactCallback {
        field: String,
        required_return_place: String,
    },
    PostSinkCall {
        call: Box<RuleTarget>,
        argument_index: usize,
        required_value: StaticScalarValue,
    },
    /// A sink option object carries one or more exact static fields, such as
    /// `{ followRedirect: false }`. The adapter lowers exact scalar fields
    /// from the structurally complete argument aggregate; rule metadata owns
    /// the client-specific option paths and values.
    CallArgumentFields {
        argument_index: usize,
        required_fields: Vec<RequiredAggregateFieldSemantics>,
    },
}

/// Compiler-fact proof for a parsed, scheme-restricted, host-allowlisted,
/// DNS-checked outbound URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlNetworkGuardSemantics {
    pub root: UrlGuardRootSemantics,
    pub parser: RuleTarget,
    pub scheme: UrlSchemeGuardSemantics,
    pub host_allowlist: UrlHostAllowlistSemantics,
    /// Optional DNS-address rejection proof. Rules for arbitrary caller-
    /// controlled hosts require this. A rule whose finite host allowlist is
    /// itself the declared trust boundary may omit it; the engine still
    /// requires exact parser, scheme, finite-membership, and redirect facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<UrlDnsGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<UrlRedirectGuardSemantics>,
}

/// Rulepack-owned roles for a helper that parses, validates, and reconstructs
/// a URL before passing it to an outbound sink.
///
/// The owning language adapter lowers the complete string composition and
/// boolean guard syntax. The engine only relates those compiler facts to the
/// parser/component vocabulary and exact scalar requirements declared here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlReconstructionGuardSemantics {
    pub sink_argument_index: usize,
    pub parser: RuleTarget,
    pub scheme: UrlSchemeGuardSemantics,
    pub host_allowlist: UrlHostAllowlistSemantics,
    pub path_component: UrlComponentSemantics,
    /// Required fallback for a nullable/falsey path component. Omit when the
    /// runtime accessor itself always returns a string and the exact
    /// composition consumes it directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_fallback: Option<String>,
    /// Optional redirect policy required by clients that follow redirects by
    /// default. The same compiler proof used by URL-network guards applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<UrlRedirectGuardSemantics>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_sink_named_arguments: Vec<RequiredNamedArgumentSemantics>,
}

/// Role a sink rule plays in an implicit context channel.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextFlowRole {
    Producer,
    Consumer,
}

/// Declarative description of an implicit context flow. Producer findings
/// can be continued to consumer sink hits with the same channel and language.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFlowSemantics {
    /// Stable rulepack-owned channel identity, e.g. `logging.mdc`.
    pub channel: String,
    /// Whether the rule writes to or consumes from the channel.
    pub role: ContextFlowRole,
    /// Human-readable synthetic value used in taint-path evidence.
    pub value_label: String,
    /// Synthetic parameter name used in the continuation edge.
    pub parameter_name: String,
    /// A sanitizer-cleared write from one of these source rules replaces the
    /// current channel value before a later consumer in the same control-flow
    /// scope. IDs remain rulepack data; the engine proves ordering and the
    /// compiler-lowered non-null branch relationship.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrite_source_rule_ids: Vec<String>,
    #[serde(default)]
    pub sanitized_rewrite_clears_channel: bool,
}

/// Explicit exceptions to the normal source-before-sanitizer-before-sink
/// ordering contract. The rulepack selects the policy; the engine proves its
/// preconditions from structured spans and rule metadata.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostSinkPolicy {
    /// A path-construction sink may be contained by a later path sanitizer in
    /// the same file because the joined value is not consumed until after the
    /// containment check.
    PathConstructionContainment,
}

/// Exact dataflow attachment shape for sanitizer evidence that is not a
/// direct tainted-value call. Rules select the shape; shared analysis only
/// proves it from compiler facts.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SanitizerAttachmentPolicy {
    /// A hardened factory/configuration receiver must be the sink receiver or
    /// must construct that receiver before the sink.
    ReceiverFactoryLineage,
}

/// Optional analysis behavior compiled from the rulepack.
///
/// This keeps engine policy independent of rule ids and language/API names.
/// Every field is semantic and closed over a typed vocabulary; absence means
/// the normal generic analysis behavior.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSemantics {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_classes: Vec<FlowClass>,
    /// Suppress inferred entry parameters for this sink class because those
    /// values are not evidence for the sink's security property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppress_inferred_sources: Option<bool>,
    /// Suppress locally trusted sources with any matching rule-declared flow
    /// class. This is reporting policy, not a propagation shortcut.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppress_local_source_flow_classes: Vec<FlowClass>,
    /// Lower values win when equally proven source sites are grouped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_specificity_rank: Option<u8>,
    /// Higher values sort later in otherwise identical report ordering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_reporting_rank: Option<u8>,
    /// Prefer this sink as the canonical reporting boundary over a
    /// lower-priority sink reached strictly downstream on the same proven
    /// source flow. Higher values win. This affects presentation only: both
    /// sinks remain in the compiler facts and taint graph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_terminal_priority: Option<u8>,
    /// Explicit evaluation mode for sink rules that do not require a taint
    /// source. Authored categories may inherit this through rulepack metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_taint_evaluation: Option<NonTaintEvaluation>,
    /// Permit file-level package/import evidence when the matched call itself
    /// has no receiver/package identity. Sources default to `true` for
    /// framework request objects; sinks default to `false`. Set this to
    /// `false` on a source whose compiler import/alias binding is required to
    /// distinguish a library API from a same-named application method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_file_package_evidence: Option<bool>,
    /// The sink's compiler/lifecycle constraint is sufficient identity, so a
    /// separate call-site package gate is unnecessary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_call_package_gate: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_profile: Option<GuardProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_guard: Option<CompilerGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitizer_guard: Option<SanitizerGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_containment_guard: Option<PathContainmentGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_consumer_containment_guard: Option<PathConsumerContainmentGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_path_containment_guard: Option<RelativePathContainmentGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameterized_query: Option<ParameterizedQuerySemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nosql_filter: Option<NoSqlFilterSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_key_denylist_guard: Option<DynamicKeyDenylistGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_factory_guard: Option<ReceiverFactoryGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_configuration_guard: Option<ReceiverConfigurationGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured_argument_factory_guard: Option<ConfiguredArgumentFactoryGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured_argument_receiver_guard: Option<ConfiguredArgumentReceiverGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_callback_configuration_guard: Option<ReceiverCallbackConfigurationGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured_call_argument_guard: Option<ConfiguredCallArgumentGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub character_escape: Option<CharacterEscapeSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub character_constraint: Option<CharacterConstraintSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_origin_path_constraint: Option<SameOriginPathConstraintSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_network_guard: Option<UrlNetworkGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_reconstruction_guard: Option<UrlReconstructionGuardSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_flow: Option<ContextFlowSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_sink_policy: Option<PostSinkPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitizer_attachment_policy: Option<SanitizerAttachmentPolicy>,
    /// Rulepack-owned constructor calls that may connect a hardened factory
    /// receiver to the eventual sink receiver. Shared analysis proves the
    /// assignment lineage and never owns the constructor/API vocabulary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receiver_factory_lineage_builders: Vec<RuleTarget>,
}

impl AnalysisSemantics {
    /// Overlay explicitly declared fields while retaining unspecified bundled
    /// defaults. This is the inverse view of `inherit_missing`: overlay data
    /// wins and the existing value fills its omissions.
    pub(crate) fn merge_overriding(&mut self, incoming: Self) {
        let mut merged = incoming;
        merged.inherit_missing(self);
        *self = merged;
    }

    /// Fill absent rule-specific semantics from rulepack metadata. Explicit
    /// rule fields always win; metadata provides declarative per-tag defaults
    /// without introducing security taxonomy branches in the engine.
    pub(crate) fn inherit_missing(&mut self, defaults: &Self) {
        if self.flow_classes.is_empty() {
            self.flow_classes.clone_from(&defaults.flow_classes);
        }
        if self.suppress_local_source_flow_classes.is_empty() {
            self.suppress_local_source_flow_classes
                .clone_from(&defaults.suppress_local_source_flow_classes);
        }
        if let (Some(current), Some(default)) = (
            self.character_constraint.as_mut(),
            defaults.character_constraint.as_ref(),
        ) {
            if current.accepted_providers.is_empty() {
                current.accepted_providers.clone_from(&default.accepted_providers);
            }
            if current.accepted_untyped_source_payload_types.is_empty() {
                current
                    .accepted_untyped_source_payload_types
                    .clone_from(&default.accepted_untyped_source_payload_types);
            }
        }
        if self.character_constraint.is_none() {
            self.character_constraint
                .clone_from(&defaults.character_constraint);
        }
        if let (Some(current), Some(default)) = (
            self.same_origin_path_constraint.as_mut(),
            defaults.same_origin_path_constraint.as_ref(),
        ) {
            if current.accepted_providers.is_empty() {
                current.accepted_providers.clone_from(&default.accepted_providers);
            }
            if current.required_predicates.is_empty() {
                current
                    .required_predicates
                    .clone_from(&default.required_predicates);
            }
            if current.required_accepted_prefixes.is_empty() {
                current
                    .required_accepted_prefixes
                    .clone_from(&default.required_accepted_prefixes);
            }
            if current.required_rejected_prefixes.is_empty() {
                current
                    .required_rejected_prefixes
                    .clone_from(&default.required_rejected_prefixes);
            }
            if current.required_rejected_components.is_empty() {
                current
                    .required_rejected_components
                    .clone_from(&default.required_rejected_components);
            }
            if current.accepted_static_fallbacks.is_empty() {
                current
                    .accepted_static_fallbacks
                    .clone_from(&default.accepted_static_fallbacks);
            }
        }
        macro_rules! inherit_option {
            ($($field:ident),+ $(,)?) => {
                $(if self.$field.is_none() { self.$field = defaults.$field.clone(); })+
            };
        }
        inherit_option!(
            source_specificity_rank,
            source_reporting_rank,
            suppress_inferred_sources,
            sink_terminal_priority,
            non_taint_evaluation,
            allow_file_package_evidence,
            skip_call_package_gate,
            guard_profile,
            compiler_guard,
            sanitizer_guard,
            path_containment_guard,
            path_consumer_containment_guard,
            relative_path_containment_guard,
            parameterized_query,
            nosql_filter,
            dynamic_key_denylist_guard,
            receiver_factory_guard,
            receiver_configuration_guard,
            configured_argument_factory_guard,
            configured_argument_receiver_guard,
            receiver_callback_configuration_guard,
            configured_call_argument_guard,
            character_escape,
            same_origin_path_constraint,
            url_network_guard,
            url_reconstruction_guard,
            context_flow,
            post_sink_policy,
            sanitizer_attachment_policy,
        );
        if self.receiver_factory_lineage_builders.is_empty() {
            self.receiver_factory_lineage_builders
                .clone_from(&defaults.receiver_factory_lineage_builders);
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonTaintEvaluation {
    Pattern,
    Lifecycle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCallbackArgSemantics {
    pub callback_arg_index: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_param_indices: Vec<usize>,
    /// Every callback parameter at or after this index receives source data.
    /// The compiler-declared callback arity supplies the finite range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_param_indices_from: Option<usize>,
}

/// Language-neutral value roles for a call that invokes a callable argument.
///
/// This models runtime helpers such as protected-call APIs without teaching
/// the shared IDG any provider or language-specific name. The matcher proves
/// the outer call, while the compiler callgraph proves the callback binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackInvocationSemantics {
    /// Positional argument containing the invoked callable.
    pub callback_arg_index: usize,
    /// Exact field path beneath `callback_arg_index` whose value is a static
    /// callback map. When present, every compiler-proven callback stored in
    /// that complete map is invoked by the matched external API. Field/API
    /// spelling remains rule data; shared graph code receives only compiled
    /// callback identities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callback_map_field_path: Vec<String>,
    /// Exact field path beneath `callback_arg_index` whose value is forwarded
    /// into `forwarded_callback_param_index` for each callback-map entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwarded_argument_field_path: Vec<String>,
    /// Callback parameter receiving the forwarded aggregate field. Required
    /// for callback-map invocation and absent for direct callable arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_callback_param_index: Option<usize>,
    /// First outer-call argument forwarded into callback parameter zero.
    /// Omit when the callback is invoked without forwarded arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_args_from: Option<usize>,
    /// Callback parameter receiving the outer method receiver's value.
    /// This models collection/runtime APIs whose callable argument is invoked
    /// with one element from the receiver. The matched call span and callback
    /// identity remain compiler-proven; the API role lives only in rule data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_to_callback_param: Option<usize>,
    /// Positional slot in the outer call's tuple/multi-result that receives
    /// callback return zero. Later callback return fields retain this offset.
    pub callback_return_result_offset: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanOutputOverwriteSemantics {
    pub output_arg_index: usize,
    pub value_start_arg_index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputArgFlowSemantics {
    pub output_arg_index: usize,
    /// The compiler-emitted method/operator receiver flows into the output.
    /// The owning rule is matched to exact call spans before IDG lowering, so
    /// this generic value role carries no provider or API-name knowledge.
    #[serde(default, skip_serializing_if = "is_false")]
    pub value_receiver: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_start_arg_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value_arg_indices: Vec<usize>,
}

/// One constraint — a v1 vocabulary of language-agnostic post-filters.
/// Mapped to a small enum so adding constraint types is a compiler-enforced
/// audit rather than a runtime string match.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConstraintKind {
    ReceiverTypeIn {
        receiver_type_in: Vec<String>,
    },
    ReceiverTypeNotIn {
        receiver_type_not_in: Vec<String>,
    },
    /// Require the adapter-normalized receiver expression to match a
    /// rulepack-owned regex. API/runtime spellings stay in rule data; the
    /// engine evaluates the receiver emitted from the parsed call node.
    ReceiverMatchesRegex {
        receiver_matches_regex: String,
    },
    /// Reject a call when its adapter-normalized receiver expression matches
    /// a rulepack-owned regex.
    ReceiverNotMatchesRegex {
        receiver_not_matches_regex: String,
    },
    /// Keep a rule active unless a guaranteed earlier call on the same
    /// receiver matches the declared call target and decoded static-string
    /// argument regex. The matcher walks the HIR path; calls seen only on one
    /// branch never suppress a finding after the merge.
    UnlessPriorReceiverCall {
        unless_prior_receiver_call: Box<UnlessPriorReceiverCallSpec>,
    },
    /// Require a guaranteed earlier call on the same compiler receiver with
    /// exact frontend-decoded static string arguments. This is the positive
    /// counterpart to `unless_prior_receiver_call`; API and literal meaning
    /// remain entirely in rule data.
    RequiresPriorReceiverCall {
        requires_prior_receiver_call: Box<UnlessPriorReceiverCallSpec>,
    },
    /// Require the reaching definition of a rule-declared member on the same
    /// compiler receiver to be one of the exact frontend-decoded scalar
    /// values.  The matcher proves control-flow dominance and receiver
    /// identity; member and value meaning remain entirely in rule data.
    RequiresPriorReceiverWrite {
        requires_prior_receiver_write: Box<RequiresPriorReceiverWriteSpec>,
    },
    SecondArgEquals {
        second_arg_equals: String,
    },
    ArgEquals {
        arg_equals: ArgEqualsSpec,
    },
    KeywordArgEquals {
        keyword_arg_equals: KeywordArgEqualsSpec,
    },
    ArgTainted {
        arg_tainted: ArgTaintedSpec,
    },
    ReceiverTainted {
        receiver_tainted: bool,
    },
    AnyArgTainted {
        any_arg_tainted: bool,
    },
    /// A write to a receiver member is dangerous only when the receiver came
    /// from a declared factory with a tainted input and the assigned callback
    /// forwards one of its parameters to a declared call argument. The
    /// matcher proves every relationship from compiler flow facts; API and
    /// member names remain rulepack data.
    ReceiverOriginCallbackParamReachesCall {
        receiver_origin_callback_param_reaches_call: Box<ReceiverOriginCallbackParamReachesCallSpec>,
    },
    /// Require the matched call receiver to be an immutable value initialized
    /// by a declared factory whose selected aggregate argument has every
    /// rule-declared exact field/value. Unknown, mutable, spread, or
    /// ambiguous state fails closed.
    ReceiverFactoryArgumentFieldsEqual {
        receiver_factory_argument_fields_equal: Box<ReceiverFactoryArgumentFieldsSpec>,
    },
    /// Require the matched receiver's latest reaching assignment to be an
    /// exact declared factory call with selected static scalar arguments.
    ReceiverFactoryArgumentsEqual {
        receiver_factory_arguments_equal: Box<ReceiverFactoryArgumentsSpec>,
    },
    FormatArgIndex {
        format_arg_index: u32,
    },
    Namespace {
        namespace: String,
    },
    TopLevel {
        top_level: bool,
    },
    ArgCount {
        arg_count: u32,
    },
    MinArgs {
        min_args: u32,
    },
    MaxArgs {
        max_args: u32,
    },
    ArgMatchesRegex {
        arg_matches_regex: ArgRegexSpec,
    },
    ArgNotMatchesRegex {
        arg_not_matches_regex: ArgRegexSpec,
    },
    AnyArgMatchesRegex {
        any_arg_matches_regex: String,
    },
    /// Keep a rule active unless the parsed argument is an aggregate/object
    /// literal. Missing compiler value-shape facts fail open (the dangerous
    /// rule remains active).
    ArgValueNotAggregate {
        arg_value_not_aggregate: u32,
    },
    /// Require an exact adapter-emitted value-shape kind for one argument.
    /// The frontend proves syntax/type identity; the rule assigns any API or
    /// security meaning to that generic role.
    ArgValueKind {
        arg_value_kind: ArgValueKindSpec,
    },
    /// Require an exact compiler-lowered string composition whose first
    /// component is the declared literal. Rendered argument text is never
    /// parsed by this constraint.
    ArgStringCompositionStartsWith {
        arg_string_composition_starts_with: ArgStringCompositionPrefixSpec,
    },
    /// Reject only the exact compiler-lowered composition prefix selected by
    /// the rule. Absence of a complete composition satisfies this inverse.
    ArgStringCompositionNotStartsWith {
        arg_string_composition_not_starts_with: ArgStringCompositionPrefixSpec,
    },
    /// Require the selected call argument to be an inline callback whose
    /// parameter bindings were emitted by the owning language adapter.
    /// This is a pure syntax/capability fact: provider meaning and the
    /// callback position remain rulepack data.
    ArgIsInlineCallback {
        arg_is_inline_callback: u32,
    },
    /// Require one inline callback argument whose complete normal return is
    /// an exact adapter-decoded scalar. Provider/API identity and callback
    /// position remain rulepack data; named, mixed, or ambiguous callbacks
    /// fail closed.
    ArgInlineCallbackReturnsStatic {
        arg_inline_callback_returns_static: ArgInlineCallbackStaticReturnSpec,
    },
    /// Require exact adapter-decoded scalar values at selected positions in
    /// one complete positional aggregate argument.
    ArgSequenceItemsEqual {
        arg_sequence_items_equal: ArgSequenceItemsSpec,
    },
    /// Require exact adapter-decoded scalar fields on one complete aggregate
    /// call argument. Provider/API identity and field paths remain rule data;
    /// dynamic spreads, missing fields, and non-aggregate arguments fail
    /// closed.
    ArgAggregateFieldsEqual {
        arg_aggregate_fields_equal: ArgAggregateFieldsSpec,
    },
    SameReceiverCallCountAtLeast {
        same_receiver_call_count_at_least: u32,
    },
    /// `arg_lt: { index, value }` — the integer literal at the given
    /// arg position is strictly less than `value`. Used for weak-crypto
    /// strength rules (`RSA.new(1024)` rejected by `arg_lt: 2048`).
    /// Non-literal args cause the constraint to fail (conservative);
    /// the engine never approximates an unknown integer.
    ArgLt {
        arg_lt: ArgIntSpec,
    },
    /// `arg_le: { index, value }` — integer literal ≤ `value`.
    ArgLe {
        arg_le: ArgIntSpec,
    },
    /// `arg_gt: { index, value }` — integer literal > `value`. Useful
    /// for "session timeout too long" / "JWT expiry too far".
    ArgGt {
        arg_gt: ArgIntSpec,
    },
    /// `arg_ge: { index, value }` — integer literal ≥ `value`.
    ArgGe {
        arg_ge: ArgIntSpec,
    },
    /// `requires_runtime_type: { index, type }` — the arg must
    /// be narrowed to `type` by a guarding type test (e.g.
    /// `instanceof`, `isinstance`, `is`, `typeof`). P1.
    RequiresRuntimeType {
        requires_runtime_type: RuntimeTypeSpec,
    },
    /// `enclosing_decorator_in: [name, ...]` — the enclosing decl
    /// must carry at least one decorator whose tail matches.
    EnclosingDecoratorIn {
        enclosing_decorator_in: Vec<String>,
    },
    /// None of the exact adapter-emitted decorator facts may equal a listed
    /// value. This is an absence check over compiler facts, not source text.
    EnclosingDecoratorNotIn {
        enclosing_decorator_not_in: Vec<String>,
    },
    /// `enclosing_modifier_in: [static, ...]` — the enclosing declaration
    /// must carry at least one requested modifier token in its parsed AST.
    EnclosingModifierIn {
        enclosing_modifier_in: Vec<String>,
    },
    /// Source rules only: defer source/sink compatibility until a proven
    /// taint path reaches a sink, then require the sink's semantic tag to be
    /// one of these values. This keeps narrowly purposed generic sources
    /// (for example an untrusted serialized blob parameter) from pairing
    /// with unrelated sink classes without baking rule IDs into the engine.
    SinkTagIn {
        sink_tag_in: Vec<String>,
    },
    /// `must_alias: { source_arg, sink_arg }` — the two args must
    /// share a must-alias root within the same decl. P5.
    MustAlias {
        must_alias: MustAliasSpec,
    },
    /// `requires_state: { name, expected }` — the binding must be
    /// in `expected` lifecycle state at this call site. P6.
    RequiresState {
        requires_state: RequiresStateSpec,
    },
}

impl ConstraintKind {
    /// Stable snake_case name for diagnostics and the
    /// `constraint-not-exercised` validator messages.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::ReceiverTypeIn { .. } => "receiver_type_in",
            Self::ReceiverTypeNotIn { .. } => "receiver_type_not_in",
            Self::ReceiverMatchesRegex { .. } => "receiver_matches_regex",
            Self::ReceiverNotMatchesRegex { .. } => "receiver_not_matches_regex",
            Self::UnlessPriorReceiverCall { .. } => "unless_prior_receiver_call",
            Self::RequiresPriorReceiverCall { .. } => "requires_prior_receiver_call",
            Self::RequiresPriorReceiverWrite { .. } => "requires_prior_receiver_write",
            Self::SecondArgEquals { .. } => "second_arg_equals",
            Self::ArgEquals { .. } => "arg_equals",
            Self::KeywordArgEquals { .. } => "keyword_arg_equals",
            Self::ArgTainted { .. } => "arg_tainted",
            Self::ReceiverTainted { .. } => "receiver_tainted",
            Self::AnyArgTainted { .. } => "any_arg_tainted",
            Self::ReceiverOriginCallbackParamReachesCall { .. } => {
                "receiver_origin_callback_param_reaches_call"
            }
            Self::ReceiverFactoryArgumentFieldsEqual { .. } => "receiver_factory_argument_fields_equal",
            Self::ReceiverFactoryArgumentsEqual { .. } => "receiver_factory_arguments_equal",
            Self::FormatArgIndex { .. } => "format_arg_index",
            Self::Namespace { .. } => "namespace",
            Self::TopLevel { .. } => "top_level",
            Self::ArgCount { .. } => "arg_count",
            Self::MinArgs { .. } => "min_args",
            Self::MaxArgs { .. } => "max_args",
            Self::ArgMatchesRegex { .. } => "arg_matches_regex",
            Self::ArgNotMatchesRegex { .. } => "arg_not_matches_regex",
            Self::AnyArgMatchesRegex { .. } => "any_arg_matches_regex",
            Self::ArgValueNotAggregate { .. } => "arg_value_not_aggregate",
            Self::ArgValueKind { .. } => "arg_value_kind",
            Self::ArgStringCompositionStartsWith { .. } => "arg_string_composition_starts_with",
            Self::ArgStringCompositionNotStartsWith { .. } => "arg_string_composition_not_starts_with",
            Self::ArgIsInlineCallback { .. } => "arg_is_inline_callback",
            Self::ArgInlineCallbackReturnsStatic { .. } => "arg_inline_callback_returns_static",
            Self::ArgSequenceItemsEqual { .. } => "arg_sequence_items_equal",
            Self::ArgAggregateFieldsEqual { .. } => "arg_aggregate_fields_equal",
            Self::SameReceiverCallCountAtLeast { .. } => "same_receiver_call_count_at_least",
            Self::ArgLt { .. } => "arg_lt",
            Self::ArgLe { .. } => "arg_le",
            Self::ArgGt { .. } => "arg_gt",
            Self::ArgGe { .. } => "arg_ge",
            Self::RequiresRuntimeType { .. } => "requires_runtime_type",
            Self::EnclosingDecoratorIn { .. } => "enclosing_decorator_in",
            Self::EnclosingDecoratorNotIn { .. } => "enclosing_decorator_not_in",
            Self::EnclosingModifierIn { .. } => "enclosing_modifier_in",
            Self::SinkTagIn { .. } => "sink_tag_in",
            Self::MustAlias { .. } => "must_alias",
            Self::RequiresState { .. } => "requires_state",
        }
    }

    /// True for constraints that examine specific call arguments —
    /// these need both a positive and a negative `match_examples`
    /// entry to demonstrate the discriminator works.
    #[must_use]
    pub fn is_discriminating(&self) -> bool {
        matches!(
            self,
            Self::ArgTainted { .. }
                | Self::ReceiverTainted { .. }
                | Self::AnyArgTainted { .. }
                | Self::ReceiverMatchesRegex { .. }
                | Self::ReceiverNotMatchesRegex { .. }
                | Self::UnlessPriorReceiverCall { .. }
                | Self::ReceiverOriginCallbackParamReachesCall { .. }
                | Self::SecondArgEquals { .. }
                | Self::ArgEquals { .. }
                | Self::KeywordArgEquals { .. }
                | Self::ArgMatchesRegex { .. }
                | Self::ArgNotMatchesRegex { .. }
                | Self::AnyArgMatchesRegex { .. }
                | Self::ArgValueNotAggregate { .. }
                | Self::ArgValueKind { .. }
                | Self::ArgStringCompositionStartsWith { .. }
                | Self::ArgStringCompositionNotStartsWith { .. }
                | Self::ArgIsInlineCallback { .. }
                | Self::ArgInlineCallbackReturnsStatic { .. }
                | Self::ArgSequenceItemsEqual { .. }
                | Self::ArgAggregateFieldsEqual { .. }
                | Self::FormatArgIndex { .. }
                | Self::ArgLt { .. }
                | Self::ArgLe { .. }
                | Self::ArgGt { .. }
                | Self::ArgGe { .. }
                | Self::RequiresRuntimeType { .. }
                | Self::MustAlias { .. }
                | Self::RequiresState { .. }
        )
    }
}

/// Declarative state guard for a prior call on the same parsed receiver.
///
/// `static_string_args_regex` is evaluated against language-decoded static
/// string arguments joined with the ASCII unit separator (`\x1f`). Dynamic
/// arguments or non-string literals cannot satisfy the guard. This keeps
/// quoting, escapes, delimiters, and argument boundaries in the owning
/// language frontend while allowing the rulepack to own framework API and
/// literal semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlessPriorReceiverCallSpec {
    pub call: RuleTarget,
    pub static_string_args_regex: String,
}

/// Declarative reaching-definition constraint for a receiver member.
///
/// Values are compared with adapter-decoded scalar facts, never rendered
/// source.  A branch, loop, exception path, dynamic write, or ambiguous
/// receiver definition therefore fails closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiresPriorReceiverWriteSpec {
    pub target: RuleTarget,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_values: Vec<StaticScalarValue>,
    /// Exact call-shaped values accepted for the reaching write. The
    /// frontend owns callable identity and scalar argument decoding; rule
    /// data owns the allowed factory and values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_calls: Vec<ExactCallArgumentsSpec>,
}

/// One exact call result accepted as the value of a reaching receiver write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactCallArgumentsSpec {
    pub call: RuleTarget,
    pub items: Vec<RequiredSequenceItemSpec>,
}

/// Compiler proof for a callback extension on a factory-created receiver.
///
/// For a matched write such as `decoder.extension = callback`, the matcher
/// proves that:
/// 1. the reaching definition of `decoder` is `receiver_factory(...)`;
/// 2. `factory_tainted_arg_index` carries the current source taint;
/// 3. the assigned callback's `callback_param_index` reaches
///    `callback_call` argument `callback_call_arg_index`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverOriginCallbackParamReachesCallSpec {
    pub receiver_factory: RuleTarget,
    pub factory_tainted_arg_index: u32,
    pub receiver_member: RuleTarget,
    pub callback_param_index: u32,
    pub callback_call: RuleTarget,
    pub callback_call_arg_index: u32,
}

/// `{ source_arg, sink_arg }` for the must-alias constraint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MustAliasSpec {
    pub source_arg: u32,
    pub sink_arg: u32,
}

/// `{ name, expected }` for the lifecycle-state constraint.
/// `requires_state: { name | index, expected }` — the binding the call
/// acts on must be in `expected` lifecycle state at this call site.
/// Use `index` (the call's argument position) to bind to whatever
/// variable is actually passed — e.g. `requires_state: { index: 0,
/// expected: freed }` on `free`/`strcpy` flags a double-free or
/// use-after-free of ANY pointer, not just one literally named `p`.
/// `name` keeps the legacy literal-binding form.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiresStateSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    pub expected: String,
}

impl<'de> Deserialize<'de> for RequiresStateSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            index: Option<u32>,
            expected: String,
        }

        let raw = Raw::deserialize(deserializer)?;
        match (raw.name, raw.index) {
            (Some(name), None) if !name.trim().is_empty() => Ok(Self {
                name: Some(name),
                index: None,
                expected: raw.expected,
            }),
            (None, Some(index)) => Ok(Self {
                name: None,
                index: Some(index),
                expected: raw.expected,
            }),
            _ => Err(de::Error::custom(
                "requires_state must set exactly one of non-empty `name` or `index`",
            )),
        }
    }
}

/// `{ index, value }` for the integer-comparison constraints
/// (`arg_lt` / `arg_le` / `arg_gt` / `arg_ge`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgIntSpec {
    pub index: u32,
    pub value: i64,
}

/// `{ index, type_name }` for the typed-flow-narrowing constraint
/// (`requires_runtime_type`). The arg at `index` must be statically
/// narrowed to a value of declared type `type_name` at the call site.
/// The matcher fails closed when no preceding runtime type-test
/// narrowing dominates the call site.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTypeSpec {
    pub index: u32,
    #[serde(rename = "type")]
    pub type_name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArgTaintedSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kw: Option<String>,
}

impl<'de> Deserialize<'de> for ArgTaintedSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            index: Option<u32>,
            #[serde(default)]
            kw: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        match (raw.index, raw.kw) {
            (Some(index), None) => Ok(Self {
                index: Some(index),
                kw: None,
            }),
            (None, Some(kw)) if !kw.trim().is_empty() => Ok(Self {
                index: None,
                kw: Some(kw),
            }),
            _ => Err(de::Error::custom(
                "arg_tainted must set exactly one of `index` or non-empty `kw`",
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgEqualsSpec {
    pub index: u32,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgValueKindSpec {
    pub index: u32,
    pub kind: AssignValueKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgStringCompositionPrefixSpec {
    pub index: u32,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgInlineCallbackStaticReturnSpec {
    pub index: u32,
    pub value: StaticScalarValue,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeywordArgEqualsSpec {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgRegexSpec {
    pub index: u32,
    pub regex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredSequenceItemSpec {
    pub index: usize,
    pub accepted_values: Vec<StaticScalarValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgSequenceItemsSpec {
    pub argument_index: usize,
    pub items: Vec<RequiredSequenceItemSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgAggregateFieldsSpec {
    pub argument_index: usize,
    pub required_fields: Vec<RequiredAggregateFieldSemantics>,
}

/// Convenience: a rule's `constraints:` block is a list of keyed maps, each
/// carrying exactly one constraint type. We store them flattened so match
/// evaluation can loop once over the set.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleConstraint(pub Vec<ConstraintKind>);

impl RuleConstraint {
    /// True when no constraints are attached — the matcher uses this
    /// to skip constraint evaluation entirely on bare rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate the constraint list in declaration order.
    pub fn iter(&self) -> std::slice::Iter<'_, ConstraintKind> {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a RuleConstraint {
    type Item = &'a ConstraintKind;
    type IntoIter = std::slice::Iter<'a, ConstraintKind>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A rule-owned fixture that must match this rule after normal
/// parsing/indexing. These examples are deliberately kept in YAML beside
/// the rule so pattern authors prove the exact adapter fact shape they
/// intended (`kind`, callee/target text, argument positions, and
/// constraints).
#[derive(Clone, Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMatchExample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub code: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expect_match_text: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub expect_no_match: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expect_no_match_text: Vec<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde `skip_serializing_if` callback signature
fn is_false(value: &bool) -> bool {
    !*value
}

impl<'de> Deserialize<'de> for RuleMatchExample {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            path: Option<String>,
            code: String,
            #[serde(default)]
            expect_match_text: Vec<String>,
            #[serde(default)]
            expect_no_match: bool,
            #[serde(default)]
            expect_no_match_text: Vec<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        if raw.expect_no_match && !raw.expect_match_text.is_empty() {
            return Err(de::Error::custom(
                "match_examples entries cannot combine `expect_match_text` with `expect_no_match: true`",
            ));
        }
        if !raw.expect_no_match && !raw.expect_no_match_text.is_empty() {
            return Err(de::Error::custom(
                "`expect_no_match_text` requires `expect_no_match: true`",
            ));
        }
        Ok(Self {
            name: raw.name,
            path: raw.path,
            code: raw.code,
            expect_match_text: raw.expect_match_text,
            expect_no_match: raw.expect_no_match,
            expect_no_match_text: raw.expect_no_match_text,
        })
    }
}

/// Severity advisory. Tools may elevate this based on reachability or
/// precision when rendering findings.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Stable lowercase string label, matching the
    /// `serde(rename_all = "lowercase")` shape so renderers don't
    /// have to round-trip through serde for display strings.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DisabledReasonCode {
    Subsumed,
    OverBroad,
    RequiresConstraint,
    PendingAdapterFact,
}

impl DisabledReasonCode {
    /// Stable kebab-case string label for diagnostics and the
    /// `disabled_reason_counts` summary in `validate_pack`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Subsumed => "subsumed",
            Self::OverBroad => "over-broad",
            Self::RequiresConstraint => "requires-constraint",
            Self::PendingAdapterFact => "pending-adapter-fact",
        }
    }

    /// True when re-enabling the rule requires engine / adapter work
    /// that hasn't landed yet. The `subsumed` and `over-broad` codes
    /// describe deliberate design choices that won't change.
    #[must_use]
    pub fn waits_on_reenable_work(&self) -> bool {
        matches!(self, Self::RequiresConstraint | Self::PendingAdapterFact)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisabledReason {
    pub code: DisabledReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsumed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reenable_when: Option<String>,
}

/// One rule. `kind` is directory-derived (the file lives in `sources/`,
/// `sinks/`, or `sanitizers/`) so rules can't lie about their family.
/// `language` may come from either the directory layout
/// (`langs/<lang>/...`) OR from the YAML `language:` field — the latter
/// lets custom rulepack projects use a flat directory layout. When both
/// are present, the loader requires them to match (drift guard).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<DisabledReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Sources only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frameworks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manifests: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lockfiles: Vec<String>,
    /// Loader-injected adapter-visible package spelling semantics. Security
    /// values stay in YAML metadata while the matcher remains language-neutral.
    #[serde(skip, default)]
    pub package_matching: crate::loader::PackageMatchSemantics,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload_types: Vec<PayloadType>,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    /// Rulepack-compiled analysis policy. This is separate from transfer
    /// semantics because it controls finding attribution, structured guard
    /// proofs, and implicit context continuation rather than IDG edges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_semantics: Option<AnalysisSemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint_semantics: Option<TaintSemantics>,
    /// Typing-only rulepack declaration for a call that changes the
    /// lifecycle state of its receiver or one positional argument. External
    /// API spellings remain in `match`; shared analysis consumes only this
    /// generic transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_transition: Option<LifecycleTransitionSemantics>,
    /// Rulepack-declared factory-method return type. When a rule names
    /// a factory method via its structured `match` callee (`name:
    /// cursor` or `attribute: [Connection, cursor]`) and sets
    /// `returns_type: Cursor`, the matcher types a local assigned from
    /// that factory (`c = engine.connect().cursor()` → `c: Cursor`) so
    /// `receiver_type_in` sinks on the local resolve. The engine owns no
    /// method-name list — the names come from the rulepack (mirrors
    /// `taint_receiver_from_args`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns_type: Option<String>,
    /// Rulepack-declared parameter types for an otherwise untyped inline
    /// callback. The outer vector follows callback parameter order; each
    /// inner vector may carry both qualified and short aliases for that one
    /// parameter. For `match.kind: call`, `callback_arg_index` selects the
    /// callback argument. For `match.kind: type`, the target selects the
    /// compiler-declared functional-interface/callable type.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callback_param_types: Vec<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_arg_index: Option<u32>,
    /// Static aggregate-field path beneath `callback_arg_index` when the
    /// callback is stored in a configuration object rather than passed as
    /// the complete argument. Field spelling is rulepack-owned; the compiler
    /// contributes only exact parsed aggregate/callback facts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callback_field_path: Vec<String>,
    #[serde(default, skip_serializing_if = "RuleConstraint::is_empty")]
    pub constraints: RuleConstraint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_examples: Vec<RuleMatchExample>,
    pub description: String,
    /// Populated by the loader from the containing directory
    /// (`sources/`, `sinks/`, `sanitizers/`, `typing/`).
    #[serde(skip)]
    pub kind: RuleKind,
    /// Either declared in YAML (`language: python`) or derived from the
    /// containing `langs/<lang>/` directory. Defaults to empty before
    /// the loader resolves it. The loader rejects rules where neither
    /// source supplies a language, and rejects rules where YAML and
    /// directory disagree.
    #[serde(default)]
    pub language: String,
    /// Source file path for diagnostics.
    #[serde(skip)]
    pub source_path: String,
}
