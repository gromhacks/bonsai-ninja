//! Rule schema — the in-memory shape of one `sources/sinks/sanitizers` YAML entry.
//!
//! Fields mirror `docs/security-spec.mdx § Rule schema` exactly. Unknown YAML
//! fields are rejected by the loader so rulepacks catch typos at load time
//! instead of silently failing to match.

use bonsai_lang_api::{DeclKind, StaticScalarValue, Visibility};
use serde::{de, Deserialize, Deserializer, Serialize};

/// Which of the three rule families a rule belongs to. Derived from the
/// directory the YAML file is loaded from (`sources/`, `sinks/`,
/// `sanitizers/`) — never declared inside the rule itself.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Source,
    Sink,
    Sanitizer,
    /// Typing-only rules (`typing/` dir). They declare a factory
    /// method's return type via `returns_type` so the matcher can
    /// resolve `receiver_type_in` on locals assigned from that factory
    /// (`c = engine.connect().cursor()` → `c: Cursor`). They NEVER
    /// produce findings — `build_factory_returns` reads them via
    /// `all_rules()`, but they are excluded from every source/sink/
    /// sanitizer finding + inventory path, and from sink-only
    /// validation/conformance checks (cwe, severity, sink-doc, SARIF).
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Call,
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

/// The match target — either a callee (for `call` / `new`) or a read / write
/// target (for `read` / `write`).
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
    /// Restrict a `kind: param` rule to declarations with one of these
    /// adapter-emitted parameter types at the matched index. The matcher
    /// reads `Decl.type_aliases`; it never infers a type from the parameter
    /// spelling. Both qualified and short type names are accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_type_in: Vec<String>,
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
            && self.base_name_in.is_empty()
            && self.base_name_not_in.is_empty()
            && self.in_class.is_empty()
            && self.in_method.is_empty()
            && self.in_method_prefix.is_empty()
            && self.param_index_in.is_empty()
            && self.param_type_in.is_empty()
            && self.param_count_in.is_empty()
            && self.base_param_index_in.is_empty()
            && self.receiver_type_in.is_empty()
            && self.decl_kind_in.is_empty()
            && self.visibility_in.is_empty()
    }
}

/// Full match specification — the `match:` block in YAML.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    pub kind: MatchKind,
    /// Call / new callee target. Populated when `kind == Call | New`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callee: Option<RuleTarget>,
    /// Read / write target. Populated when `kind == Read | Write`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<RuleTarget>,
    /// Resolved-call depth for `kind: missing`. `0` (default) is
    /// intra-procedural; higher values walk reachable callees to the exact
    /// rule-declared depth. Ignored for other kinds.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub search_depth: u32,
}

// `&u32` is the signature serde expects for `skip_serializing_if`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintSemantics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_output_overwrite: Option<CleanOutputOverwriteSemantics>,
    /// Source rules only: argument indices that receive attacker-
    /// controlled output from the call. This covers C-style APIs such
    /// as `recv(fd, buf, len, flags)` and `SSL_read(ssl, buf, len)`
    /// where the return value is a byte count but the buffer argument
    /// becomes tainted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_output_args: Vec<usize>,
    /// Source rules only: callback argument shapes whose callback
    /// parameters receive attacker-controlled data from the source call.
    /// This covers Node-style APIs such as
    /// `fs.readFile(path, (err, data) => ...)` and
    /// `process.stdin.on("data", chunk => ...)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_callback_args: Vec<SourceCallbackArgSemantics>,
    /// Sanitizer/passthrough rules only: argument indices whose value
    /// flows unchanged to the call result. This covers decode/unescape
    /// APIs that preserve attacker control while changing representation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_result_passthrough_args: Vec<usize>,
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
    GoJwtInlineKeyfuncAlgorithm,
    GoXmlDecoderHardening,
    PythonPathContainment,
    #[serde(
        rename = "path-consumer-containment",
        alias = "python-path-consumer-containment"
    )]
    PathConsumerContainment,
    RelativePathContainment,
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
    /// Argument on the matched sink call that denotes the trusted base path.
    pub sink_base_arg_index: usize,
    /// AST-derived place operands that must accompany the base argument in
    /// the containment check (for example a platform path separator).
    pub boundary_places: Vec<String>,
}

/// Rulepack-owned roles for proving that a value consumed by a later path
/// sink was canonicalized, built below a trusted base, and rejected on
/// containment failure before the consumer executes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathConsumerContainmentGuardSemantics {
    pub canonicalizer: RuleTarget,
    /// Canonicalizer used to establish the trusted base. When omitted, the
    /// candidate canonicalizer is used for both roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_canonicalizer: Option<RuleTarget>,
    pub path_constructor: RuleTarget,
    pub containment_check: RuleTarget,
    pub sink_path_arg_index: usize,
    pub path_constructor_base_arg_index: usize,
    pub boundary_places: Vec<String>,
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
    pub required_named_arguments: Vec<RequiredNamedArgumentSemantics>,
}

/// One exact aggregate field required on a configuration argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredAggregateFieldSemantics {
    pub path: Vec<String>,
    pub value: StaticScalarValue,
}

/// Rulepack-owned safe configuration for a direct sink call.
///
/// The adapter decodes a complete, spread-free aggregate argument. The
/// engine compares typed field/value facts and credits only the explicitly
/// listed value arguments; neither layer reparses source text.
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
}

/// Security-specific forbidden characters for a compiler-proven local
/// alphabet constraint. Language frontends own transform syntax; this rule
/// metadata owns the boundary requirements for the selected sink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CharacterConstraintSemantics {
    pub required_excluded_characters: Vec<String>,
    /// Optional delimiter that must compiler-provably enclose the constrained
    /// value in the final string composition. SQL sinks use this to
    /// distinguish a quote-safe string value from an unquoted identifier or
    /// expression, where an alphanumeric allowlist alone is not a sanitizer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_enclosing_literal_delimiter: Option<String>,
}

/// Required facets of a compiler-proven same-origin path helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SameOriginPathConstraintSemantics {
    pub require_scheme_rejection: bool,
    pub require_authority_rejection: bool,
    pub require_absolute_path: bool,
    pub require_scheme_relative_rejection: bool,
}

/// Where the guarded parsed URL value appears at the matched sink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum UrlGuardRootSemantics {
    SinkReceiver,
    SinkAssignmentTarget,
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
pub struct UrlDnsGuardSemantics {
    pub resolver: RuleTarget,
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
    pub dns: UrlDnsGuardSemantics,
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
    pub path_fallback: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_profile: Option<GuardProfile>,
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
    pub configured_argument_factory_guard: Option<ConfiguredArgumentFactoryGuardSemantics>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCallbackArgSemantics {
    pub callback_arg_index: usize,
    pub source_param_indices: Vec<usize>,
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
            Self::SecondArgEquals { .. } => "second_arg_equals",
            Self::ArgEquals { .. } => "arg_equals",
            Self::KeywordArgEquals { .. } => "keyword_arg_equals",
            Self::ArgTainted { .. } => "arg_tainted",
            Self::ReceiverTainted { .. } => "receiver_tainted",
            Self::AnyArgTainted { .. } => "any_arg_tainted",
            Self::ReceiverOriginCallbackParamReachesCall { .. } => {
                "receiver_origin_callback_param_reaches_call"
            }
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
            Self::SameReceiverCallCountAtLeast { .. } => "same_receiver_call_count_at_least",
            Self::ArgLt { .. } => "arg_lt",
            Self::ArgLe { .. } => "arg_le",
            Self::ArgGt { .. } => "arg_gt",
            Self::ArgGe { .. } => "arg_ge",
            Self::RequiresRuntimeType { .. } => "requires_runtime_type",
            Self::EnclosingDecoratorIn { .. } => "enclosing_decorator_in",
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
