//! Rule schema — the in-memory shape of one `sources/sinks/sanitizers` YAML entry.
//!
//! Fields mirror `docs/security-spec.mdx § Rule schema` exactly. Unknown YAML
//! fields are rejected by the loader so rulepacks catch typos at load time
//! instead of silently failing to match.

use bonsai_lang_api::{DeclKind, Visibility};
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    /// Restrict a `kind: param` rule to zero-based parameter indexes.
    /// This keeps framework signature rules precise when the parameter
    /// name alone is common, e.g. GraphQL resolver `(parent, args, ...)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_index_in: Vec<u32>,
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
            && self.in_class.is_empty()
            && self.in_method.is_empty()
            && self.param_index_in.is_empty()
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
    /// BFS depth for `kind: missing`. `0` (default) is
    /// intra-procedural; higher values walk reachable callees,
    /// capped engine-side at 4. Ignored for other kinds.
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
            Self::SecondArgEquals { .. } => "second_arg_equals",
            Self::ArgEquals { .. } => "arg_equals",
            Self::KeywordArgEquals { .. } => "keyword_arg_equals",
            Self::ArgTainted { .. } => "arg_tainted",
            Self::ReceiverTainted { .. } => "receiver_tainted",
            Self::AnyArgTainted { .. } => "any_arg_tainted",
            Self::FormatArgIndex { .. } => "format_arg_index",
            Self::Namespace { .. } => "namespace",
            Self::TopLevel { .. } => "top_level",
            Self::ArgCount { .. } => "arg_count",
            Self::MinArgs { .. } => "min_args",
            Self::MaxArgs { .. } => "max_args",
            Self::ArgMatchesRegex { .. } => "arg_matches_regex",
            Self::ArgNotMatchesRegex { .. } => "arg_not_matches_regex",
            Self::AnyArgMatchesRegex { .. } => "any_arg_matches_regex",
            Self::SameReceiverCallCountAtLeast { .. } => "same_receiver_call_count_at_least",
            Self::ArgLt { .. } => "arg_lt",
            Self::ArgLe { .. } => "arg_le",
            Self::ArgGt { .. } => "arg_gt",
            Self::ArgGe { .. } => "arg_ge",
            Self::RequiresRuntimeType { .. } => "requires_runtime_type",
            Self::EnclosingDecoratorIn { .. } => "enclosing_decorator_in",
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
                | Self::SecondArgEquals { .. }
                | Self::ArgEquals { .. }
                | Self::KeywordArgEquals { .. }
                | Self::ArgMatchesRegex { .. }
                | Self::ArgNotMatchesRegex { .. }
                | Self::AnyArgMatchesRegex { .. }
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

/// `{ source_arg, sink_arg }` for the must-alias constraint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MustAliasSpec {
    pub source_arg: u32,
    pub sink_arg: u32,
}

/// `{ name, expected }` for the lifecycle-state constraint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiresStateSpec {
    pub name: String,
    pub expected: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint_semantics: Option<TaintSemantics>,
    #[serde(default, skip_serializing_if = "RuleConstraint::is_empty")]
    pub constraints: RuleConstraint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_examples: Vec<RuleMatchExample>,
    pub description: String,
    /// Populated by the loader from the containing directory
    /// (`sources/`, `sinks/`, `sanitizers/`).
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
