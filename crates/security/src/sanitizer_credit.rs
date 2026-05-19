//! Sanitizer-tag-to-sink-tag credit table.
//!
//! Pure data: given a sanitizer's `tag` and a sink's `tag`, decide
//! whether the sanitizer's filtering applies to that sink. The answer
//! does NOT mean the value is safe — it means the developer attempted
//! to filter for the right context. Findings whose chain has a
//! credited sanitizer are surfaced as `status: sanitized` (review for
//! bypass), per `security-spec.mdx`.
//!
//! ## Why this is NOT a "library/API propagation table"
//!
//! `docs/contributing/taint-engine-spec.mdx` non-negotiables forbid the engine from
//! using "hard-coded library/API propagation tables" or "security rule
//! IDs to decide propagation behavior." This table does neither:
//!
//! 1. The taint engine's propagation logic is unchanged. Sanitizer
//!    calls do not clear taint in `crates/taint`. This table runs at
//!    FINDING-ASSEMBLY time, not at propagation time, and only decides
//!    whether sanitizer evidence should be reported as
//!    `status: sanitized` for a given sink class.
//! 2. The keys are sanitizer TAGS — categorical metadata authored by
//!    rule writers — not rule IDs or library/API names. A new sanitizer
//!    with `tag: html-encode` automatically inherits the credit even
//!    though no engine code mentions the rule's id or its callee.
//! 3. The values are sink TAGS — same vocabulary as on the sink rule's
//!    `tag:` field. The engine reads both at runtime.
//!
//! The table is the SHAPE of "which classifier-tag covers which
//! classifier-tag" — it's the same kind of category mapping the
//! reviewer would write down. It belongs in the security crate (per
//! `docs/contributing/architecture.mdx` ownership: "Security rule matching and
//! reports — `crates/security`").
//!
//! Adding a new credit pair: extend `MAPPING` below, ship a sanitizer
//! YAML rule using the listed tag, and the engine picks it up at the
//! next run. No engine recompile needed for new sanitizer rules — they
//! reuse existing tags. Engine recompile IS needed to add a new
//! sanitizer-tag vocabulary entry here.

/// Static credit map. Each entry says: a sanitizer tagged
/// `sanitizer_tag` clears any sink whose tag is in `sink_tags`.
///
/// Same-tag credit (`sql-injection` clears `sql-injection`,
/// `path-traversal` clears `path-traversal`, etc.) is implicit — see
/// [`sanitizer_credits_sink_tag`]. Only cross-tag credits or
/// context-narrowed credits go in this table.
const MAPPING: &[(&str, &[&str])] = &[
    // Open-redirect family
    ("open-redirect-sanitize", &["open-redirect"]),
    ("url-encode", &["open-redirect"]),
    ("url-build", &["ssrf", "open-redirect"]),
    ("same-origin-path", &["open-redirect", "header-injection"]),
    // NoSQL family — sanitize-tag credits the broader nosql-injection
    // sink tag.
    ("nosql-sanitize", &["nosql-injection"]),
    ("nosql-parameter", &["nosql-injection"]),
    // Signed-token verification doubles as eval/deser guard: a hash-
    // verified payload is no longer attacker-shaped.
    (
        "signed-token-verify",
        &["code-injection", "insecure-deserialization"],
    ),
    (
        "signature-verify",
        &["code-injection", "insecure-deserialization", "untrusted-token"],
    ),
    ("signature-sanitizer", &["signature-replay", "untrusted-token"]),
    // XSS family — context-tagged HTML/JS/CSS encoders. Wrong-context
    // distinction is preserved: HTML-encode does NOT credit
    // open-redirect because URL context needs URL encoding (which is
    // `url-encode` above).
    ("html-encode", &["xss"]),
    ("html-sanitize", &["xss"]),
    ("js-encode", &["xss"]),
    ("css-encode", &["xss"]),
    ("xss-sanitize", &["xss"]),
    // Path-traversal family — separate sanitize tag clears the sink
    // family.
    ("path-sanitize", &["path-traversal"]),
    ("zip-slip-guard", &["path-traversal"]),
    (
        "regex-validate",
        &[
            "path-traversal",
            "open-redirect",
            "sql-injection",
            "xpath-injection",
        ],
    ),
    (
        "allowlist-validate",
        &[
            "path-traversal",
            "open-redirect",
            "sql-injection",
            "ssrf",
            "xpath-injection",
        ],
    ),
    (
        "char-allowlist",
        &[
            "path-traversal",
            "open-redirect",
            "sql-injection",
            "command-injection",
            "header-injection",
            "xpath-injection",
        ],
    ),
    // CSRF presence sanitizers credit csrf class.
    ("csrf-protect", &["csrf"]),
    // SSRF sanitizers (IP allowlist + URL parse + scheme guard) credit
    // ssrf class.
    ("ssrf-sanitize", &["ssrf"]),
    // LDAP filter / DN escapers.
    ("ldap-escape", &["ldap-injection"]),
    // Command-injection arg escapers.
    ("shell-escape", &["command-injection"]),
    // SQL parametric / escape paths.
    ("sql-escape", &["sql-injection"]),
    ("sql-parameter", &["sql-injection"]),
    ("sql-parameterize", &["sql-injection"]),
    ("db-bind-parameter", &["sql-injection"]),
    // Header newline strippers.
    ("header-sanitize", &["header-injection"]),
    // XXE entity-disable / secure-features.
    ("xxe-sanitizer", &["xxe"]),
    ("xpath-parameter", &["xpath-injection"]),
    // Auth: explicit auth check on the path is the architectural
    // sanitizer for the access-control / weak-auth sink families.
    ("auth-sanitizer", &["weak-auth", "access-control"]),
    ("password-verify", &["weak-auth"]),
    // Deser: explicit safe-loader (json.load vs pickle, YAML.safe_load
    // vs YAML.load).
    ("deser-secure", &["insecure-deserialization"]),
    // JWT: signature/exp/aud verifier covers the untrusted-token /
    // signature-replay sink tags.
    ("jwt-verify", &["jwt", "untrusted-token", "signature-replay"]),
    // Timing-attack family.
    ("constant-time", &["timing-attack"]),
    ("constant-time-compare", &["timing-attack"]),
    // Memory-safety helpers — bounded copies / explicit length checks.
    ("bounds-check", &["memory-safety"]),
    ("crypto-bounds", &["memory-safety", "weak-crypto"]),
    // Crypto: stronger primitive replaces weak default.
    ("crypto-mode", &["weak-crypto"]),
    ("kdf", &["weak-crypto"]),
    // Numeric coercion — strtol et al. clear integer-overflow flow
    // when paired with errno checks.
    ("numeric-coerce", &["integer-overflow"]),
    // Regex escaping — drops the redos hazard for user patterns.
    ("regex-escape", &["redos"]),
    // Information-exposure: deliberate redaction site.
    ("controlled-exposure", &["information-exposure"]),
    // Passthrough — the engine treats these as identity edges (T104),
    // not as credits. Listed here so `sanitizer_credit_audit.py` knows
    // they're recognized vocabulary, not unmapped tags.
    ("passthrough-decode", &[]),
    ("passthrough-encode", &[]),
    ("passthrough-transform", &[]),
    // Lock acquire — guards subsequent shared-state access. Credits
    // the `race` sink class so the engine knows accesses inside the
    // guard are safe.
    ("lock-acquire", &["race"]),
    // Cookie-secure — cookie set with httpOnly + secure flags.
    // Architectural sanitizer: presence is the safe shape; absence
    // on a state-changing route is the finding.
    ("cookie-secure", &["cookie-misconfig"]),
    // Rate-limit middleware presence — architectural sanitizer that
    // credits the rate-limit-missing class for a route.
    ("rate-limit", &["rate-limit-missing"]),
    // Recognized but intentionally non-crediting — these tag patterns
    // mark sites for inventory but make no claim about clearing taint.
    // Reviewer enumerates with `security sanitizers --tag <X>` to find
    // them. Adding to MAPPING with [] preserves audit silence without
    // implying a sink credit.
    ("validation", &[]),
    ("schema-validate", &[]),
    ("base64-encode", &[]),
    ("hash", &[]),
    ("url-decode", &[]),
    ("non-sanitizer", &[]),
];

/// True when a sanitizer with `san_tag` clears a sink with `sink_tag`.
///
/// Decision order:
///   1. If either tag is absent, return `false` (no claim either way).
///   2. If they match exactly, return `true` — same-class credit.
///   3. If `san_tag` appears in `MAPPING` with `sink_tag` in the
///      target list, return `true` — cross-tag credit.
///   4. Otherwise `false` — wrong-context case.
#[must_use]
pub fn sanitizer_credits_sink_tag(san_tag: Option<&str>, sink_tag: Option<&str>) -> bool {
    let (Some(s), Some(k)) = (san_tag, sink_tag) else {
        return false;
    };
    if s == k {
        return true;
    }
    for (san, sinks) in MAPPING {
        if *san == s && sinks.contains(&k) {
            return true;
        }
    }
    false
}

/// True when `san_tag` is a vocabulary entry the engine recognises but
/// whose credit list is intentionally empty — passthrough markers,
/// inventory-only tags (`validation`, `schema-validate`, `hash`,
/// `url-decode`, `base64-encode`, `non-sanitizer`). Status assembly
/// uses this to avoid mis-classifying these tags as `WrongContext`:
/// they made no claim of clearing taint to begin with, so a chain that
/// only contains them stays `Unsanitized`.
#[must_use]
pub fn sanitizer_tag_is_recognized_non_crediting(san_tag: &str) -> bool {
    for (tag, sinks) in MAPPING {
        if *tag == san_tag {
            return sinks.is_empty();
        }
    }
    false
}

#[cfg(test)]
#[path = "sanitizer_credit_tests.rs"]
mod tests;
