//! Render security reports (text / graph JSON / train JSON).
//!
//! The renderers are pure functions over the in-memory data model — the
//! CLI commands feed them the already-matched / already-grouped data.

use crate::deps::DependencyInventory;
use crate::finding::Finding;
use crate::matcher::RuntimeDisabledRule;
use serde::Serialize;

const CWE_TAXONOMY_GUID: &str = "25F72D7E-8A92-459D-AD67-64853F788765";

#[derive(Clone, Debug, Serialize)]
pub struct SecurityReport {
    pub schema_version: String,
    pub language_coverage: Vec<String>,
    pub findings: Vec<Finding>,
    /// Rules the runtime matcher dropped during this analysis run
    /// (e.g., regex compile failures the schema-level pack validator
    /// did not catch). Empty when no rules were dropped. Surfacing
    /// this in the public report makes those silent failures visible
    /// to the user without requiring `tracing::warn` log scraping.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_disabled_rules: Vec<RuntimeDisabledRule>,
}

impl SecurityReport {
    /// Build a report from findings only — runtime-disabled rules
    /// default to empty. Use [`Self::with_runtime_disabled_rules`] when
    /// the matcher actually dropped rules.
    #[must_use]
    pub fn new(findings: Vec<Finding>) -> Self {
        Self::with_runtime_disabled_rules(findings, Vec::new())
    }

    /// Full constructor — derives `language_coverage` from the
    /// findings' languages so consumers don't have to pass the same
    /// list twice.
    #[must_use]
    pub fn with_runtime_disabled_rules(
        findings: Vec<Finding>,
        runtime_disabled_rules: Vec<RuntimeDisabledRule>,
    ) -> Self {
        let mut languages: Vec<String> = findings.iter().map(|finding| finding.language.clone()).collect();
        languages.sort();
        languages.dedup();
        Self {
            schema_version: "1.0".to_string(),
            language_coverage: languages,
            findings,
            runtime_disabled_rules,
        }
    }

    /// Convenience wrapper around [`render_sarif_json`].
    #[must_use]
    pub fn sarif_json(&self) -> String {
        render_sarif_json(self)
    }

    #[must_use]
    pub fn sarif_json_with_workspace_root(&self, workspace_root: &str) -> String {
        render_sarif_with_provenance(self, Some(workspace_root), None)
    }
}

/// Pretty-print the report as JSON. Used by `--render graph` so the
/// CLI emits the same structure SDK consumers see.
pub fn render_graph_json(report: &SecurityReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TrainExample {
    pub example_id: String,
    pub finding_id: String,
    pub language: String,
    pub source_id: String,
    pub sink_id: String,
    pub sanitizer_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    pub payload_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub precision: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TrainReport {
    pub schema_version: String,
    pub examples: Vec<TrainExample>,
}

/// Render the report as JSONL-style training examples — one row per
/// finding with stable ids the `--render train` consumer can use to
/// build labelled datasets.
pub fn render_train_json(report: &SecurityReport) -> String {
    let examples: Vec<TrainExample> = report
        .findings
        .iter()
        .enumerate()
        .map(|(finding_index, finding)| TrainExample {
            example_id: format!("ex-{finding_index:06}"),
            finding_id: finding.finding_id.clone(),
            language: finding.language.clone(),
            source_id: finding.source.rule_id.clone(),
            sink_id: finding.sink.rule_id.clone(),
            sanitizer_ids: finding
                .sanitizers_seen
                .iter()
                .map(|sanitizer| sanitizer.rule_id.clone())
                .collect(),
            group_id: finding.group_id.clone(),
            flow_id: finding.representative_flow_id.clone(),
            payload_types: finding.source.payload_types.clone(),
            tag: finding.tag.clone(),
            severity: finding.severity.map(|severity| severity.as_str().to_string()),
            precision: finding.precision.clone(),
        })
        .collect();
    let train = TrainReport {
        schema_version: "1.0".to_string(),
        examples,
    };
    serde_json::to_string_pretty(&train).unwrap_or_else(|_| "{}".to_string())
}

/// Minimal text renderer — one block per finding. Full view integration
/// (grouped / compact / trace) lives in the CLI command's renderer so it
/// can reuse inspect's styled output.
pub fn render_grouped_text(report: &SecurityReport) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "security — {} finding(s) across languages: {}\n\n",
        report.findings.len(),
        if report.language_coverage.is_empty() {
            "<none>".to_string()
        } else {
            report.language_coverage.join(", ")
        },
    ));
    for finding in &report.findings {
        output.push_str(&format!(
            "{}  [{}]  {} -> {}\n    at {}:{}:{}\n    status: {}\n    precision: {}\n",
            finding.finding_id,
            finding.severity.map_or("info", |severity| severity.as_str()),
            finding.source.rule_id,
            finding.sink.rule_id,
            finding.sink.file,
            finding.sink.line,
            finding.sink.column,
            finding.status.as_str(),
            finding.precision,
        ));
        if !finding.sanitizers_seen.is_empty() {
            output.push_str("    sanitizers: ");
            for sanitizer in &finding.sanitizers_seen {
                output.push_str(&sanitizer.rule_id);
                output.push(' ');
            }
            output.push('\n');
        }
        output.push('\n');
    }
    output
}

/// Render a [`SecurityReport`] as SARIF 2.1.0
/// (<https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>).
///
/// Each [`Finding`] becomes one `result` carrying:
///
/// - **`ruleId`**: the bonsai sink rule id (`"python.sqli.cursor_execute"`).
///   GitHub code-scanning groups results by ruleId and applies
///   per-rule suppressions; using the sink rule id keeps that
///   surface coherent across CWE-shared rule families. CWE
///   classification lives in the standard SARIF taxa relationship
///   (`taxa[CWE-89]`), not in `ruleId`. (S1, S6)
/// - **`ruleIndex`**: 0-based index into `tool.driver.rules[]` so
///   consumers can fast-lookup the rule's metadata. (S3)
/// - **`level`** + **`kind`** + **`rank`**: SARIF severity / classification
///   triple. `kind: "review"` for wrong-context / sanitized-but-
///   bypassable findings, `kind: "fail"` for raw. `rank` is a
///   0–100 number derived from severity for IDE sorting. (S5)
/// - **`fingerprints`** / **`partialFingerprints`**: stable identity
///   tokens so CI scan diffs match findings across runs. (S7)
/// - **`locations[0]`**: sink file + region with `endLine` and
///   `endColumn` so IDEs can highlight the exact expression. (S9)
/// - **`codeFlows[0].threadFlows[0].locations[]`**: source → sanitizer*
///   → sink chain. Every step carries `kinds: ["source"|"sanitizer"|"sink"]`
///   so the IDE step-through can label nodes. (S4)
/// - **`properties.bonsai`**: bonsai-specific metadata that doesn't
///   fit the SARIF schema cleanly — `finding_id`, `flow_id`,
///   `group_id`, `precision`, `status`, `tainted_args`,
///   `chain_display`. Sanitizer rule ids are deduped. (S11)
///
/// `runs[0].tool.driver` advertises every loaded rule via
/// `rules[]` (S2); CWE classification is exposed via
/// `runs[0].taxonomies` + per-result `taxa` relationships (S6).
/// Paths are emitted relative to `originalUriBaseIds["%SRCROOT%"]`
/// instead of leaking absolute host paths. (S8)
/// `runs[0].automationDetails` and `versionControlProvenance` are
/// emitted when the security context provides them. (S10)
pub fn render_sarif_json(report: &SecurityReport) -> String {
    render_sarif_with_provenance(report, None, None)
}

/// Same as [`render_sarif_json`] but lets the caller attach
/// optional provenance metadata for CI scan differentiation:
///
/// - `workspace_root`: absolute path that becomes the
///   `originalUriBaseIds["%SRCROOT%"]` anchor. When `None`, the
///   anchor isn't emitted and paths fall back to absolute.
/// - `version_control`: `(repository_uri, branch, revision_id)` tuple
///   — emitted as `runs[0].versionControlProvenance[0]`. Any of the
///   three may be empty; an entirely-empty triple suppresses the
///   field. Used by GitHub code-scanning to differentiate scans
///   across branches and commits.
pub(crate) fn render_sarif_with_provenance(
    report: &SecurityReport,
    workspace_root: Option<&str>,
    version_control: Option<(&str, &str, &str)>,
) -> String {
    // S2: emit one ruleDescriptor per distinct sink rule id (the
    // bonsai rule we attribute the finding to). Fast index lookup
    // via the BTreeMap so a stable name → index mapping exists.
    let mut rule_index: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut rules_in_order: Vec<String> = Vec::new();
    for finding in &report.findings {
        let rule_id = finding.sink.rule_id.clone();
        if !rule_index.contains_key(&rule_id) {
            rule_index.insert(rule_id.clone(), rules_in_order.len());
            rules_in_order.push(rule_id);
        }
    }
    // Build per-rule SARIF descriptors. We don't have a heavy
    // descriptor catalogue at hand, so populate the name + tags
    // surface that GitHub renders and let IDE plugins fall back to
    // the bonsai property bag for the rest.
    //
    // Pre-build a (sink_rule_id → first_finding) map so the
    // per-rule descriptor build is O(rules + findings) instead of
    // O(rules × findings). On OWASP-scale reports the linear
    // `report.findings.iter().find(...)` was several seconds of
    // visible end-of-scan latency.
    let mut representatives: ahash::AHashMap<&str, &crate::Finding> = ahash::AHashMap::new();
    for finding in &report.findings {
        representatives
            .entry(finding.sink.rule_id.as_str())
            .or_insert(finding);
    }
    let rules_json: Vec<serde_json::Value> = rules_in_order
        .iter()
        .map(|rule_id| {
            // First-match-wins semantics preserved: the AHashMap
            // entry is populated only on the first encounter, and
            // `report.findings` iteration order is stable across
            // runs (sorted upstream by severity then finding_id).
            let representative = representatives.get(rule_id.as_str()).copied();
            let default_level = representative
                .map(|finding| sarif_level_for_severity(finding.severity))
                .unwrap_or("warning");
            let cwes: Vec<String> = representative
                .map(|finding| finding.cwe.clone())
                .unwrap_or_default();
            let cwes = dedup_strings(cwes);
            let mut tags: Vec<String> = cwes
                .iter()
                .map(|cwe| format!("external/cwe/{}", cwe.to_lowercase()))
                .collect();
            if !tags.is_empty() {
                tags.insert(0, "security".to_string());
            }
            let tags = dedup_strings(tags);
            let relationships: Vec<serde_json::Value> = cwes
                .iter()
                .map(|cwe| cwe_relationship(cwe))
                .collect();
            let security_severity = representative
                .and_then(|finding| finding.severity)
                .map(security_severity_for_severity)
                .unwrap_or("5.0");
            let precision = representative
                .map(|finding| sarif_precision_label(&finding.precision).to_string())
                .unwrap_or_else(|| "medium".to_string());
            let rank = representative
                .map(|finding| sarif_rank_for_severity(finding.severity))
                .unwrap_or(50.0);
            let source_rule = representative
                .map(|finding| finding.source.rule_id.as_str())
                .unwrap_or("unknown-source");
            let message_text = format!("Tainted value reaches {rule_id} from {{0}}.");
            let source_summary = representative
                .map(|finding| {
                    format!(
                        "{} -> {} ({})",
                        finding.source.rule_id,
                        finding.sink.rule_id,
                        finding.tag.as_deref().unwrap_or("untagged")
                    )
                })
                .unwrap_or_else(|| format!("{source_rule} -> {rule_id}"));
            let tag = representative
                .and_then(|finding| finding.tag.clone())
                .unwrap_or_else(|| "untagged".to_string());
            serde_json::json!({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": { "text": rule_id },
                "fullDescription": { "text": format!("bonsai rule {} (tag: {}; {})", rule_id, tag, source_summary) },
                "messageStrings": {
                    "default": { "text": message_text },
                },
                "defaultConfiguration": {
                    "level": default_level,
                    "rank": rank,
                    "enabled": true,
                },
                "properties": {
                    "cwe": cwes,
                    "tags": tags,
                    "tag": tag,
                    "security-severity": security_severity,
                    "precision": precision,
                },
                "relationships": relationships,
            })
        })
        .collect();

    // S6: collect every CWE referenced by any finding for the
    // standard SARIF `taxonomies` block. GitHub code-scanning
    // renders CWE classifications only when this exact shape is
    // present.
    let mut cwe_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for finding in &report.findings {
        for cwe in &finding.cwe {
            cwe_set.insert(cwe.clone());
        }
    }
    let cwe_taxa: Vec<serde_json::Value> = cwe_set
        .iter()
        .map(|cwe| {
            serde_json::json!({
                "id": cwe,
                "name": cwe,
                "shortDescription": { "text": format!("Common Weakness Enumeration {}", cwe) },
                "helpUri": cwe_help_uri(cwe),
            })
        })
        .collect();
    let taxonomies_json = if cwe_set.is_empty() {
        serde_json::json!([])
    } else {
        serde_json::json!([{
            "name": "CWE",
            "guid": CWE_TAXONOMY_GUID,
            "version": "4.14",
            "informationUri": "https://cwe.mitre.org/",
            "downloadUri": "https://cwe.mitre.org/data/xml/cwec_v4.14.xml.zip",
            "shortDescription": { "text": "Common Weakness Enumeration" },
            "isComprehensive": false,
            "organization": "MITRE",
            "taxa": cwe_taxa,
        }])
    };

    let workspace_root_uri = workspace_root.map(uri_for_path);
    let results_json: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| finding_to_sarif_result(finding, &rule_index, &cwe_set, workspace_root))
        .collect();

    // S10: optional automation details + version control provenance.
    let automation_details = serde_json::json!({
        "id": "bonsai-ninja/security/taint-analysis",
        "description": { "text": "bonsai-ninja security taint-analysis run" },
    });
    let version_control_provenance: Vec<serde_json::Value> = match version_control {
        Some((repo, branch, rev)) if !repo.is_empty() || !branch.is_empty() || !rev.is_empty() => {
            let mut entry = serde_json::Map::new();
            if !repo.is_empty() {
                entry.insert(
                    "repositoryUri".to_string(),
                    serde_json::Value::String(repo.to_string()),
                );
            }
            if !branch.is_empty() {
                entry.insert(
                    "branch".to_string(),
                    serde_json::Value::String(branch.to_string()),
                );
            }
            if !rev.is_empty() {
                entry.insert(
                    "revisionId".to_string(),
                    serde_json::Value::String(rev.to_string()),
                );
            }
            vec![serde_json::Value::Object(entry)]
        }
        _ => Vec::new(),
    };

    let mut run = serde_json::json!({
        "tool": {
            "driver": {
                "name": "bonsai-ninja",
                "informationUri": "https://github.com/gromhacks/bonsai-ninja",
                "version": env!("CARGO_PKG_VERSION"),
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "rules": rules_json,
                "supportedTaxonomies": [{ "name": "CWE", "guid": CWE_TAXONOMY_GUID }],
            },
        },
        "results": results_json,
        "taxonomies": taxonomies_json,
        "automationDetails": automation_details,
        "columnKind": "utf16CodeUnits",
    });
    if let Some(uri) = workspace_root_uri {
        run["originalUriBaseIds"] = serde_json::json!({
            "%SRCROOT%": {
                "uri": uri,
                "description": { "text": "Workspace root" },
            },
        });
    }
    if !version_control_provenance.is_empty() {
        run["versionControlProvenance"] = serde_json::json!(version_control_provenance);
    }

    let sarif = serde_json::json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

/// Map a bonsai severity to the SARIF `level` enum
/// (`error` / `warning` / `note`). A missing severity defaults to
/// `warning` so consumers don't see an empty level in the IDE panel.
fn sarif_level_for_severity(severity: Option<crate::rule::Severity>) -> &'static str {
    match severity {
        Some(crate::rule::Severity::Critical | crate::rule::Severity::High) => "error",
        Some(crate::rule::Severity::Medium) => "warning",
        Some(crate::rule::Severity::Low | crate::rule::Severity::Info) => "note",
        None => "warning",
    }
}

/// Map a bonsai severity to the SARIF `rank` 0–100 numeric used by
/// IDE sorting. Higher rank = more dangerous.
fn sarif_rank_for_severity(severity: Option<crate::rule::Severity>) -> f64 {
    match severity {
        Some(crate::rule::Severity::Critical) => 95.0,
        Some(crate::rule::Severity::High) => 80.0,
        Some(crate::rule::Severity::Medium) => 55.0,
        Some(crate::rule::Severity::Low) => 25.0,
        Some(crate::rule::Severity::Info) => 10.0,
        None => 50.0,
    }
}

/// Approximate SARIF/GitHub `security-severity` from the bonsai
/// severity tier. SARIF expects this property as a stringified CVSS-
/// like 0.0-10.0 score.
fn security_severity_for_severity(severity: crate::rule::Severity) -> &'static str {
    match severity {
        crate::rule::Severity::Critical => "9.5",
        crate::rule::Severity::High => "8.0",
        crate::rule::Severity::Medium => "5.5",
        crate::rule::Severity::Low => "2.5",
        crate::rule::Severity::Info => "1.0",
    }
}

/// Normalize bonsai's precision labels to the SARIF ecosystem's
/// common `precision` vocabulary.
fn sarif_precision_label(precision: &str) -> &'static str {
    match precision {
        "exact" | "narrowed" => "high",
        "over-approximate" => "medium",
        "unknown" => "low",
        _ => "medium",
    }
}

fn cwe_relationship(cwe: &str) -> serde_json::Value {
    serde_json::json!({
        "target": {
            "id": cwe,
            "toolComponent": {
                "name": "CWE",
                "guid": CWE_TAXONOMY_GUID,
            },
        },
        "kinds": ["superset"],
    })
}

fn cwe_help_uri(cwe: &str) -> String {
    let id = cwe.strip_prefix("CWE-").unwrap_or(cwe);
    format!("https://cwe.mitre.org/data/definitions/{id}.html")
}

/// Build a relative SARIF artifactLocation when `workspace_root` is
/// provided and the absolute `path` lives under it. Falls back to
/// the absolute path otherwise. Stops leaking host paths in
/// published SARIF reports (S8).
fn artifact_location_relative(path: &str, workspace_root: Option<&str>) -> serde_json::Value {
    if let Some(root) = workspace_root {
        let root_normalized = root.trim_end_matches('/');
        let root_with_sep = format!("{root_normalized}/");
        if path == root_normalized {
            return serde_json::json!({
                "uri": "",
                "uriBaseId": "%SRCROOT%",
            });
        }
        if let Some(relative) = path.strip_prefix(&root_with_sep) {
            return serde_json::json!({
                "uri": relative,
                "uriBaseId": "%SRCROOT%",
            });
        }
    }
    serde_json::json!({
        "uri": path,
    })
}

/// Encode a filesystem path as a `file://` URI. Absolute Unix paths
/// already start with `/`, so the doubled-slash form Windows expects
/// is only emitted for non-absolute inputs.
fn uri_for_path(path: &str) -> String {
    let normalized = path.trim_end_matches('/');
    let mut uri = if normalized.starts_with('/') {
        format!("file://{normalized}")
    } else {
        format!("file:///{normalized}")
    };
    if !uri.ends_with('/') {
        uri.push('/');
    }
    uri
}

/// Dedup the sanitizer rule-id list — the same sanitizer matched on
/// multiple call args (e.g. `bleach.clean(a, b)`) shows up as two
/// `FindingMatch` entries with the same rule_id; SARIF consumers
/// expect a unique-id list so the IDE doesn't render the rule
/// twice in the panel. Order-preserving dedup so the first
/// occurrence wins (matches the engine's chronological ordering).
fn dedup_sanitizer_rule_ids(seen: &[crate::finding::FindingMatch]) -> Vec<String> {
    let mut deduped: Vec<String> = Vec::with_capacity(seen.len());
    for sanitizer in seen {
        if !deduped.iter().any(|existing| existing == &sanitizer.rule_id) {
            deduped.push(sanitizer.rule_id.clone());
        }
    }
    deduped
}

fn dedup_strings(values: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::with_capacity(values.len());
    for value in values {
        if !deduped.iter().any(|existing| existing == &value) {
            deduped.push(value);
        }
    }
    deduped
}

/// Render one [`Finding`] as a SARIF `result` object. Carries level /
/// kind / rank, the sink location, the source→sanitizer→sink code
/// flow, CWE taxa relationships, fingerprints, and bonsai-specific
/// metadata in `properties.bonsai`.
fn finding_to_sarif_result(
    finding: &Finding,
    rule_index: &std::collections::BTreeMap<String, usize>,
    cwe_set: &std::collections::BTreeSet<String>,
    workspace_root: Option<&str>,
) -> serde_json::Value {
    let level = sarif_level_for_severity(finding.severity);
    // S5: SARIF kind/rank. wrong-context / sanitized-but-bypassed
    // findings are advisory ("review"), raw flows are failures
    // ("fail"). `rank` is a 0-100 numeric for IDE sorting.
    let kind = match finding.status {
        crate::finding::FindingStatus::Sanitized | crate::finding::FindingStatus::WrongContext => "review",
        crate::finding::FindingStatus::Unsanitized => "fail",
    };
    let rank = sarif_rank_for_severity(finding.severity);
    let message = format!(
        "{} -> {} ({}). {}",
        finding.source.rule_id,
        finding.sink.rule_id,
        finding.tag.as_deref().unwrap_or("untagged"),
        finding.sink.text,
    );
    let sink_location = match_to_sarif_location(&finding.sink, "sink", &finding.hops, workspace_root);
    let is_pattern_finding = finding.source.category.as_deref() == Some("pattern");
    let code_flows = if is_pattern_finding {
        None
    } else {
        Some(build_sarif_code_flows(finding, workspace_root))
    };

    // S6: link this finding to every CWE it carries via SARIF's
    // reportingDescriptorReference shape. CVEBench also uses this
    // as a CWE fallback when result.properties.cwe is absent.
    let finding_cwes = dedup_strings(finding.cwe.clone());
    let cwe_taxa: Vec<serde_json::Value> = finding_cwes
        .iter()
        .filter(|cwe| cwe_set.contains(*cwe))
        .map(|cwe| {
            serde_json::json!({
                "id": cwe,
                "toolComponent": {
                    "name": "CWE",
                    "guid": CWE_TAXONOMY_GUID,
                },
            })
        })
        .collect();
    let mut result_tags: Vec<String> = vec!["security".to_string()];
    for cwe in &finding_cwes {
        result_tags.push(cwe.clone());
        result_tags.push(format!("external/cwe/{}", cwe.to_lowercase()));
    }
    let result_tags = dedup_strings(result_tags);

    // S1 + S3: ruleId is the bonsai sink rule id; ruleIndex points
    // into tool.driver.rules[]. Consumers can fast-lookup metadata
    // and group by per-rule baseline.
    let rule_idx = rule_index.get(&finding.sink.rule_id).copied().unwrap_or(0);

    // S7: stable fingerprints for CI baseline diffing.
    let primary_fingerprint = finding.finding_id.clone();
    let partial_fingerprint_token = format!(
        "{}:{}:{}:{}",
        finding.source.rule_id,
        finding.sink.rule_id,
        finding.sink.enclosing_fn.as_deref().unwrap_or(""),
        finding.tag.as_deref().unwrap_or(""),
    );
    let primary_location_line_hash = format!(
        "{:016x}:1",
        bonsai_hash::fnv1a_names64(&[
            finding.sink.file.clone(),
            finding.sink.line.to_string(),
            finding.sink.rule_id.clone(),
        ])
    );

    let mut result = serde_json::json!({
        "ruleId": finding.sink.rule_id,
        "ruleIndex": rule_idx,
        "level": level,
        "kind": kind,
        "rank": rank,
        "message": {
            "id": "default",
            "arguments": [finding.source.rule_id],
            "text": message,
        },
        "locations": [sink_location],
        "fingerprints": {
            "bonsai/finding/v1": primary_fingerprint,
        },
        "partialFingerprints": {
            "bonsai/source-sink-host/v1": partial_fingerprint_token,
            "primaryLocationLineHash": primary_location_line_hash,
            "primaryLocationStartColumnFingerprint": finding.sink.column.max(1).to_string(),
        },
        "properties": {
            // Keep the top-level `cwe` and `tags` arrays for
            // consumers that haven't migrated to `taxa[]` yet
            // (benchmark scorers, custom dashboards).
            "cwe": finding.cwe,
            "tags": result_tags,
            "bonsai": {
                "finding_id": finding.finding_id,
                "flow_id": finding.representative_flow_id,
                "group_id": finding.group_id,
                "tag": finding.tag,
                "cwe": finding.cwe,
                "owasp": finding.owasp,
                "precision": finding.precision,
                "analysis_complete": finding.analysis_complete,
                "analysis_incomplete_reasons": finding.analysis_incomplete_reasons,
                "status": finding.status.as_str(),
                "language": finding.language,
                "source_rule_id": finding.source.rule_id,
                "sink_rule_id": finding.sink.rule_id,
                "sanitizer_rule_ids": dedup_sanitizer_rule_ids(&finding.sanitizers_seen),
                "tainted_args": finding.sink.tainted_args,
                "taint_path": finding.taint_path,
                "chain_display": finding.chain_display,
            }
        }
    });
    if let Some(code_flows) = code_flows {
        result["codeFlows"] = code_flows;
    }
    if !cwe_taxa.is_empty() {
        result["taxa"] = serde_json::json!(cwe_taxa);
    }
    result
}

fn build_sarif_code_flows(finding: &Finding, workspace_root: Option<&str>) -> serde_json::Value {
    // S4: tag every codeFlow step with `kinds` so IDE step-through
    // can render the chain semantically. The middle hops come from
    // `finding.taint_path`, which preserves the concrete call site
    // and argument propagation evidence the taint engine used.
    let mut thread_flow_locations: Vec<serde_json::Value> = Vec::new();
    push_thread_flow_location(
        &mut thread_flow_locations,
        thread_flow_location(
            match_to_sarif_location(&finding.source, "source", &finding.hops, workspace_root),
            &["source", "taint"],
            "essential",
        ),
    );

    let mut sanitizers_by_step: Vec<Vec<&crate::finding::FindingMatch>> =
        vec![Vec::new(); finding.taint_path.len()];
    let mut unmatched_sanitizers = Vec::new();
    for sanitizer in &finding.sanitizers_seen {
        if let Some(idx) = sanitizer_taint_step_index(sanitizer, &finding.taint_path) {
            sanitizers_by_step[idx].push(sanitizer);
        } else {
            unmatched_sanitizers.push(sanitizer);
        }
    }

    for (idx, step) in finding.taint_path.iter().enumerate() {
        if !taint_step_matches_match(step, &finding.sink) {
            push_thread_flow_location(
                &mut thread_flow_locations,
                thread_flow_location(
                    taint_step_to_sarif_location(step, &finding.hops, workspace_root),
                    &["taint", "call"],
                    "important",
                ),
            );
        }
        for sanitizer in &sanitizers_by_step[idx] {
            push_thread_flow_location(
                &mut thread_flow_locations,
                thread_flow_location(
                    match_to_sarif_location(sanitizer, "sanitizer", &finding.hops, workspace_root),
                    &["sanitizer"],
                    "important",
                ),
            );
        }
    }
    unmatched_sanitizers.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    for sanitizer in unmatched_sanitizers {
        push_thread_flow_location(
            &mut thread_flow_locations,
            thread_flow_location(
                match_to_sarif_location(sanitizer, "sanitizer", &finding.hops, workspace_root),
                &["sanitizer"],
                "important",
            ),
        );
    }

    push_thread_flow_location(
        &mut thread_flow_locations,
        thread_flow_location(
            match_to_sarif_location(&finding.sink, "sink", &finding.hops, workspace_root),
            &["sink"],
            "essential",
        ),
    );
    let flow_summary = if finding.taint_path.is_empty() {
        format!("{} -> {}", finding.source.rule_id, finding.sink.rule_id)
    } else {
        let chain: Vec<String> = finding
            .taint_path
            .iter()
            .map(|step| format!("{} -> {}", step.caller, step.callee))
            .collect();
        chain.join("; ")
    };
    serde_json::json!([{
        "message": { "text": flow_summary },
        "threadFlows": [{
            "id": "primary",
            "locations": thread_flow_locations,
        }],
    }])
}

fn sanitizer_taint_step_index(
    sanitizer: &crate::finding::FindingMatch,
    taint_path: &[crate::finding::TaintPropagationStep],
) -> Option<usize> {
    taint_path
        .iter()
        .position(|step| {
            step.file == sanitizer.file && step.line == sanitizer.line && step.column == sanitizer.column
        })
        .or_else(|| {
            taint_path
                .iter()
                .position(|step| step.file == sanitizer.file && step.line == sanitizer.line)
        })
}

fn thread_flow_location(location: serde_json::Value, kinds: &[&str], importance: &str) -> serde_json::Value {
    serde_json::json!({
        "location": location,
        "kinds": kinds,
        "importance": importance,
    })
}

fn push_thread_flow_location(locations: &mut Vec<serde_json::Value>, next: serde_json::Value) {
    if let Some(previous) = locations.last_mut() {
        if same_thread_flow_site(previous, &next) {
            merge_thread_flow_location(previous, next);
            return;
        }
    }
    locations.push(next);
}

fn same_thread_flow_site(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    if thread_flow_has_kind(left, "sanitizer") || thread_flow_has_kind(right, "sanitizer") {
        return false;
    }
    match (
        thread_flow_uri(left),
        thread_flow_start_line(left),
        thread_flow_uri(right),
        thread_flow_start_line(right),
    ) {
        (Some(left_uri), Some(left_line), Some(right_uri), Some(right_line)) => {
            left_uri == right_uri && left_line == right_line
        }
        _ => false,
    }
}

fn thread_flow_has_kind(location: &serde_json::Value, kind: &str) -> bool {
    location
        .get("kinds")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|kinds| kinds.iter().any(|value| value.as_str() == Some(kind)))
}

fn thread_flow_uri(location: &serde_json::Value) -> Option<&str> {
    location
        .get("location")?
        .get("physicalLocation")?
        .get("artifactLocation")?
        .get("uri")?
        .as_str()
}

fn thread_flow_start_line(location: &serde_json::Value) -> Option<u64> {
    location
        .get("location")?
        .get("physicalLocation")?
        .get("region")?
        .get("startLine")?
        .as_u64()
}

fn merge_thread_flow_location(previous: &mut serde_json::Value, next: serde_json::Value) {
    let mut kinds: Vec<serde_json::Value> = previous
        .get("kinds")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(next_kinds) = next.get("kinds").and_then(serde_json::Value::as_array) {
        for kind in next_kinds {
            if !kinds.iter().any(|existing| existing == kind) {
                kinds.push(kind.clone());
            }
        }
    }
    previous["kinds"] = serde_json::Value::Array(kinds);
    if next.get("importance").and_then(serde_json::Value::as_str) == Some("essential") {
        previous["importance"] = serde_json::Value::String("essential".to_string());
    }
}

fn taint_step_matches_match(
    step: &crate::finding::TaintPropagationStep,
    finding_match: &crate::finding::FindingMatch,
) -> bool {
    step.file == finding_match.file && step.line == finding_match.line
}

fn taint_step_to_sarif_location(
    step: &crate::finding::TaintPropagationStep,
    hops: &[crate::flow_evidence::FlowFunctionBody],
    workspace_root: Option<&str>,
) -> serde_json::Value {
    let artifact = artifact_location_relative(&step.file, workspace_root);
    let display = format!("{} -> {}", step.caller, step.callee);
    let start_column = step.column.max(1);
    let end_column = start_column.saturating_add(u32::try_from(display.chars().count()).unwrap_or(0));
    let mut physical = serde_json::json!({
        "artifactLocation": artifact,
        "region": {
            "startLine": step.line.max(1),
            "startColumn": start_column,
            "endLine": step.line.max(1),
            "endColumn": end_column.max(start_column + 1),
            "snippet": { "text": display },
        },
    });
    if let Some(context) = body_context_region(hops, Some(step.caller.as_str()), step.line) {
        physical["contextRegion"] = context;
    }
    serde_json::json!({
        "physicalLocation": physical,
        "logicalLocations": logical_locations_for(Some(step.caller.as_str()), Some(step.file.as_str())),
        "message": { "text": format!("taint propagates through {display}") },
        "properties": {
            "kind": "taint",
            "caller": step.caller,
            "callee": step.callee,
            "tainted_args": step.tainted_args,
        }
    })
}

/// SARIF `contextRegion` for the function enclosing a flow step - the full
/// body captured in `finding.hops`, located by function name and line
/// containment so same-named functions at different sites stay distinct.
/// `None` when no body was captured (pattern findings, unresolved chains).
fn body_context_region(
    hops: &[crate::flow_evidence::FlowFunctionBody],
    func: Option<&str>,
    line: u32,
) -> Option<serde_json::Value> {
    let func = func?;
    let body = hops.iter().find(|b| {
        b.function == func
            && b.lines.first().is_some_and(|first| first.n <= line)
            && b.lines.last().is_some_and(|last| last.n >= line)
    })?;
    let start = body.lines.first()?.n;
    let end = body.lines.last()?.n;
    let text = body
        .lines
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    Some(serde_json::json!({
        "startLine": start,
        "endLine": end,
        "snippet": { "text": text },
    }))
}

/// Render one match site as a SARIF `location` object — physical
/// region with snippet, logical-location frame for the enclosing fn,
/// and a `properties.kind` tag identifying the role
/// (`source` / `sanitizer` / `sink`).
fn match_to_sarif_location(
    finding_match: &crate::finding::FindingMatch,
    role: &str,
    hops: &[crate::flow_evidence::FlowFunctionBody],
    workspace_root: Option<&str>,
) -> serde_json::Value {
    let artifact = artifact_location_relative(&finding_match.file, workspace_root);
    // S9: emit endLine/endColumn/snippet so IDEs can highlight the
    // exact expression. End line falls back to start line when the
    // adapter doesn't expose a span end (most matches are single-
    // line); column-end is the start column + match-text width.
    let start_column = finding_match.column.max(1);
    let end_column =
        start_column.saturating_add(u32::try_from(finding_match.text.chars().count()).unwrap_or(0));
    let mut physical = serde_json::json!({
        "artifactLocation": artifact,
        "region": {
            "startLine": finding_match.line,
            "startColumn": start_column,
            "endLine": finding_match.line,
            "endColumn": end_column.max(start_column + 1),
            "snippet": { "text": finding_match.text },
        },
    });
    if let Some(context) =
        body_context_region(hops, finding_match.enclosing_fn.as_deref(), finding_match.line)
    {
        physical["contextRegion"] = context;
    }
    serde_json::json!({
        "physicalLocation": physical,
        "logicalLocations": logical_locations_for(finding_match.enclosing_fn.as_deref(), Some(finding_match.file.as_str())),
        "message": { "text": format!("[{role}] {}", finding_match.text) },
        "properties": {
            "kind": role,
            "rule_id": finding_match.rule_id,
        }
    })
}

/// SARIF logical-location frame for the enclosing function. Empty
/// array when the matcher couldn't resolve an enclosing fn — IDE
/// breadcrumbs handle the empty case gracefully.
fn logical_locations_for(enclosing: Option<&str>, file: Option<&str>) -> serde_json::Value {
    match enclosing {
        Some(name) if !name.is_empty() => {
            let mut frame = serde_json::json!({
                "name": name,
                "kind": "function",
            });
            if let Some(file) = file.filter(|file| !file.is_empty()) {
                frame["fullyQualifiedName"] = serde_json::json!(format!("{file}::{name}"));
            }
            serde_json::json!([frame])
        }
        _ => serde_json::json!([]),
    }
}

/// Text-render a [`DependencyInventory`]. One row per (language, key).
pub fn render_deps_text(inv: &DependencyInventory) -> String {
    let mut output = String::new();
    output.push_str(&format!("deps — {} entries\n", inv.rows.len()));
    for row in &inv.rows {
        output.push_str(&format!(
            "  [{}] {} — rules={} signals={} severity={} tags={}\n",
            row.language,
            row.key,
            row.rule_ids.len(),
            row.signals.join(","),
            row.severity.map_or("-", |severity| severity.as_str()),
            row.tags.join(","),
        ));
    }
    output
}

#[cfg(test)]
#[path = "report_sarif_tests.rs"]
mod sarif_tests;
