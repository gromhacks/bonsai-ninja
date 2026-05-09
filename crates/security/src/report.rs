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
    /// default to empty. Use [`with_runtime_disabled_rules`] when
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
    let sink_location = match_to_sarif_location(&finding.sink, "sink", workspace_root);
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
    thread_flow_locations.push(thread_flow_location(
        match_to_sarif_location(&finding.source, "source", workspace_root),
        &["source", "taint"],
        "essential",
    ));

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
            thread_flow_locations.push(thread_flow_location(
                taint_step_to_sarif_location(step, workspace_root),
                &["taint", "call"],
                "important",
            ));
        }
        for sanitizer in &sanitizers_by_step[idx] {
            thread_flow_locations.push(thread_flow_location(
                match_to_sarif_location(sanitizer, "sanitizer", workspace_root),
                &["sanitizer"],
                "important",
            ));
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
        thread_flow_locations.push(thread_flow_location(
            match_to_sarif_location(sanitizer, "sanitizer", workspace_root),
            &["sanitizer"],
            "important",
        ));
    }

    thread_flow_locations.push(thread_flow_location(
        match_to_sarif_location(&finding.sink, "sink", workspace_root),
        &["sink"],
        "essential",
    ));
    let flow_summary = if finding.taint_path.is_empty() {
        format!("{} -> {}", finding.source.rule_id, finding.sink.rule_id)
    } else {
        let hops: Vec<String> = finding
            .taint_path
            .iter()
            .map(|step| format!("{} -> {}", step.caller, step.callee))
            .collect();
        hops.join("; ")
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

fn taint_step_matches_match(
    step: &crate::finding::TaintPropagationStep,
    finding_match: &crate::finding::FindingMatch,
) -> bool {
    step.file == finding_match.file && step.line == finding_match.line
}

fn taint_step_to_sarif_location(
    step: &crate::finding::TaintPropagationStep,
    workspace_root: Option<&str>,
) -> serde_json::Value {
    let artifact = artifact_location_relative(&step.file, workspace_root);
    let display = format!("{} -> {}", step.caller, step.callee);
    let start_column = step.column.max(1);
    let end_column = start_column.saturating_add(u32::try_from(display.chars().count()).unwrap_or(0));
    serde_json::json!({
        "physicalLocation": {
            "artifactLocation": artifact,
            "region": {
                "startLine": step.line.max(1),
                "startColumn": start_column,
                "endLine": step.line.max(1),
                "endColumn": end_column.max(start_column + 1),
                "snippet": { "text": display },
            },
        },
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

/// Render one match site as a SARIF `location` object — physical
/// region with snippet, logical-location frame for the enclosing fn,
/// and a `properties.kind` tag identifying the role
/// (`source` / `sanitizer` / `sink`).
fn match_to_sarif_location(
    finding_match: &crate::finding::FindingMatch,
    role: &str,
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
    serde_json::json!({
        "physicalLocation": {
            "artifactLocation": artifact,
            "region": {
                "startLine": finding_match.line,
                "startColumn": start_column,
                "endLine": finding_match.line,
                "endColumn": end_column.max(start_column + 1),
                "snippet": { "text": finding_match.text },
            },
        },
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
mod sarif_tests {
    use super::*;
    use crate::finding::{
        Finding, FindingMatch, FindingStatus, TaintPropagationArg, TaintPropagationStep, TaintedArgInfo,
    };
    use crate::rule::Severity;
    use serde_json::Value;

    fn sample_match(rule_id: &str, file: &str, line: u32) -> FindingMatch {
        FindingMatch {
            rule_id: rule_id.to_string(),
            file: file.to_string(),
            line,
            column: 5,
            text: format!("call site for {rule_id}"),
            enclosing_fn: Some("handle_request".to_string()),
            tag: Some("command-injection".to_string()),
            severity: Some(Severity::Critical),
            category: None,
            trust: Some("remote".to_string()),
            payload_types: Vec::new(),
            tainted_args: vec![TaintedArgInfo {
                index: 0,
                value_text: "user_input".to_string(),
            }],
            sanitised_arg_indices: Vec::new(),
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            finding_id: "S:00000000abcd1234".to_string(),
            language: "python".to_string(),
            source: sample_match("python.sources.flask_args", "app.py", 12),
            sink: sample_match("python.cmdi.os_system", "auth.py", 42),
            sanitizers_seen: Vec::new(),
            group_id: Some("G:000000000a1b2c3d".to_string()),
            representative_flow_id: Some("F:0000000001ab73e2".to_string()),
            chain_display: vec![
                "handle_request".to_string(),
                "verify_token".to_string(),
                "run_admin_command".to_string(),
            ],
            taint_path: Vec::new(),
            tag: Some("command-injection".to_string()),
            severity: Some(Severity::Critical),
            precision: "exact".to_string(),
            cwe: vec!["CWE-78".to_string()],
            owasp: vec!["A03".to_string()],
            status: FindingStatus::Unsanitized,
            from_test: false,
        }
    }

    #[test]
    fn sarif_render_top_level_shape() {
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).expect("valid json");
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].as_str().unwrap().contains("sarif-schema-2.1.0"));
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "bonsai-ninja");
        assert_eq!(v["runs"][0]["columnKind"], "utf16CodeUnits");
        // S2: rules[] now contains one entry per loaded sink rule
        // (the bonsai rule the finding fired on), not the CWE.
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert!(
            rules.iter().any(|r| r["id"] == "python.cmdi.os_system"),
            "rules[] should contain the sink rule id, got {rules:#?}"
        );
        // S6: CWE classification lives in runs[].taxonomies, not in
        // tool.driver.rules.
        assert_eq!(v["runs"][0]["taxonomies"][0]["name"], "CWE");
        assert_eq!(v["runs"][0]["taxonomies"][0]["guid"], CWE_TAXONOMY_GUID);
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["supportedTaxonomies"][0]["guid"],
            CWE_TAXONOMY_GUID
        );
        assert!(v["runs"][0]["taxonomies"][0]["taxa"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == "CWE-78"));
    }

    #[test]
    fn sarif_result_rule_id_is_bonsai_sink_rule() {
        // S1: ruleId is the bonsai rule that fired, not the CWE.
        // GitHub code-scanning groups by ruleId; using the sink rule
        // gives us per-rule baselines and suppressions.
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "python.cmdi.os_system");
        assert_eq!(result["level"], "error");
        // S3: ruleIndex points into tool.driver.rules[].
        assert_eq!(result["ruleIndex"], 0);
    }

    #[test]
    fn sarif_result_carries_kind_rank_fingerprints() {
        // S5 + S7: kind/rank for IDE sorting; fingerprints for CI
        // baseline diffing.
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["kind"], "fail");
        assert!(result["rank"].as_f64().unwrap() >= 90.0);
        assert_eq!(result["fingerprints"]["bonsai/finding/v1"], "S:00000000abcd1234");
        assert!(result["partialFingerprints"]["bonsai/source-sink-host/v1"]
            .as_str()
            .unwrap()
            .contains("python.cmdi.os_system"));
        assert_eq!(
            result["partialFingerprints"]["primaryLocationStartColumnFingerprint"],
            "5"
        );
        assert!(result["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .unwrap()
            .ends_with(":1"));
    }

    #[test]
    fn sarif_taxa_link_each_finding_to_its_cwe() {
        // S6: CWE on the result via SARIF's reportingDescriptorReference shape.
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let taxa = &v["runs"][0]["results"][0]["taxa"];
        let arr = taxa.as_array().expect("taxa array");
        assert!(!arr.is_empty(), "expected at least one taxa reference");
        assert_eq!(arr[0]["id"], "CWE-78");
        assert_eq!(arr[0]["toolComponent"]["name"], "CWE");
        assert_eq!(arr[0]["toolComponent"]["guid"], CWE_TAXONOMY_GUID);
    }

    #[test]
    fn sarif_review_kind_for_sanitized_findings() {
        let mut f = sample_finding();
        f.status = FindingStatus::Sanitized;
        let report = SecurityReport::new(vec![f]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["kind"], "review");
    }

    #[test]
    fn sarif_severity_maps_to_sarif_level() {
        let levels = [
            (Severity::Critical, "error"),
            (Severity::High, "error"),
            (Severity::Medium, "warning"),
            (Severity::Low, "note"),
            (Severity::Info, "note"),
        ];
        for (sev, expected_level) in levels {
            let mut f = sample_finding();
            f.severity = Some(sev);
            f.sink.severity = Some(sev);
            let report = SecurityReport::new(vec![f]);
            let s = render_sarif_json(&report);
            let v: Value = serde_json::from_str(&s).unwrap();
            assert_eq!(
                v["runs"][0]["results"][0]["level"], expected_level,
                "severity {sev:?} should map to SARIF level {expected_level}"
            );
        }
    }

    #[test]
    fn sarif_location_uses_sink_file_line_column() {
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0];
        // S8: without workspace_root, paths fall back to absolute
        // (no uriBaseId emitted).
        assert_eq!(loc["physicalLocation"]["artifactLocation"]["uri"], "auth.py");
        assert!(loc["physicalLocation"]["artifactLocation"]["uriBaseId"].is_null());
        let region = &loc["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 42);
        assert_eq!(region["startColumn"], 5);
        // S9: endLine/endColumn/snippet now emitted so IDEs can
        // highlight the exact expression.
        assert_eq!(region["endLine"], 42);
        assert!(region["endColumn"].as_u64().unwrap() > 5);
        assert!(
            region["snippet"]["text"]
                .as_str()
                .unwrap()
                .contains("python.cmdi.os_system"),
            "snippet should carry the matched text"
        );
        let logical = &loc["logicalLocations"][0];
        assert_eq!(logical["name"], "handle_request");
        assert_eq!(logical["kind"], "function");
        assert_eq!(logical["fullyQualifiedName"], "auth.py::handle_request");
    }

    #[test]
    fn sarif_paths_relative_when_workspace_root_supplied() {
        // S8: with workspace_root the paths are relative under
        // %SRCROOT%, no host paths leaked.
        let mut f = sample_finding();
        f.sink.file = "/projects/x/auth.py".to_string();
        f.source.file = "/projects/x/app.py".to_string();
        let report = SecurityReport::new(vec![f]);
        let s = render_sarif_with_provenance(&report, Some("/projects/x"), None);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            v["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"],
            "file:///projects/x/"
        );
        let sink_loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];
        assert_eq!(sink_loc["uri"], "auth.py");
        assert_eq!(sink_loc["uriBaseId"], "%SRCROOT%");
    }

    #[test]
    fn sarif_codeflows_threads_source_then_sink() {
        // S4: every step carries `kinds: [...]` for IDE
        // step-through labelling.
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let tflows = &v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"];
        let arr = tflows.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["kinds"][0], "source");
        assert_eq!(arr[1]["kinds"][0], "sink");
        assert_eq!(
            arr[0]["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "app.py"
        );
        assert_eq!(
            arr[1]["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "auth.py"
        );
    }

    #[test]
    fn sarif_codeflows_includes_sanitizer_hops_in_path_order() {
        let mut f = sample_finding();
        f.taint_path = vec![
            TaintPropagationStep {
                caller: "handle_request".to_string(),
                callee: "normalize".to_string(),
                file: "app.py".to_string(),
                line: 20,
                column: 9,
                tainted_args: Vec::new(),
            },
            TaintPropagationStep {
                caller: "normalize".to_string(),
                callee: "run_admin_command".to_string(),
                file: "lib.py".to_string(),
                line: 8,
                column: 5,
                tainted_args: Vec::new(),
            },
            TaintPropagationStep {
                caller: "run_admin_command".to_string(),
                callee: "os.system".to_string(),
                file: "auth.py".to_string(),
                line: 42,
                column: 5,
                tainted_args: Vec::new(),
            },
        ];
        f.sanitizers_seen = vec![sample_match("python.sanitizers.shlex_quote", "lib.py", 8)];
        let report = SecurityReport::new(vec![f]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let tflows = &v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"];
        let arr = tflows.as_array().unwrap();
        assert_eq!(arr.len(), 5);
        assert_eq!(arr[0]["kinds"][0], "source");
        assert_eq!(arr[1]["kinds"][0], "taint");
        assert_eq!(arr[2]["kinds"][0], "taint");
        assert_eq!(arr[3]["kinds"][0], "sanitizer");
        assert_eq!(
            arr[3]["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "lib.py"
        );
        assert_eq!(arr[4]["kinds"][0], "sink");
    }

    #[test]
    fn sarif_pattern_findings_skip_codeflows() {
        let mut f = sample_finding();
        f.source.category = Some("pattern".to_string());
        f.source.rule_id = "pattern:python.weakrand.random".to_string();
        f.source.file = f.sink.file.clone();
        f.source.line = f.sink.line;
        f.source.column = f.sink.column;
        f.taint_path = Vec::new();
        let report = SecurityReport::new(vec![f]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert!(
            v["runs"][0]["results"][0]["codeFlows"].is_null(),
            "pattern-only results should not fabricate source==sink codeFlows"
        );
    }

    #[test]
    fn sarif_codeflows_include_concrete_taint_path_hops() {
        let mut f = sample_finding();
        f.taint_path = vec![TaintPropagationStep {
            caller: "handle_request".to_string(),
            callee: "run_admin_command".to_string(),
            file: "app.py".to_string(),
            line: 20,
            column: 9,
            tainted_args: vec![TaintPropagationArg {
                index: 0,
                value_text: "payload".to_string(),
                param_name: "cmd".to_string(),
            }],
        }];
        let report = SecurityReport::new(vec![f]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let tflows = &v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"];
        let arr = tflows.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["kinds"][0], "source");
        assert_eq!(arr[1]["kinds"][0], "taint");
        assert_eq!(arr[1]["kinds"][1], "call");
        assert_eq!(
            arr[1]["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "app.py"
        );
        assert_eq!(arr[1]["location"]["physicalLocation"]["region"]["startLine"], 20);
        assert_eq!(
            arr[1]["location"]["properties"]["tainted_args"][0]["param_name"],
            "cmd"
        );
        assert_eq!(arr[2]["kinds"][0], "sink");
    }

    #[test]
    fn sarif_rule_descriptors_carry_cwe_metadata() {
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "python.cmdi.os_system");
        assert_eq!(
            rule["messageStrings"]["default"]["text"],
            "Tainted value reaches python.cmdi.os_system from {0}."
        );
        assert_eq!(rule["defaultConfiguration"]["enabled"], true);
        assert!(rule["defaultConfiguration"]["rank"].as_f64().unwrap() >= 90.0);
        assert_eq!(rule["properties"]["cwe"][0], "CWE-78");
        assert_eq!(rule["properties"]["security-severity"], "9.5");
        assert_eq!(rule["properties"]["precision"], "high");
        assert_eq!(rule["relationships"][0]["target"]["id"], "CWE-78");
        assert_eq!(
            rule["relationships"][0]["target"]["toolComponent"]["guid"],
            CWE_TAXONOMY_GUID
        );
    }

    #[test]
    fn sarif_dedups_sanitizer_rule_ids() {
        // S11: same sanitizer matched on multiple args produces
        // duplicate FindingMatch entries with the same rule_id;
        // the SARIF emit dedups them.
        let mut f = sample_finding();
        let m = sample_match("python.sanitizer.bleach_clean", "lib.py", 8);
        f.sanitizers_seen = vec![m.clone(), m];
        let report = SecurityReport::new(vec![f]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let ids = v["runs"][0]["results"][0]["properties"]["bonsai"]["sanitizer_rule_ids"]
            .as_array()
            .unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "python.sanitizer.bleach_clean");
    }

    #[test]
    fn sarif_properties_carry_bonsai_metadata() {
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let props = &v["runs"][0]["results"][0]["properties"]["bonsai"];
        assert_eq!(props["finding_id"], "S:00000000abcd1234");
        assert_eq!(props["flow_id"], "F:0000000001ab73e2");
        assert_eq!(props["group_id"], "G:000000000a1b2c3d");
        assert_eq!(props["language"], "python");
        assert_eq!(props["status"], "unsanitized");
        assert_eq!(props["cwe"][0], "CWE-78");
        assert_eq!(props["chain_display"][0], "handle_request");
        assert_eq!(props["tainted_args"][0]["value_text"], "user_input");
    }

    #[test]
    fn sarif_empty_report_emits_well_formed_run_with_empty_results() {
        let report = SecurityReport::new(Vec::new());
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "bonsai-ninja");
        assert!(v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn sarif_emits_one_rule_per_distinct_sink_rule_id() {
        // S2: rules[] has one entry per loaded sink rule. Two
        // findings with different sink rule ids → two rule entries
        // even when they share a CWE.
        let f1 = sample_finding();
        let mut f2 = sample_finding();
        f2.finding_id = "S:0000000011111111".to_string();
        f2.sink = sample_match("python.cmdi.subprocess", "other.py", 99);
        let report = SecurityReport::new(vec![f1, f2]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        let ids: std::collections::HashSet<_> = rules
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains("python.cmdi.os_system"));
        assert!(ids.contains("python.cmdi.subprocess"));
        // ruleIndex on each result points back into rules[].
        let r0 = &v["runs"][0]["results"][0];
        let r1 = &v["runs"][0]["results"][1];
        let idx0 = r0["ruleIndex"].as_u64().unwrap() as usize;
        let idx1 = r1["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[idx0]["id"], r0["ruleId"]);
        assert_eq!(rules[idx1]["id"], r1["ruleId"]);
    }

    #[test]
    fn sarif_emits_version_control_provenance_when_supplied() {
        // S10: optional VCS metadata for CI scan differentiation.
        let report = SecurityReport::new(vec![sample_finding()]);
        let s = render_sarif_with_provenance(
            &report,
            None,
            Some(("https://github.com/foo/bar", "main", "abc123")),
        );
        let v: Value = serde_json::from_str(&s).unwrap();
        let prov = &v["runs"][0]["versionControlProvenance"][0];
        assert_eq!(prov["repositoryUri"], "https://github.com/foo/bar");
        assert_eq!(prov["branch"], "main");
        assert_eq!(prov["revisionId"], "abc123");
        // automationDetails always present.
        assert_eq!(
            v["runs"][0]["automationDetails"]["id"],
            "bonsai-ninja/security/taint-analysis"
        );
    }
}
