use bonsai_security::{FindingStatus, Rulepack, TaintAnalysisReport};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn rulepack() -> &'static Rulepack {
    static PACK: OnceLock<Rulepack> = OnceLock::new();
    PACK.get_or_init(|| bonsai_security::load_rulepack(&rules_root()).expect("load rulepack"))
}

fn analyze(source: &str) -> TaintAnalysisReport {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write("restore.c", Arc::<str>::from(source));
    bonsai_security::run_taint_analysis(
        &workspace,
        rulepack(),
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("taint analysis")
}

fn memcpy_status(report: &TaintAnalysisReport) -> FindingStatus {
    report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "c.memory.memcpy")
        .unwrap_or_else(|| panic!("missing c.memory.memcpy: {:#?}", report.findings))
        .finding
        .status
}

#[test]
fn exact_c_numeric_clamp_sanitizes_only_the_bounded_destination_call() {
    let safe = analyze(
        r#"typedef struct { char payload[128]; } packet_t;
void restore(const char *input, unsigned long claimed) {
  packet_t packet;
  if (claimed > sizeof(packet.payload)) claimed = sizeof(packet.payload);
  char output[128];
  memcpy(output, input, claimed);
}
"#,
    );
    assert_eq!(memcpy_status(&safe), FindingStatus::Sanitized, "{safe:#?}");

    for unsafe_source in [
        r#"void restore(const char *input, unsigned long claimed) {
  char output[128];
  if (claimed > sizeof(output)) observe(claimed);
  memcpy(output, input, claimed);
}
"#,
        r#"void restore(const char *input, unsigned long claimed) {
  char output[128];
  if (claimed > sizeof(output)) claimed = sizeof(output);
  claimed = read_length();
  memcpy(output, input, claimed);
}
"#,
    ] {
        let unsafe_report = analyze(unsafe_source);
        assert_eq!(
            memcpy_status(&unsafe_report),
            FindingStatus::Unsanitized,
            "{unsafe_report:#?}"
        );
    }
}

#[test]
fn c_compound_static_allowlist_credits_only_the_guarded_url_configuration() {
    let source = r#"#include <curl/curl.h>
static const char *TRUSTED[] = {"api.example", "hooks.example", NULL};
static int accepted(const char *value) {
  if (strncmp(value, "https://", 8) != 0) return 0;
  const char *token = value + 8;
  for (int i = 0; TRUSTED[i]; i++) {
    size_t n = strlen(TRUSTED[i]);
    if (strncmp(token, TRUSTED[i], n) == 0 &&
        (token[n] == '/' || token[n] == '\0')) return 1;
  }
  return 0;
}
void fetch(void *client, const char *value) {
  if (!accepted(value)) return;
  curl_easy_setopt(client, CURLOPT_URL, value);
  curl_easy_setopt(client, CURLOPT_FOLLOWLOCATION, 0L);
}
"#;
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    let file = workspace.vfs().write("fetch.c", Arc::<str>::from(source));
    let index = workspace.db().decl_index(file).expect("C declaration index");
    let fact = index
        .compiler_guards
        .iter()
        .find(|fact| {
            fact.capability == "terminal-predicate.compound-static-allowlist"
                && fact
                    .evidence
                    .contains(&"guarded-argument:2=predicate-argument:0".to_string())
        })
        .unwrap_or_else(|| panic!("missing compiler guard: {:#?}", index.compiler_guards));
    assert!(
        fact.evidence.iter().any(|evidence| {
            evidence == "related-call:curl_easy_setopt:argument:1=place:CURLOPT_FOLLOWLOCATION"
        }),
        "{fact:#?}"
    );
    let report = bonsai_security::run_taint_analysis(
        &workspace,
        rulepack(),
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        sink_status(&report, "c.ssrf.curl_easy_setopt"),
        FindingStatus::Sanitized,
        "{report:#?}"
    );
}

fn sink_status(report: &TaintAnalysisReport, sink_rule: &str) -> FindingStatus {
    report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == sink_rule)
        .unwrap_or_else(|| panic!("missing {sink_rule}: {:#?}", report.findings))
        .finding
        .status
}

#[test]
fn cpp_compound_static_allowlist_credits_the_exact_projected_url_argument() {
    let source = r#"#include <set>
#include <string>
static const std::set<std::string> TRUSTED = {"api.example", "hooks.example"};
static bool accepted(const std::string& value, std::string& token) {
  if (value.rfind("https://", 0) != 0) return false;
  auto rest = value.substr(8);
  token = rest.substr(0, rest.find('/'));
  return TRUSTED.count(token) > 0;
}
void fetch(void *client, const std::string& value) {
  std::string token;
  if (!accepted(value, token)) return;
  curl_easy_setopt(client, CURLOPT_URL, value.c_str());
  curl_easy_setopt(client, CURLOPT_FOLLOWLOCATION, 0L);
}
"#;
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write("fetch.cpp", Arc::<str>::from(source));
    let report = bonsai_security::run_taint_analysis(
        &workspace,
        rulepack(),
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        sink_status(&report, "cpp.ssrf.curl_easy_setopt_url"),
        FindingStatus::Sanitized,
        "{report:#?}"
    );
}
